//! Invitations: creation, acceptance, revocation, listing.
//!
//! An invitation targets exactly one scope: a tenant (`role = "tenant_owner"`)
//! or a workspace (`role ∈ {"admin", "editor", "viewer"}`). `email IS NULL`
//! means a reusable link; `email IS NOT NULL` means an addressed invitation
//! (until email verification, Stage 3, addressed invitations are effectively
//! links; see handoff §16).
//!
//! Raw tokens are returned once from [`create_invitation`] as a tuple
//! `(invitation, raw_token)` and never persisted; `invitations.token_hash`
//! stores SHA-256 of the raw token.
//!
//! **Invariant exception (§5 p.5):** [`accept_invitation`] does **not** call
//! `authz.require` — it authorizes by the invitation token. All other
//! services in this module check `authz.require(...)` first.

use authz::WorkspaceRole;
use domain::{AuthUser, Invitation, InvitationTarget};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CoreError, SaasState};

/// Default invitation lifetime, in hours (7 days).
const DEFAULT_TTL_HOURS: i32 = 168;

/// Creates an invitation.
///
/// The raw token is returned to the caller once (as the second tuple element)
/// and is not persisted; `invitations.token_hash` stores SHA-256 of it.
///
/// `ttl_hours` defaults to [`DEFAULT_TTL_HOURS`] when `None`.
/// `max_uses` (if `Some`) must be `>= 1`; `None` means unlimited (typical for
/// link invitations).
pub async fn create_invitation(
    state: &SaasState,
    actor: &AuthUser,
    target: InvitationTarget,
    email: Option<String>,
    role: String,
    ttl_hours: Option<i32>,
    max_uses: Option<i32>,
) -> Result<(Invitation, String), CoreError> {
    let domain_str = target_domain(target);

    state
        .authz
        .require(actor.id, &domain_str, "invitations", "create")
        .await?;

    validate_role(target, &role)?;

    if let Some(email) = email.as_deref() {
        identity::validate_email(email).map_err(|e| CoreError::Validation(e.to_string()))?;
    }

    let ttl = ttl_hours.unwrap_or(DEFAULT_TTL_HOURS);
    if ttl <= 0 {
        return Err(CoreError::Validation("ttl_hours must be positive".into()));
    }
    if let Some(max) = max_uses {
        if max < 1 {
            return Err(CoreError::Validation("max_uses must be >= 1".into()));
        }
    }

    let token = generate_token();
    let token_hash = hash_token(&token);

    let (tenant_id, workspace_id) = match target {
        InvitationTarget::Tenant(id) => (Some(id), None),
        InvitationTarget::Workspace(id) => (None, Some(id)),
    };

    let invitation = sqlx::query_as::<_, Invitation>(
        r#"
        insert into invitations
            (tenant_id, workspace_id, email, role, token_hash, created_by, expires_at, max_uses)
        values ($1, $2, $3, $4, $5, $6, now() + make_interval(hours => $7::int), $8)
        returning *
        "#,
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(email)
    .bind(&role)
    .bind(&token_hash)
    .bind(actor.id)
    .bind(ttl)
    .bind(max_uses)
    .fetch_one(state.pool())
    .await?;

    Ok((invitation, token))
}

/// Checks an invitation by raw token without accepting it.
///
/// Returns `Some(Invitation)` if the token is valid (not revoked, not expired,
/// not exhausted), or `None` otherwise. Does not increment `used_count`, does
/// not write memberships, and does not call `authz.require` (authorized by the
/// token itself, same as [`accept_invitation`]).
///
/// Used by the UI to show "invalid / expired / revoked" before asking the
/// user to log in.
pub async fn check_invitation(
    state: &SaasState,
    raw_token: &str,
) -> Result<Option<Invitation>, CoreError> {
    let token_hash = hash_token(raw_token);

    let invitation = sqlx::query_as::<_, Invitation>(
        r#"
        select * from invitations
        where token_hash = $1
          and revoked_at is null
          and expires_at >= now()
          and (max_uses is null or used_count < max_uses)
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(state.pool())
    .await?;

    Ok(invitation)
}

/// Accepts an invitation by raw token.
///
/// **Does not call `authz.require`** (§5 p.5 explicit exception): the caller
/// is authorized by the possession of the raw token. Everything else — the
/// `used_count` increment, the membership write, and the `grant_*` — happens
/// in one transaction; `grant_*` runs before `tx.commit()`.
///
/// Returns `CoreError::NotFound` if the token does not match any active
/// invitation (does not exist, revoked, expired, or exhausted). The reason is
/// not distinguished to avoid leaking invitation state.
///
/// **Known limitation (handoff §16):** `actor.email` is not compared to
/// `invitation.email` until email verification (Stage 3); addressed
/// invitations are effectively links in Stage 2a.
pub async fn accept_invitation(
    state: &SaasState,
    user: &AuthUser,
    raw_token: &str,
) -> Result<Invitation, CoreError> {
    let token_hash = hash_token(raw_token);

    let mut tx = state.pool().begin().await?;

    let invitation: Invitation = sqlx::query_as::<_, Invitation>(
        r#"
        select * from invitations
        where token_hash = $1
          and revoked_at is null
          and expires_at >= now()
          and (max_uses is null or used_count < max_uses)
        for update
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(CoreError::NotFound)?;

    sqlx::query("update invitations set used_count = used_count + 1 where id = $1")
        .bind(invitation.id)
        .execute(&mut *tx)
        .await?;

    if let Some(tenant_id) = invitation.tenant_id {
        sqlx::query(
            r#"
            insert into tenant_members (tenant_id, user_id, role)
            values ($1, $2, 'owner')
            on conflict (tenant_id, user_id) do update set role = excluded.role
            "#,
        )
        .bind(tenant_id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;

        state.authz.grant_tenant_owner(user.id, tenant_id).await?;
    } else if let Some(workspace_id) = invitation.workspace_id {
        let role = match invitation.role.as_str() {
            "admin" => WorkspaceRole::Admin,
            "editor" => WorkspaceRole::Editor,
            "viewer" => WorkspaceRole::Viewer,
            other => {
                return Err(CoreError::Internal(format!(
                    "unexpected workspace role in invitation: {other}"
                )))
            }
        };

        sqlx::query(
            r#"
            insert into workspace_members (workspace_id, user_id, role)
            values ($1, $2, $3)
            on conflict (workspace_id, user_id) do update set role = excluded.role
            "#,
        )
        .bind(workspace_id)
        .bind(user.id)
        .bind(invitation.role.as_str())
        .execute(&mut *tx)
        .await?;

        state
            .authz
            .grant_workspace_role(user.id, workspace_id, role)
            .await?;
    } else {
        // Unreachable: the CHECK constraint enforces exactly one scope.
        return Err(CoreError::Internal(
            "invitation has neither tenant_id nor workspace_id".into(),
        ));
    }

    tx.commit().await?;

    Ok(invitation)
}

/// Revokes an invitation (sets `revoked_at = now()`).
///
/// `target` is required to resolve the Casbin domain before any SQL; the
/// `WHERE` clause additionally checks that the invitation belongs to `target`,
/// so a mismatched `(target, invitation_id)` pair yields `NotFound`.
pub async fn revoke_invitation(
    state: &SaasState,
    actor: &AuthUser,
    target: InvitationTarget,
    invitation_id: Uuid,
) -> Result<(), CoreError> {
    let domain_str = target_domain(target);

    state
        .authz
        .require(actor.id, &domain_str, "invitations", "revoke")
        .await?;

    let (tenant_filter, workspace_filter) = match target {
        InvitationTarget::Tenant(id) => (Some(id), None::<Uuid>),
        InvitationTarget::Workspace(id) => (None::<Uuid>, Some(id)),
    };

    let result = sqlx::query(
        r#"
        update invitations
        set revoked_at = now()
        where id = $1
          and ($2::uuid is null or tenant_id = $2)
          and ($3::uuid is null or workspace_id = $3)
          and revoked_at is null
        "#,
    )
    .bind(invitation_id)
    .bind(tenant_filter)
    .bind(workspace_filter)
    .execute(state.pool())
    .await?;

    if result.rows_affected() == 0 {
        return Err(CoreError::NotFound);
    }

    Ok(())
}

/// Lists invitations for a tenant or workspace, newest first.
pub async fn list_invitations(
    state: &SaasState,
    actor: &AuthUser,
    target: InvitationTarget,
) -> Result<Vec<Invitation>, CoreError> {
    let domain_str = target_domain(target);

    state
        .authz
        .require(actor.id, &domain_str, "invitations", "list")
        .await?;

    let invitations = match target {
        InvitationTarget::Tenant(id) => {
            sqlx::query_as::<_, Invitation>(
                "select * from invitations where tenant_id = $1 order by created_at desc",
            )
            .bind(id)
            .fetch_all(state.pool())
            .await?
        }
        InvitationTarget::Workspace(id) => {
            sqlx::query_as::<_, Invitation>(
                "select * from invitations where workspace_id = $1 order by created_at desc",
            )
            .bind(id)
            .fetch_all(state.pool())
            .await?
        }
    };

    Ok(invitations)
}

/// Resolves the Casbin domain string for an invitation target.
fn target_domain(target: InvitationTarget) -> String {
    match target {
        InvitationTarget::Tenant(id) => domain::tenant_domain(id),
        InvitationTarget::Workspace(id) => domain::workspace_domain(id),
    }
}

/// Generates a raw invitation token: 2 × UUID v4 (244 bits of entropy),
/// hex-encoded into 64 characters.
fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// SHA-256 of the raw token, hex-encoded. Stored in `invitations.token_hash`.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Validates that `role` is allowed for the given `target`.
fn validate_role(target: InvitationTarget, role: &str) -> Result<(), CoreError> {
    match target {
        InvitationTarget::Tenant(_) => {
            if role != "tenant_owner" {
                return Err(CoreError::Validation(format!(
                    "invalid tenant role: {role} (expected tenant_owner)"
                )));
            }
        }
        InvitationTarget::Workspace(_) => {
            if !matches!(role, "admin" | "editor" | "viewer") {
                return Err(CoreError::Validation(format!(
                    "invalid workspace role: {role} (expected admin|editor|viewer)"
                )));
            }
        }
    }
    Ok(())
}