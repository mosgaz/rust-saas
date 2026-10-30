//! Invitations: creation, acceptance, revocation, listing.
//!
//! An invitation targets exactly one scope: a tenant or a workspace.
//! `email IS NULL` means a reusable link; `email IS NOT NULL` means an
//! addressed invitation.
//!
//! **Invariant exception (§5 p.5):** [`accept_invitation`] does **not** call
//! `authz.require` — it authorizes by the invitation token. All other
//! services in this module check `authz.require(...)` first.
//!
//! Stage 3c: [`accept_invitation`] enforces addressed invitations before
//! mutating anything:
//! 1. If `invitation.email IS NULL` (link), no extra checks.
//! 2. If `invitation.email IS NOT NULL`:
//!    a. `actor.email_verified == false` → [`CoreError::EmailNotVerified`]
//!       (verified-first: an unverified address is not proof of ownership).
//!    b. `!actor.email.eq_ignore_ascii_case(invitation.email)` →
//!       [`CoreError::Forbidden`] (case-insensitive; see Appendix B §2.32).
//!
//! The check runs after the `SELECT ... FOR UPDATE` lookup and before
//! `used_count` is incremented, so a rejected accept does not consume a use.

use domain::{AuthUser, Invitation, InvitationTarget};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CoreError, SaasState};

/// Default invitation lifetime, in hours (7 days).
const DEFAULT_TTL_HOURS: i32 = 168;

/// Creates an invitation.
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

    validate_role(state, target, &role).await?;

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
/// Order:
/// 1. `SELECT ... FOR UPDATE` by `token_hash`, filtered by
///    `revoked_at IS NULL`, `expires_at >= now()`, and remaining uses;
///    `None` → [`CoreError::NotFound`].
/// 2. **Stage 3c:** if `invitation.email IS NOT NULL` (addressed):
///    a. `actor.email_verified == false` → [`CoreError::EmailNotVerified`]
///       (verified-first, see §«Решения A»).
///    b. `!actor.email.eq_ignore_ascii_case(inv.email)` →
///       [`CoreError::Forbidden`] (case-insensitive, §«Решения C»).
///    Both checks run **before** `used_count` is incremented, so a
///    rejected accept does not consume a use.
/// 3. `UPDATE used_count`.
/// 4. Insert `*_members` (`ON CONFLICT DO NOTHING`; multi-role PK) and
///    `authz.grant_role`.
/// 5. `COMMIT`.
///
/// Link invitations (`email IS NULL`) skip step 2 entirely; unverified
/// actors may still accept them (Stage 3c preserves the Stage 2a
/// behaviour for links).
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

    // Stage 3c: addressed invitation — verified-first, then case-insensitive
    // match. Both checks precede any mutation (`used_count`, `*_members`,
    // `casbin_rule`), so a rejected accept leaves the invitation untouched.
    if let Some(inv_email) = invitation.email.as_deref() {
        if !user.email_verified {
            return Err(CoreError::EmailNotVerified);
        }
        if !user.email.eq_ignore_ascii_case(inv_email) {
            return Err(CoreError::Forbidden);
        }
    }

    sqlx::query("update invitations set used_count = used_count + 1 where id = $1")
        .bind(invitation.id)
        .execute(&mut *tx)
        .await?;

    let role_key = ::access::RoleKey::parse(&invitation.role)
        .map_err(|e| CoreError::Validation(e.to_string()))?;

    if let Some(tenant_id) = invitation.tenant_id {
        let domain_str = domain::tenant_domain(tenant_id);
        let permissions =
            ::access::get_permissions_for_role(state.access(), &domain_str, &role_key)
                .await
                .map_err(CoreError::from)?;

        sqlx::query(
            r#"
            insert into tenant_members (tenant_id, user_id, role)
            values ($1, $2, $3)
            on conflict do nothing
            "#,
        )
        .bind(tenant_id)
        .bind(user.id)
        .bind(role_key.as_str())
        .execute(&mut *tx)
        .await?;

        state
            .authz
            .grant_role(user.id, &domain_str, role_key.as_str(), &permissions)
            .await?;
    } else if let Some(workspace_id) = invitation.workspace_id {
        let domain_str = domain::workspace_domain(workspace_id);
        let permissions =
            ::access::get_permissions_for_role(state.access(), &domain_str, &role_key)
                .await
                .map_err(CoreError::from)?;

        sqlx::query(
            r#"
            insert into workspace_members (workspace_id, user_id, role)
            values ($1, $2, $3)
            on conflict do nothing
            "#,
        )
        .bind(workspace_id)
        .bind(user.id)
        .bind(role_key.as_str())
        .execute(&mut *tx)
        .await?;

        state
            .authz
            .grant_role(user.id, &domain_str, role_key.as_str(), &permissions)
            .await?;
    } else {
        return Err(CoreError::Internal(
            "invitation has neither tenant_id nor workspace_id".into(),
        ));
    }

    tx.commit().await?;

    Ok(invitation)
}

/// Revokes an invitation.
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

/// Lists invitations.
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

fn target_domain(target: InvitationTarget) -> String {
    match target {
        InvitationTarget::Tenant(id) => domain::tenant_domain(id),
        InvitationTarget::Workspace(id) => domain::workspace_domain(id),
    }
}

fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Validates that `role` exists in the target domain.
async fn validate_role(
    state: &SaasState,
    target: InvitationTarget,
    role: &str,
) -> Result<(), CoreError> {
    let domain_str = target_domain(target);
    let role_key =
        ::access::RoleKey::parse(role).map_err(|e| CoreError::Validation(e.to_string()))?;

    let exists = ::access::get_role(state.access(), &domain_str, &role_key)
        .await
        .map_err(CoreError::from)?
        .is_some();

    if !exists {
        return Err(CoreError::Validation(format!(
            "role '{role}' does not exist in domain '{domain_str}'"
        )));
    }
    Ok(())
}
