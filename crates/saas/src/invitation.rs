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
//!
//! **Stage 3f (ADR-0002 rev.2 §2.5):** both `create_invitation` and
//! `accept_invitation` reject when the target tenant's `status != 'active'`
//! with [`CoreError::TenantSuspended`]. `create_invitation` is the
//! "defense in depth" path: the example's `#[server]` already calls
//! `saas::platform::resolve_active_tenant` before the service, but a
//! future consumer that calls `saas::invitation::create_invitation`
//! directly must not be able to bypass suspension. `accept_invitation`
//! runs the status check **inside** the service (the `#[server]` does not
//! resolve for `accept_invitation`, because the invitation token is the
//! only authorization proof the actor has and the tenant id is not known
//! to the client before the lookup). Both checks run before any mutation:
//! `create_invitation` before `INSERT`, `accept_invitation` before
//! `used_count++` and before `*_members` / `casbin_rule` writes.
//!
//! `revoke_invitation` and `list_invitations` do **not** resolve the
//! tenant status — they are cleanup concerns: an owner must be able to
//! revoke stale invitations and list history on a suspended tenant
//! (ADR-0002 rev.2 §2.4). `check_invitation` (public) does not resolve
//! either — an anonymous visitor on `/invitations/:token` gets the
//! invitation's existence and status regardless; if they try to accept,
//! `accept_invitation` rejects with `TenantSuspended`.
//!
//! **Stage 3e (ADR-0004):** the three mutation services emit audit events
//! after the business operation commits:
//! - `create_invitation` → `invitation.created`
//!   (`metadata: { role, email: Option<String>, target: "tenant:{id}" |
//!   "workspace:{id}" }`).
//! - `accept_invitation` → `invitation.accepted`
//!   (`metadata: { role, target }`).
//! - `revoke_invitation` → `invitation.revoked`
//!   (`metadata: { target }`).
//!
//! Each write is best-effort via [`SaasState::audit_or_warn`] — a failed
//! audit write is `tracing::warn!` and does not fail the business
//! operation (ADR-0004 §2.4).

use audit::{events, AuditEvent};
use domain::{AuthUser, Invitation, InvitationTarget, TenantStatus};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CoreError, SaasState};

/// Default invitation lifetime, in hours (7 days).
const DEFAULT_TTL_HOURS: i32 = 168;

/// Creates an invitation.
///
/// Emits `invitation.created` (Stage 3e) after the row is committed.
///
/// Stage 3f: rejects with [`CoreError::TenantSuspended`] if the target
/// tenant is not `'active'` (defense in depth — the caller normally runs
/// `saas::platform::resolve_active_tenant` first; a direct caller must not
/// bypass suspension). For `InvitationTarget::Workspace(_)` the check
/// joins through `workspaces` → `tenants` (workspaces have no status of
/// their own).
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

    let (tenant_id, workspace_id) = match target {
        InvitationTarget::Tenant(id) => (Some(id), None),
        InvitationTarget::Workspace(id) => (None, Some(id)),
    };

    // Stage 3f: defense in depth — reject before any further work
    // (validate_role / INSERT) if the target tenant is suspended.
    ensure_tenant_active(state, tenant_id, workspace_id).await?;

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
    .bind(&email)
    .bind(&role)
    .bind(&token_hash)
    .bind(actor.id)
    .bind(ttl)
    .bind(max_uses)
    .fetch_one(state.pool())
    .await?;

    state
        .audit_or_warn(AuditEvent {
            event_type: events::INVITATION_CREATED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("invitation".into()),
            target_id: Some(invitation.id),
            metadata: serde_json::json!({
                "role": role,
                "email": email,
                "target": domain_str,
                "max_uses": max_uses,
            }),
        })
        .await;

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
/// 3. **Stage 3f:** [`ensure_tenant_active`] on the invitation's tenant
///    (`InvitationTarget::Workspace` joins through `workspaces`). Runs
///    **before** `used_count++`, so a suspended tenant does not consume a
///    use; the address checks in step 2 take priority (they run in-memory;
///    the status check needs one SELECT).
/// 4. `UPDATE used_count`.
/// 5. Insert `*_members` (`ON CONFLICT DO NOTHING`; multi-role PK) and
///    `authz.grant_role`.
/// 6. `COMMIT`.
/// 7. Emit `invitation.accepted` (Stage 3e).
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

    // Stage 3f: reject before `used_count++` if the target tenant is
    // suspended. The invitation row is locked (`FOR UPDATE`), but the
    // `tenants` row is not — a concurrent `suspend_tenant` can land
    // between this check and the insert; acceptable for the reference
    // consumer (suspension is an admin action, not a per-request race).
    ensure_tenant_active(state, invitation.tenant_id, invitation.workspace_id).await?;

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

    let target = match (invitation.tenant_id, invitation.workspace_id) {
        (Some(tid), _) => domain::tenant_domain(tid),
        (_, Some(wid)) => domain::workspace_domain(wid),
        _ => String::new(),
    };

    state
        .audit_or_warn(AuditEvent {
            event_type: events::INVITATION_ACCEPTED.into(),
            actor_id: Some(user.id),
            actor_email: Some(user.email.clone()),
            target_type: Some("invitation".into()),
            target_id: Some(invitation.id),
            metadata: serde_json::json!({
                "role": invitation.role,
                "target": target,
            }),
        })
        .await;

    Ok(invitation)
}

/// Revokes an invitation.
///
/// Emits `invitation.revoked` (Stage 3e) after the row is updated.
///
/// Stage 3f: does **not** resolve the tenant status — revoke is a cleanup
/// concern and must remain available on a suspended tenant (ADR-0002 rev.2
/// §2.4).
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

    state
        .audit_or_warn(AuditEvent {
            event_type: events::INVITATION_REVOKED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("invitation".into()),
            target_id: Some(invitation_id),
            metadata: serde_json::json!({ "target": domain_str }),
        })
        .await;

    Ok(())
}

/// Lists invitations.
///
/// Stage 3f: does **not** resolve the tenant status — listing is a
/// read-only concern and must remain available on a suspended tenant.
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

/// Rejects if the target tenant's `status != 'active'`.
///
/// Stage 3f helper used by [`create_invitation`] and
/// [`accept_invitation`] (ADR-0002 rev.2 §2.5). Exactly one of
/// `tenant_id` / `workspace_id` must be `Some`; for `Workspace` the check
/// joins through `workspaces` → `tenants` (workspaces have no status of
/// their own).
///
/// Errors:
/// - `TenantSuspended` — tenant exists and its status is not `'active'`.
/// - `NotFound` — the referenced tenant/workspace row is gone (e.g. a
///   cascaded delete that raced the FK; defensive only — the FK normally
///   removes the invitation first).
/// - `Internal` — neither id is set (should be unreachable: the
///   `invitations` CHECK constraint guarantees exactly one).
async fn ensure_tenant_active(
    state: &SaasState,
    tenant_id: Option<Uuid>,
    workspace_id: Option<Uuid>,
) -> Result<(), CoreError> {
    let status: Option<TenantStatus> = match (tenant_id, workspace_id) {
        (Some(tid), _) => {
            sqlx::query_scalar("select status from tenants where id = $1")
                .bind(tid)
                .fetch_optional(state.pool())
                .await?
        }
        (_, Some(wid)) => {
            sqlx::query_scalar(
                r#"
                select t.status
                from tenants t
                join workspaces w on w.tenant_id = t.id
                where w.id = $1
                "#,
            )
            .bind(wid)
            .fetch_optional(state.pool())
            .await?
        }
        _ => {
            return Err(CoreError::Internal(
                "invitation has neither tenant_id nor workspace_id".into(),
            ));
        }
    };

    match status {
        Some(TenantStatus::Active) => Ok(()),
        Some(TenantStatus::Suspended) => Err(CoreError::TenantSuspended),
        None => Err(CoreError::NotFound),
    }
}