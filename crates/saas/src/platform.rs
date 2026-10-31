//! Platform-level services: tenant container and provisioning, platform
//! administration (list, suspend, activate), and active-tenant resolution.
//!
//! Extracted from `lib.rs` in Stage 3f. Paths are preserved:
//! `saas::platform::{create_tenant, provision_tenant, list_tenants,
//! suspend_tenant, activate_tenant, resolve_active_tenant, ActiveTenant}`.
//! `saas::ActiveTenant` and `saas::resolve_active_tenant` are also
//! re-exported from the crate root for convenience (`pub use
//! platform::{ActiveTenant, resolve_active_tenant};` in `lib.rs`).
//!
//! **`create_tenant` vs `provision_tenant`.** `create_tenant` inserts the
//! tenant row only — no owner, no membership, no `casbin_rule`. Its caller
//! is responsible for provisioning (via `provision_tenant` or an invitation
//! flow). `provision_tenant` does both: inserts the tenant and assigns
//! `owner_role_key` to `owner` (`access::create_owner_role` +
//! `authz.grant_role` + `tenant_members` row).
//!
//! **Platform admin is not a superuser.** `list_tenants`, `suspend_tenant`,
//! and `activate_tenant` require `(tenants, list|manage)` in
//! `PLATFORM_DOMAIN`; they do **not** grant the actor any role inside the
//! target tenant (ADR-0002, handoff §2).
//!
//! **`resolve_active_tenant` — explicit call, membership-only.** Callers
//! pass a `tenant_id` and get back an [`ActiveTenant`] or a typed error
//! (`Forbidden` if the actor is not a tenant member, `TenantSuspended` if
//! the tenant's status is not `active`, `NotFound` if the tenant does not
//! exist). Membership is checked via `EXISTS tenant_members` — not
//! `authz.require(tenants, read)` — so that workspace-only roles
//! (`editor`/`viewer`) can pass (ADR-0002 rev.2 §2.4). `#[server]`
//! functions in the example call this before any mutation of tenant-scoped
//! resources (ADR-0002 §3); reads do not resolve.
//!
//! **Idempotency.** `suspend_tenant` and `activate_tenant` are idempotent:
//! `UPDATE tenants SET status = ... WHERE id = $1 AND status = <expected>
//! RETURNING *` emits the transition event only when the update matched
//! (an actual transition occurred). Zero-row updates fall through to a
//! `SELECT ... FOR UPDATE` lookup that returns the existing row (no
//! emission) or `NotFound`.
//!
//! **Emission points (ADR-0004, decision C):**
//! - `create_tenant` / `provision_tenant` → `tenant.created` (target:
//!   tenant; `provision_tenant` puts `owner_id` / `owner_role_key` in
//!   `metadata`).
//! - `suspend_tenant` → `tenant.suspended` (only on transition).
//! - `activate_tenant` → `tenant.activated` (only on transition).
//! All emissions are best-effort via `SaasState::audit_or_warn`; a failed
//! write does not fail the business operation (ADR-0004 §2.4).

use ::access::RoleKey;
use audit::{events, AuditEvent};
use domain::{AuthUser, Tenant, TenantStatus, PLATFORM_DOMAIN};
use uuid::Uuid;

use crate::{CoreError, SaasState};

/// Creates a tenant container. No side effects.
///
/// Emits `tenant.created` (Stage 3e) after the row is committed.
pub async fn create_tenant(
    state: &SaasState,
    actor: &AuthUser,
    name: String,
) -> Result<Tenant, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenants", "create")
        .await?;

    let tenant = sqlx::query_as::<_, Tenant>(
        "insert into tenants (name) values ($1) returning id, name, status, created_at",
    )
    .bind(&name)
    .fetch_one(&state.pool)
    .await?;

    state
        .audit_or_warn(AuditEvent {
            event_type: events::TENANT_CREATED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("tenant".into()),
            target_id: Some(tenant.id),
            metadata: serde_json::json!({ "name": name }),
        })
        .await;

    Ok(tenant)
}

/// Creates a tenant and assigns an explicit owner with `owner_role_key`.
///
/// Emits `tenant.created` (Stage 3e) after the transaction commits; the
/// target is the new tenant, the actor is `actor` (not `owner`).
pub async fn provision_tenant(
    state: &SaasState,
    actor: &AuthUser,
    name: String,
    owner: &AuthUser,
    owner_role_key: &RoleKey,
) -> Result<Tenant, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenants", "create")
        .await?;

    let mut tx = state.pool.begin().await?;

    let tenant = sqlx::query_as::<_, Tenant>(
        "insert into tenants (name) values ($1) returning id, name, status, created_at",
    )
    .bind(&name)
    .fetch_one(&mut *tx)
    .await?;

    let domain_str = domain::tenant_domain(tenant.id);

    ::access::create_owner_role(state.access(), &domain_str)
        .await
        .map_err(CoreError::from)?;

    let permissions =
        ::access::get_permissions_for_role(state.access(), &domain_str, owner_role_key)
            .await
            .map_err(CoreError::from)?;

    state
        .authz
        .grant_role(owner.id, &domain_str, owner_role_key.as_str(), &permissions)
        .await?;

    sqlx::query(
        r#"
        insert into tenant_members (tenant_id, user_id, role)
        values ($1, $2, $3)
        on conflict do nothing
        "#,
    )
    .bind(tenant.id)
    .bind(owner.id)
    .bind(owner_role_key.as_str())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    state
        .audit_or_warn(AuditEvent {
            event_type: events::TENANT_CREATED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("tenant".into()),
            target_id: Some(tenant.id),
            metadata: serde_json::json!({
                "name": name,
                "owner_id": owner.id.to_string(),
                "owner_role_key": owner_role_key.as_str(),
            }),
        })
        .await;

    Ok(tenant)
}

/// Lists every tenant on the platform, newest first.
///
/// Requires `(tenants, list)` in `PLATFORM_DOMAIN` (Stage 3f). No pagination
/// in Stage 3f (MVP; Stage 4 adds `limit` / `offset` — see Appendix B
/// §IV). Read-only: no audit emission.
pub async fn list_tenants(
    state: &SaasState,
    actor: &AuthUser,
) -> Result<Vec<Tenant>, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenants", "list")
        .await?;

    let tenants = sqlx::query_as::<_, Tenant>(
        "select id, name, status, created_at from tenants order by created_at desc",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(tenants)
}

/// Suspends a tenant (`tenants.status = 'suspended'`).
///
/// Requires `(tenants, manage)` in `PLATFORM_DOMAIN`. Idempotent: emits
/// `tenant.suspended` only on a transition (`active` → `suspended`); a
/// no-op call on an already-suspended tenant returns the row unchanged and
/// emits nothing. `NotFound` if the tenant does not exist.
///
/// A suspended tenant blocks mutating `#[server]` calls that go through
/// [`resolve_active_tenant`]; read-only pages (`list_*`, `my_permissions`,
/// `get_*`) are not gated here (ADR-0002 rev.2 §2.4). Invitations are
/// blocked by [`crate::invitation::create_invitation`] (defense in depth)
/// and by [`crate::invitation::accept_invitation`] (both check
/// `status = 'active'` on the invitation's tenant).
pub async fn suspend_tenant(
    state: &SaasState,
    actor: &AuthUser,
    tenant_id: Uuid,
) -> Result<Tenant, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenants", "manage")
        .await?;

    let updated = sqlx::query_as::<_, Tenant>(
        r#"
        update tenants
        set status = 'suspended'
        where id = $1 and status = 'active'
        returning id, name, status, created_at
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.pool)
    .await?;

    let (tenant, transitioned) = match updated {
        Some(t) => (t, true),
        None => {
            let existing = sqlx::query_as::<_, Tenant>(
                "select id, name, status, created_at from tenants where id = $1 for update",
            )
            .bind(tenant_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(CoreError::NotFound)?;
            (existing, false)
        }
    };

    if transitioned {
        state
            .audit_or_warn(AuditEvent {
                event_type: events::TENANT_SUSPENDED.into(),
                actor_id: Some(actor.id),
                actor_email: Some(actor.email.clone()),
                target_type: Some("tenant".into()),
                target_id: Some(tenant.id),
                metadata: serde_json::json!({}),
            })
            .await;
    }

    Ok(tenant)
}

/// Activates a suspended tenant (`tenants.status = 'active'`).
///
/// Symmetric to [`suspend_tenant`]: requires `(tenants, manage)` in
/// `PLATFORM_DOMAIN`; emits `tenant.activated` only on a transition
/// (`suspended` → `active`); idempotent no-op returns the row with no
/// emission; `NotFound` if the tenant does not exist.
pub async fn activate_tenant(
    state: &SaasState,
    actor: &AuthUser,
    tenant_id: Uuid,
) -> Result<Tenant, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenants", "manage")
        .await?;

    let updated = sqlx::query_as::<_, Tenant>(
        r#"
        update tenants
        set status = 'active'
        where id = $1 and status = 'suspended'
        returning id, name, status, created_at
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.pool)
    .await?;

    let (tenant, transitioned) = match updated {
        Some(t) => (t, true),
        None => {
            let existing = sqlx::query_as::<_, Tenant>(
                "select id, name, status, created_at from tenants where id = $1 for update",
            )
            .bind(tenant_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(CoreError::NotFound)?;
            (existing, false)
        }
    };

    if transitioned {
        state
            .audit_or_warn(AuditEvent {
                event_type: events::TENANT_ACTIVATED.into(),
                actor_id: Some(actor.id),
                actor_email: Some(actor.email.clone()),
                target_type: Some("tenant".into()),
                target_id: Some(tenant.id),
                metadata: serde_json::json!({}),
            })
            .await;
    }

    Ok(tenant)
}

/// A tenant whose `status = 'active'`, as resolved by
/// [`resolve_active_tenant`].
///
/// Dereferences to [`Tenant`], so callers can pass `active.id`,
/// `active.name`, etc. `into_inner` unwraps it when the newtype gets in
/// the way. The type-level guarantee (only constructed when
/// `status = 'active'`) makes the "is this tenant active?" check auditable:
/// a function that takes `&ActiveTenant` proves the resolution has happened.
#[derive(Debug, Clone)]
pub struct ActiveTenant(Tenant);

impl ActiveTenant {
    /// Consumes the newtype, returning the wrapped [`Tenant`].
    pub fn into_inner(self) -> Tenant {
        self.0
    }
}

impl std::ops::Deref for ActiveTenant {
    type Target = Tenant;
    fn deref(&self) -> &Tenant {
        &self.0
    }
}

/// Resolves a tenant that the actor is a member of and that is not
/// suspended.
///
/// Order (ADR-0002 rev.2 §2.4; decision A):
/// 1. Membership check: `EXISTS (SELECT 1 FROM tenant_members WHERE
///    tenant_id = $1 AND user_id = $2)`. **Not** `authz.require(tenants,
///    read)` — an `editor`/`viewer` with no `(tenants, read)` permission in
///    the tenant domain would otherwise be unable to load pages that
///    legitimately mutate their workspace. Membership is the right
///    precondition for "can I act in this tenant?".
/// 2. Non-member → [`CoreError::Forbidden`].
/// 3. `SELECT ... FROM tenants WHERE id = $1`; missing → `NotFound`.
/// 4. `tenant.status != 'active'` → [`CoreError::TenantSuspended`].
/// 5. Success → [`ActiveTenant`].
///
/// Callers in the example (`#[server]` functions that mutate tenant-scoped
/// resources) call this **explicitly**, not via middleware (ADR-0002 §3).
/// Read-only paths (`list_members`, `my_permissions`, `list_roles`,
/// `list_invitations`, `list_documents`, `get_*`, `revoke_invitation`) do
/// **not** resolve — a suspended tenant should still allow reading its
/// history (cleanup concerns). The canonical mutation paths that resolve
/// are: `create_workspace`, `create_document`, `create_role`,
/// `update_role`, `delete_role`, `assign_role`, `remove_role`,
/// `create_invitation`.
pub async fn resolve_active_tenant(
    state: &SaasState,
    actor: &AuthUser,
    tenant_id: Uuid,
) -> Result<ActiveTenant, CoreError> {
    let is_member: bool = sqlx::query_scalar(
        "select exists (select 1 from tenant_members where tenant_id = $1 and user_id = $2)",
    )
    .bind(tenant_id)
    .bind(actor.id)
    .fetch_one(&state.pool)
    .await?;

    if !is_member {
        return Err(CoreError::Forbidden);
    }

    let tenant = sqlx::query_as::<_, Tenant>(
        "select id, name, status, created_at from tenants where id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(CoreError::NotFound)?;

    if tenant.status != TenantStatus::Active {
        return Err(CoreError::TenantSuspended);
    }

    Ok(ActiveTenant(tenant))
}