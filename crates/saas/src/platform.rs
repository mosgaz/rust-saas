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
//! and `activate_tenant` require `(tenant, list|manage)` in
//! `PLATFORM_DOMAIN`; they do **not** grant the actor any role inside the
//! target tenant (ADR-0002, handoff §2).
//!
//! **`resolve_active_tenant` — explicit call, membership-only.** Callers
//! pass a `tenant_id` and get back an [`ActiveTenant`] or a typed error
//! (`Forbidden` if the actor is not a tenant member, `TenantSuspended` if
//! the tenant's status is not `active`, `NotFound` if the tenant does not
//! exist). Membership is checked via `EXISTS tenant_members` — not
//! `authz.require(tenant, read)` — so that workspace-only roles
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
//!
//! All emissions are best-effort via `SaasState::audit_or_warn`; a failed
//! write does not fail the business operation (ADR-0004 §2.4).

use ::access::RoleKey;
use audit::{events, AuditEvent};
use domain::{AuthUser, Page, Tenant, TenantStatus, Workspace, PLATFORM_DOMAIN};
use uuid::Uuid;
use tracing::instrument;

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
        .require(actor.id, PLATFORM_DOMAIN, "tenant", "create")
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
#[instrument(
    skip(state, actor, name),
    fields(actor_id = %actor.id, owner_id = %owner.id, role_key = %owner_role_key.as_str()),
)]
pub async fn provision_tenant(
    state: &SaasState,
    actor: &AuthUser,
    name: String,
    owner: &AuthUser,
    owner_role_key: &RoleKey,
) -> Result<Tenant, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenant", "create")
        .await?;

    let mut tx = state.pool.begin().await?;

    let tenant = sqlx::query_as::<_, Tenant>(
        "insert into tenants (name) values ($1) returning id, name, status, created_at",
    )
    .bind(&name)
    .fetch_one(&mut *tx)
    .await?;

    let domain_str = domain::tenant_domain(tenant.id);

    ::access::create_owner_role(state.access()?, &domain_str)
        .await
        .map_err(CoreError::from)?;

    let permissions =
        ::access::get_permissions_for_role(state.access()?, &domain_str, owner_role_key)
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

/// Lists every tenant on the platform, newest first, with pagination.
///
/// Requires `(tenant, list)` in `PLATFORM_DOMAIN` (Stage 3f).
/// Read-only: no audit emission.
pub async fn list_tenants_paged(
    state: &SaasState,
    actor: &AuthUser,
    limit: i64,
    offset: i64,
) -> Result<Page<Tenant>, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenant", "list")
        .await?;

    let total: i64 = sqlx::query_scalar("select count(*) from tenants")
        .fetch_one(&state.pool)
        .await?;

    let items = sqlx::query_as::<_, Tenant>(
        r#"
        select id, name, status, created_at
        from tenants
        order by created_at desc
        limit $1 offset $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Page {
        items,
        total,
        limit,
        offset,
    })
}

/// Lists every tenant on the platform, newest first.
///
/// **Deprecated:** use [`list_tenants_paged`] with `(i64::MAX, 0)` for "all rows".
#[deprecated(note = "use list_tenants_paged(..., i64::MAX, 0) for 'all rows'")]
pub async fn list_tenants(state: &SaasState, actor: &AuthUser) -> Result<Vec<Tenant>, CoreError> {
    Ok(list_tenants_paged(state, actor, i64::MAX, 0).await?.items)
}

/// Suspends a tenant (`tenants.status = 'suspended'`).
///
/// Requires `(tenant, manage)` in `PLATFORM_DOMAIN`. Idempotent: emits
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
#[instrument(skip(state, actor), fields(operation = "suspend_tenant", actor_id = %actor.id))]
pub async fn suspend_tenant(
    state: &SaasState,
    actor: &AuthUser,
    tenant_id: Uuid,
) -> Result<Tenant, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenant", "manage")
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
/// Symmetric to [`suspend_tenant`]: requires `(tenant, manage)` in
/// `PLATFORM_DOMAIN`; emits `tenant.activated` only on a transition
/// (`suspended` → `active`); idempotent no-op returns the row with no
/// emission; `NotFound` if the tenant does not exist.
#[instrument(skip(state, actor), fields(operation = "activate_tenant", actor_id = %actor.id))]
pub async fn activate_tenant(
    state: &SaasState,
    actor: &AuthUser,
    tenant_id: Uuid,
) -> Result<Tenant, CoreError> {
    state
        .authz
        .require(actor.id, PLATFORM_DOMAIN, "tenant", "manage")
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
///    tenant_id = $1 AND user_id = $2)`. **Not** `authz.require(tenant,
///    read)` — an `editor`/`viewer` with no `(tenant, read)` permission in
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
#[instrument(skip(state, actor), fields(operation = "resolve_active_tenant", actor_id = %actor.id))]
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

/// A workspace whose parent tenant's `status = 'active'`, as resolved by
/// [`resolve_active_workspace`].
///
/// Symmetric to [`ActiveTenant`]: type-level guarantee that the parent
/// tenant is active. `into_inner` unwraps the newtype; `Deref` gives
/// field access.
#[derive(Debug, Clone)]
pub struct ActiveWorkspace(Workspace);

impl ActiveWorkspace {
    /// Consumes the newtype, returning the wrapped [`Workspace`].
    pub fn into_inner(self) -> Workspace {
        self.0
    }
}

impl std::ops::Deref for ActiveWorkspace {
    type Target = Workspace;
    fn deref(&self) -> &Workspace {
        &self.0
    }
}

/// Resolves a tenant that the actor is a member of — **without** checking
/// `status`.
///
/// Read path only: a suspended tenant must still allow its members to
/// read (`list_*`, `get_*`, `my_permissions`, `revoke_invitation`).
/// Mutations use [`resolve_active_tenant`] instead.
///
/// Order:
/// 1. `EXISTS tenant_members` → non-member is [`CoreError::Forbidden`].
/// 2. `SELECT tenants` → missing is [`CoreError::NotFound`].
pub async fn resolve_tenant(
    state: &SaasState,
    actor: &AuthUser,
    tenant_id: Uuid,
) -> Result<Tenant, CoreError> {
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

    sqlx::query_as::<_, Tenant>("select id, name, status, created_at from tenants where id = $1")
        .bind(tenant_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(CoreError::NotFound)
}

/// Resolves a workspace that the actor is a member of — **without**
/// checking the parent tenant's status.
///
/// Read path only. Mutations use [`resolve_active_workspace`].
///
/// Order:
/// 1. `EXISTS workspace_members` → non-member is [`CoreError::Forbidden`].
/// 2. `SELECT workspaces` → missing is [`CoreError::NotFound`].
pub async fn resolve_workspace(
    state: &SaasState,
    actor: &AuthUser,
    workspace_id: Uuid,
) -> Result<Workspace, CoreError> {
    let is_member: bool = sqlx::query_scalar(
        "select exists (select 1 from workspace_members where workspace_id = $1 and user_id = $2)",
    )
    .bind(workspace_id)
    .bind(actor.id)
    .fetch_one(&state.pool)
    .await?;

    if !is_member {
        return Err(CoreError::Forbidden);
    }

    sqlx::query_as::<_, Workspace>(
        "select id, tenant_id, name, created_at from workspaces where id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(CoreError::NotFound)
}

/// Resolves a workspace whose parent tenant is active.
///
/// Symmetric to [`resolve_active_tenant`] but for workspace scope. The
/// workspace has no `status` of its own — the check goes through
/// `workspaces.tenant_id → tenants.status`. Composed from
/// [`resolve_workspace`] + one `SELECT tenants`.
///
/// Order:
/// 1. [`resolve_workspace`] — membership + row (`Forbidden` / `NotFound`).
/// 2. `SELECT tenants.status` — parent gone → `NotFound` (defensive; FK
///    should cascade).
/// 3. `status != 'active'` → [`CoreError::TenantSuspended`].
#[instrument(
    skip(state, actor),
    fields(operation = "resolve_active_workspace", actor_id = %actor.id),
)]
pub async fn resolve_active_workspace(
    state: &SaasState,
    actor: &AuthUser,
    workspace_id: Uuid,
) -> Result<ActiveWorkspace, CoreError> {
    let ws = resolve_workspace(state, actor, workspace_id).await?;

    let status: Option<TenantStatus> =
        sqlx::query_scalar("select status from tenants where id = $1")
            .bind(ws.tenant_id)
            .fetch_optional(&state.pool)
            .await?;

    match status {
        Some(TenantStatus::Active) => Ok(ActiveWorkspace(ws)),
        Some(TenantStatus::Suspended) => Err(CoreError::TenantSuspended),
        None => Err(CoreError::NotFound),
    }
}

/// Returns `true` iff `user_id` is a member of `tenant_id`.
///
/// Read-only helper for consumer-side UI gating. **Not** a security check
/// — mutations still go through `resolve_active_tenant` /
/// `resolve_active_workspace` / `authz.require`.
pub async fn is_tenant_member(
    state: &SaasState,
    user_id: Uuid,
    tenant_id: Uuid,
) -> Result<bool, CoreError> {
    let exists: bool = sqlx::query_scalar(
        "select exists (select 1 from tenant_members where tenant_id = $1 and user_id = $2)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(exists)
}

/// Returns `true` iff `user_id` is a member of `workspace_id`.
///
/// Same caveat as [`is_tenant_member`] — UI gating only.
pub async fn is_workspace_member(
    state: &SaasState,
    user_id: Uuid,
    workspace_id: Uuid,
) -> Result<bool, CoreError> {
    let exists: bool = sqlx::query_scalar(
        "select exists (select 1 from workspace_members where workspace_id = $1 and user_id = $2)",
    )
    .bind(workspace_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(exists)
}

