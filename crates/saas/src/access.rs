//! Role and permission wrappers over the `access` crate.
//!
//! Invariant (§5 p.5): every mutation service calls
//! `authz.require(actor.id, domain, "roles", "<action>")` first.
//!
//! `assign_role` and `revoke_role` update the `casbin_rule` (via
//! `authz.grant_role`/`revoke_role`) and the `*_members` bookkeeping tables in
//! one flow. `access` is the sole owner of `roles`/`permissions`;
//! `*_members` belong to `saas`.
//!
//! Stage 2d: `delete_role` performs a full cleanup — `casbin_rule` (`g`+`p`,
//! via `authz.purge_role`), `*_members`, and the `roles` row. Steps after
//! `require` are idempotent, so a partial failure can be retried by calling
//! `delete_role` again with the same `role_id`.
//!
//! **Stage 3e (ADR-0004, decision A):**
//! - `assign_role` → `member.role_assigned` (target: user, metadata:
//!   `{ domain, role_key }`).
//! - `revoke_role` → `member.role_revoked` (same shape).
//! - `delete_role` → `role.deleted` (target: role, metadata:
//!   `{ domain, key }`). **This** is the canonical emission point — the
//!   direct `access::delete_role` does not emit (it leaves orphans in
//!   `casbin_rule`/`*_members`; see `crates/access/src/role.rs`).
//!
//! Emissions run **after** the business operation commits. `audit_or_warn`
//! (defined on `SaasState`) logs a failed write via `tracing::warn!` and
//! does **not** propagate (ADR-0004 §2.4).

use ::access::{Permission, Role, RoleKey};
use audit::{events, AuditEvent};
use domain::AuthUser;
use uuid::Uuid;

use crate::{CoreError, SaasState};

/// Creates a role in `domain`. Delegates to `access::create_role`
/// (which emits `role.created`).
pub async fn create_role(
    state: &SaasState,
    actor: &AuthUser,
    domain: &str,
    key: &RoleKey,
    name: String,
    description: String,
    permissions: &[(String, String)],
) -> Result<Role, CoreError> {
    ::access::create_role(
        state.access(),
        actor,
        domain,
        key,
        name,
        description,
        permissions,
    )
    .await
    .map_err(Into::into)
}

/// Updates a role. Delegates to `access::update_role`
/// (which emits `role.updated`).
pub async fn update_role(
    state: &SaasState,
    actor: &AuthUser,
    role_id: Uuid,
    name: String,
    description: String,
    permissions: &[(String, String)],
) -> Result<Role, CoreError> {
    ::access::update_role(
        state.access(),
        actor,
        role_id,
        name,
        description,
        permissions,
    )
    .await
    .map_err(Into::into)
}

/// Deletes a role and cleans up its residuals.
///
/// Order:
/// 1. `access::get_role_by_id(role_id)` — obtain `domain`, `key`,
///    `protected` (no `actor`, §5 p.5).
/// 2. Reject `protected=true` ([`CoreError::Forbidden`]).
/// 3. `require(actor.id, role.domain, "roles", "delete")`.
/// 4. `authz.purge_role(domain, key)` — deletes all `g`-rows (`user →
///    role_key → domain`) and `p`-rows (`role_key → domain → resource →
///    action`) for this role in this domain.
/// 5. `DELETE *_members WHERE role = role_key` — `tenant_members` /
///    `workspace_members`; `platform` has no members table.
/// 6. `access::delete_role_by_id(role_id)` — low-level `DELETE` of the
///    `roles` row (no `require`, no `protected` check; the caller performed
///    both). Idempotent, so a partial failure at any step can be retried by
///    calling `delete_role` again with the same `role_id`.
/// 7. Emit `role.deleted` (Stage 3e, decision A).
///
/// The `require` runs once, in this function; it is not re-executed after
/// the actor's own `g`-row for `role_key` has been purged in step 4. This
/// avoids the self-delete deadlock where the actor is the sole holder of
/// the very role being deleted.
pub async fn delete_role(
    state: &SaasState,
    actor: &AuthUser,
    role_id: Uuid,
) -> Result<(), CoreError> {
    let role = ::access::get_role_by_id(state.access(), role_id)
        .await
        .map_err(CoreError::from)?
        .ok_or(CoreError::NotFound)?;

    if role.protected {
        return Err(CoreError::Forbidden);
    }

    state
        .authz()
        .require(actor.id, &role.domain, "roles", "delete")
        .await?;

    state
        .authz()
        .purge_role(&role.domain, role.key.as_str())
        .await?;

    delete_members_by_domain(state, &role.domain, role.key.as_str()).await?;

    ::access::delete_role_by_id(state.access(), role_id)
        .await
        .map_err(CoreError::from)?;

    let domain_for_event = role.domain.clone();
    let key_for_event = role.key.as_str().to_string();

    state
        .audit_or_warn(AuditEvent {
            event_type: events::ROLE_DELETED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("role".into()),
            target_id: Some(role_id),
            metadata: serde_json::json!({
                "domain": domain_for_event,
                "key": key_for_event,
            }),
        })
        .await;

    Ok(())
}

/// Lists roles in `domain`. Delegates to `access::list_roles`.
pub async fn list_roles(
    state: &SaasState,
    actor: &AuthUser,
    domain: &str,
) -> Result<Vec<Role>, CoreError> {
    ::access::list_roles(state.access(), actor, domain)
        .await
        .map_err(Into::into)
}

/// Lists all permissions in the reference table. Delegates to
/// `access::list_permissions`.
pub async fn list_permissions(state: &SaasState) -> Result<Vec<Permission>, CoreError> {
    ::access::list_permissions(state.access())
        .await
        .map_err(Into::into)
}

/// Returns the `(resource, action)` pairs that `actor` is effectively
/// allowed to perform in `domain`.
///
/// Iterates the reference table (`access::list_permissions`) and calls
/// `authz.can(actor.id, domain, resource, action)` for each pair. This is a
/// **read-only UX helper** for gating buttons and links; it does **not**
/// replace `authz.require` in `saas::*` services, which every action still
/// calls server-side.
///
/// No `require` call: any authenticated actor may discover their own
/// effective permissions in a domain. A non-member gets an empty vector.
///
/// Does not emit audit events (read-only).
pub async fn my_permissions(
    state: &SaasState,
    actor: &AuthUser,
    domain: &str,
) -> Result<Vec<(String, String)>, CoreError> {
    let reference = ::access::list_permissions(state.access())
        .await
        .map_err(CoreError::from)?;

    let mut out = Vec::with_capacity(reference.len());
    for Permission {
        resource, action, ..
    } in reference
    {
        if state
            .authz()
            .can(actor.id, domain, &resource, &action)
            .await?
        {
            out.push((resource, action));
        }
    }
    Ok(out)
}

/// Assigns `role_key` to `user_id` in `domain`.
///
/// Order:
/// 1. `require(actor.id, domain, "roles", "grant")`.
/// 2. `::access::get_permissions_for_role(domain, role_key)` to fetch `p`-rows.
/// 3. `INSERT` into `tenant_members` / `workspace_members` (bookkeeping).
/// 4. `authz.grant_role(user_id, domain, role_key, permissions)`.
/// 5. Emit `member.role_assigned` (Stage 3e; target: user).
pub async fn assign_role(
    state: &SaasState,
    actor: &AuthUser,
    user_id: Uuid,
    domain: &str,
    role_key: &RoleKey,
) -> Result<(), CoreError> {
    state
        .authz()
        .require(actor.id, domain, "roles", "grant")
        .await?;

    let permissions = ::access::get_permissions_for_role(state.access(), domain, role_key)
        .await
        .map_err(CoreError::from)?;

    match parse_domain(domain) {
        Some(Scope::Tenant(tenant_id)) => {
            sqlx::query(
                r#"
                insert into tenant_members (tenant_id, user_id, role)
                values ($1, $2, $3)
                on conflict do nothing
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(role_key.as_str())
            .execute(state.pool())
            .await?;
        }
        Some(Scope::Workspace(workspace_id)) => {
            sqlx::query(
                r#"
                insert into workspace_members (workspace_id, user_id, role)
                values ($1, $2, $3)
                on conflict do nothing
                "#,
            )
            .bind(workspace_id)
            .bind(user_id)
            .bind(role_key.as_str())
            .execute(state.pool())
            .await?;
        }
        Some(Scope::Platform) => {
            // `platform` has no `*_members` table (bookkeeping is not needed).
        }
        None => {
            return Err(CoreError::Validation(format!(
                "invalid domain for assign_role: {domain}"
            )));
        }
    }

    state
        .authz()
        .grant_role(user_id, domain, role_key.as_str(), &permissions)
        .await?;

    state
        .audit_or_warn(AuditEvent {
            event_type: events::MEMBER_ROLE_ASSIGNED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("user".into()),
            target_id: Some(user_id),
            metadata: serde_json::json!({
                "domain": domain,
                "role_key": role_key.as_str(),
            }),
        })
        .await;

    Ok(())
}

/// Revokes `role_key` from `user_id` in `domain`.
///
/// Order:
/// 1. `require(actor.id, domain, "roles", "grant")`.
/// 2. `DELETE` from `tenant_members` / `workspace_members`.
/// 3. `authz.revoke_role(user_id, domain, role_key)`.
/// 4. Emit `member.role_revoked` (Stage 3e; target: user).
pub async fn revoke_role(
    state: &SaasState,
    actor: &AuthUser,
    user_id: Uuid,
    domain: &str,
    role_key: &RoleKey,
) -> Result<(), CoreError> {
    state
        .authz()
        .require(actor.id, domain, "roles", "grant")
        .await?;

    match parse_domain(domain) {
        Some(Scope::Tenant(tenant_id)) => {
            sqlx::query(
                r#"
                delete from tenant_members
                where tenant_id = $1 and user_id = $2 and role = $3
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(role_key.as_str())
            .execute(state.pool())
            .await?;
        }
        Some(Scope::Workspace(workspace_id)) => {
            sqlx::query(
                r#"
                delete from workspace_members
                where workspace_id = $1 and user_id = $2 and role = $3
                "#,
            )
            .bind(workspace_id)
            .bind(user_id)
            .bind(role_key.as_str())
            .execute(state.pool())
            .await?;
        }
        Some(Scope::Platform) => {
            // `platform` has no `*_members` table.
        }
        None => {
            return Err(CoreError::Validation(format!(
                "invalid domain for revoke_role: {domain}"
            )));
        }
    }

    state
        .authz()
        .revoke_role(user_id, domain, role_key.as_str())
        .await?;

    state
        .audit_or_warn(AuditEvent {
            event_type: events::MEMBER_ROLE_REVOKED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("user".into()),
            target_id: Some(user_id),
            metadata: serde_json::json!({
                "domain": domain,
                "role_key": role_key.as_str(),
            }),
        })
        .await;

    Ok(())
}

/// Deletes every `*_members` row for `(domain, role_key)`. `platform` is a
/// no-op (no `*_members` table). Called from [`delete_role`] only; not
/// exposed publicly.
async fn delete_members_by_domain(
    state: &SaasState,
    domain: &str,
    role_key: &str,
) -> Result<(), CoreError> {
    match parse_domain(domain) {
        Some(Scope::Tenant(tenant_id)) => {
            sqlx::query("delete from tenant_members where tenant_id = $1 and role = $2")
                .bind(tenant_id)
                .bind(role_key)
                .execute(state.pool())
                .await?;
        }
        Some(Scope::Workspace(workspace_id)) => {
            sqlx::query("delete from workspace_members where workspace_id = $1 and role = $2")
                .bind(workspace_id)
                .bind(role_key)
                .execute(state.pool())
                .await?;
        }
        Some(Scope::Platform) => {
            // `platform` has no `*_members` table.
        }
        None => {
            return Err(CoreError::Validation(format!(
                "invalid domain for delete_role: {domain}"
            )));
        }
    }
    Ok(())
}

enum Scope {
    Platform,
    Tenant(Uuid),
    Workspace(Uuid),
}

fn parse_domain(domain: &str) -> Option<Scope> {
    if domain == "platform" {
        Some(Scope::Platform)
    } else if let Some(id) = domain.strip_prefix("tenant:") {
        Uuid::parse_str(id).ok().map(Scope::Tenant)
    } else if let Some(id) = domain.strip_prefix("workspace:") {
        Uuid::parse_str(id).ok().map(Scope::Workspace)
    } else {
        None
    }
}