//! Role and permission wrappers over the `access` crate.
//!
//! Invariant (§5 p.5): every mutation service calls
//! `authz.require(actor.id, domain, "roles", "<action>")` first.
//!
//! `assign_role` and `revoke_role` update the `casbin_rule` (via
//! `authz.grant_role`/`revoke_role`) and the `*_members` bookkeeping tables in
//! one flow. `access` is the sole owner of `roles`/`permissions`;
//! `*_members` belong to `saas`.

use ::access::{Permission, Role, RoleKey};
use domain::AuthUser;
use uuid::Uuid;

use crate::{CoreError, SaasState};

/// Creates a role in `domain`. Delegates to `access::create_role`.
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

/// Updates a role. Delegates to `access::update_role`.
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

/// Deletes a role. Delegates to `access::delete_role`.
pub async fn delete_role(
    state: &SaasState,
    actor: &AuthUser,
    role_id: Uuid,
) -> Result<(), CoreError> {
    ::access::delete_role(state.access(), actor, role_id)
        .await
        .map_err(Into::into)
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

/// Assigns `role_key` to `user_id` in `domain`.
///
/// Order:
/// 1. `require(actor.id, domain, "roles", "grant")`.
/// 2. `::access::get_permissions_for_role(domain, role_key)` to fetch `p`-rows.
/// 3. `INSERT` into `tenant_members` / `workspace_members` (bookkeeping).
/// 4. `authz.grant_role(user_id, domain, role_key, permissions)`.
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

    Ok(())
}

/// Revokes `role_key` from `user_id` in `domain`.
///
/// Order:
/// 1. `require(actor.id, domain, "roles", "grant")`.
/// 2. `DELETE` from `tenant_members` / `workspace_members`.
/// 3. `authz.revoke_role(user_id, domain, role_key)`.
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