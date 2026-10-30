//! Role CRUD and `create_owner_role`.
//!
//! Invariant (§5 p.5):
//! - `create_role`, `update_role`, `delete_role`, `list_roles` — with
//!   `authz.require(actor.id, domain, "roles", "<action>")`.
//! - `get_role`, `get_role_by_id` — no actor (helper, called after
//!   `require` in a caller).
//! - `delete_role_by_id` — no actor (low-level `DELETE`, called by
//!   `saas::access::delete_role` after its own `require`; idempotent).
//! - `create_owner_role` — no actor (bootstrap / provisioning helper,
//!   idempotent; called after `require` in a caller).
//!
//! `roles.key` is immutable: `update_role` never changes it. Renaming is
//! `delete_role` + `create_role` (a new row). This keeps `casbin_rule`
//! `g(user, key, domain)` valid forever.

use domain::AuthUser;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{AccessError, AccessState, Permission, Role, RoleKey};

#[derive(Debug, sqlx::FromRow)]
struct RoleRow {
    id: Uuid,
    domain: String,
    key: RoleKey,
    name: String,
    description: String,
    protected: bool,
    immutable: bool,
}

impl RoleRow {
    fn into_role(self, permissions: Vec<Permission>) -> Role {
        Role {
            id: self.id,
            domain: self.domain,
            key: self.key,
            name: self.name,
            description: self.description,
            protected: self.protected,
            immutable: self.immutable,
            permissions,
        }
    }
}

/// Creates a role in `domain` with the given permissions.
///
/// Order:
/// 1. `require(actor.id, domain, "roles", "create")`.
/// 2. `INSERT roles` with `protected=false`, `immutable=false`.
/// 3. `INSERT role_permissions` for each `(resource, action)`; a missing
///    `(resource, action)` in `permissions` yields
///    [`AccessError::PermissionNotFound`].
///
/// `key` must be a valid [`RoleKey`].
pub async fn create_role(
    state: &AccessState,
    actor: &AuthUser,
    domain: &str,
    key: &RoleKey,
    name: String,
    description: String,
    permissions: &[(String, String)],
) -> Result<Role, AccessError> {
    state
        .authz()
        .require(actor.id, domain, "roles", "create")
        .await?;

    let mut tx = state.pool().begin().await?;

    let id: Uuid = sqlx::query_scalar(
        r#"
        insert into roles (domain, key, name, description)
        values ($1, $2, $3, $4)
        returning id
        "#,
    )
    .bind(domain)
    .bind(key.as_str())
    .bind(&name)
    .bind(&description)
    .fetch_one(&mut *tx)
    .await?;

    insert_role_permissions(&mut tx, id, permissions).await?;

    tx.commit().await?;

    let permissions = get_permissions_for_role_id(state.pool(), id).await?;

    Ok(Role {
        id,
        domain: domain.to_string(),
        key: key.clone(),
        name,
        description,
        protected: false,
        immutable: false,
        permissions,
    })
}

/// Updates a role's `name`, `description`, and `permissions` (never `key`).
///
/// Order:
/// 1. Load the role (its `domain` decides the `require` scope).
/// 2. `require(actor.id, role.domain, "roles", "manage")`.
/// 3. Reject `protected=true` ([`AccessError::Protected`]) and
///    `immutable=true` ([`AccessError::Immutable`]).
/// 4. `UPDATE roles` + replace `role_permissions` in one transaction.
pub async fn update_role(
    state: &AccessState,
    actor: &AuthUser,
    role_id: Uuid,
    name: String,
    description: String,
    permissions: &[(String, String)],
) -> Result<Role, AccessError> {
    let role = fetch_role(state.pool(), role_id).await?;

    state
        .authz()
        .require(actor.id, &role.domain, "roles", "manage")
        .await?;

    if role.protected {
        return Err(AccessError::Protected);
    }
    if role.immutable {
        return Err(AccessError::Immutable);
    }

    let mut tx = state.pool().begin().await?;

    sqlx::query("update roles set name = $1, description = $2 where id = $3")
        .bind(&name)
        .bind(&description)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("delete from role_permissions where role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;

    insert_role_permissions(&mut tx, role_id, permissions).await?;

    tx.commit().await?;

    let permissions = get_permissions_for_role_id(state.pool(), role_id).await?;

    Ok(Role {
        id: role.id,
        domain: role.domain,
        key: role.key,
        name,
        description,
        protected: role.protected,
        immutable: role.immutable,
        permissions,
    })
}

/// Deletes a role.
///
/// Order:
/// 1. Load the role (its `domain` decides the `require` scope).
/// 2. `require(actor.id, role.domain, "roles", "delete")`.
/// 3. Reject `protected=true` ([`AccessError::Protected`]).
/// 4. `DELETE roles` (cascades `role_permissions`).
///
/// Residual `casbin_rule` and `*_members.role` rows for the deleted
/// `role_key` remain at the `access` layer; `saas::access::delete_role`
/// handles their cleanup via [`crate::delete_role_by_id`] +
/// `authz.purge_role` + `DELETE *_members` (Stage 2d). Consumers that call
/// this function directly are responsible for that cleanup themselves.
pub async fn delete_role(
    state: &AccessState,
    actor: &AuthUser,
    role_id: Uuid,
) -> Result<(), AccessError> {
    let role = fetch_role(state.pool(), role_id).await?;

    state
        .authz()
        .require(actor.id, &role.domain, "roles", "delete")
        .await?;

    if role.protected {
        return Err(AccessError::Protected);
    }

    let result = sqlx::query("delete from roles where id = $1")
        .bind(role_id)
        .execute(state.pool())
        .await?;

    if result.rows_affected() == 0 {
        return Err(AccessError::RoleNotFound(role_id.to_string()));
    }

    Ok(())
}

/// Lists roles in `domain`.
///
/// Order:
/// 1. `require(actor.id, domain, "roles", "list")`.
/// 2. `SELECT roles WHERE domain = $1 ORDER BY key`.
/// 3. For each, load `permissions` via `role_permissions`.
pub async fn list_roles(
    state: &AccessState,
    actor: &AuthUser,
    domain: &str,
) -> Result<Vec<Role>, AccessError> {
    state
        .authz()
        .require(actor.id, domain, "roles", "list")
        .await?;

    let rows: Vec<RoleRow> = sqlx::query_as(
        r#"
        select id, domain, key, name, description, protected, immutable
        from roles
        where domain = $1
        order by key
        "#,
    )
    .bind(domain)
    .fetch_all(state.pool())
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let permissions = get_permissions_for_role_id(state.pool(), row.id).await?;
        out.push(row.into_role(permissions));
    }
    Ok(out)
}

/// Returns a role by `(domain, role_key)`, if any.
///
/// **No `actor`** (§5 p.5 exception): helper, called after `require` in a
/// caller (e.g. `saas::invitation::create_invitation` for validating
/// `invitation.role`).
pub async fn get_role(
    state: &AccessState,
    domain: &str,
    role_key: &RoleKey,
) -> Result<Option<Role>, AccessError> {
    let row: Option<RoleRow> = sqlx::query_as(
        r#"
        select id, domain, key, name, description, protected, immutable
        from roles
        where domain = $1 and key = $2
        "#,
    )
    .bind(domain)
    .bind(role_key.as_str())
    .fetch_optional(state.pool())
    .await?;

    match row {
        None => Ok(None),
        Some(row) => {
            let permissions = get_permissions_for_role_id(state.pool(), row.id).await?;
            Ok(Some(row.into_role(permissions)))
        }
    }
}

/// Returns a role by its `id`, if any.
///
/// **No `actor`** (§5 p.5 exception): helper, called after `require` in a
/// caller. Used by `saas::access::delete_role` to obtain the role's
/// `(domain, key)` before purging its Casbin rows and deleting the row.
pub async fn get_role_by_id(
    state: &AccessState,
    role_id: Uuid,
) -> Result<Option<Role>, AccessError> {
    let row: Option<RoleRow> = sqlx::query_as(
        r#"
        select id, domain, key, name, description, protected, immutable
        from roles
        where id = $1
        "#,
    )
    .bind(role_id)
    .fetch_optional(state.pool())
    .await?;

    match row {
        None => Ok(None),
        Some(row) => {
            let permissions = get_permissions_for_role_id(state.pool(), row.id).await?;
            Ok(Some(row.into_role(permissions)))
        }
    }
}

/// Low-level `DELETE` of a role row by `id`. Does not `require`, does not
/// check `protected`, does not cascade to `casbin_rule` / `*_members`.
///
/// **No `actor`** (§5 p.5 exception): called by
/// `saas::access::delete_role` after its own `require`, `protected` check,
/// `authz.purge_role`, and `DELETE *_members`. Idempotent: deleting a
/// missing row is a no-op (`Ok(())`), so the caller's sequence is retry-safe.
pub async fn delete_role_by_id(state: &AccessState, role_id: Uuid) -> Result<(), AccessError> {
    sqlx::query("delete from roles where id = $1")
        .bind(role_id)
        .execute(state.pool())
        .await?;
    Ok(())
}

/// Creates (idempotently) the `owner` role in `domain` and grants it every
/// `(resource, action)` from the `permissions` reference table.
///
/// **No `actor`** (§5 p.5 exception): called from bootstrap (`seed`, SQL
/// migration) and from `saas::platform::provision_tenant` /
/// `saas::tenant::create_workspace` after the caller's `require`.
///
/// Idempotent: concurrent callers on the same `domain` are serialized by
/// `INSERT ... ON CONFLICT (domain, key) DO NOTHING RETURNING id`; only the
/// winning insert copies permissions. The loser re-selects the existing row.
pub async fn create_owner_role(state: &AccessState, domain: &str) -> Result<Role, AccessError> {
    let key = RoleKey::parse("owner")?;

    let mut tx = state.pool().begin().await?;

    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        insert into roles (domain, key, name, description, protected, immutable)
        values ($1, 'owner', 'Owner', 'Domain owner: all permissions', true, true)
        on conflict (domain, key) do nothing
        returning id
        "#,
    )
    .bind(domain)
    .fetch_optional(&mut *tx)
    .await?;

    let id = match inserted {
        Some(id) => {
            sqlx::query(
                r#"
                insert into role_permissions (role_id, resource, action)
                select $1, resource, action from permissions
                on conflict do nothing
                "#,
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            id
        }
        None => {
            sqlx::query_scalar("select id from roles where domain = $1 and key = 'owner'")
                .bind(domain)
                .fetch_one(&mut *tx)
                .await?
        }
    };

    tx.commit().await?;

    let permissions = get_permissions_for_role_id(state.pool(), id).await?;

    Ok(Role {
        id,
        domain: domain.to_string(),
        key,
        name: "Owner".to_string(),
        description: "Domain owner: all permissions".to_string(),
        protected: true,
        immutable: true,
        permissions,
    })
}

/// Loads `permissions` for a role id (join `role_permissions` →
/// `permissions`). Shared with `permission.rs`.
pub(crate) async fn get_permissions_for_role_id(
    pool: &PgPool,
    role_id: Uuid,
) -> Result<Vec<Permission>, AccessError> {
    let rows = sqlx::query_as::<_, (String, String, String)>(
        r#"
        select p.resource, p.action, p.description
        from role_permissions rp
        join permissions p on p.resource = rp.resource and p.action = rp.action
        where rp.role_id = $1
        order by p.resource, p.action
        "#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(resource, action, description)| Permission {
            resource,
            action,
            description,
        })
        .collect())
}

async fn fetch_role(pool: &PgPool, role_id: Uuid) -> Result<Role, AccessError> {
    let row: Option<RoleRow> = sqlx::query_as(
        r#"
        select id, domain, key, name, description, protected, immutable
        from roles
        where id = $1
        "#,
    )
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let row = row.ok_or_else(|| AccessError::RoleNotFound(role_id.to_string()))?;
    let permissions = get_permissions_for_role_id(pool, row.id).await?;
    Ok(row.into_role(permissions))
}

async fn insert_role_permissions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
    permissions: &[(String, String)],
) -> Result<(), AccessError> {
    for (resource, action) in permissions {
        let exists: Option<i32> =
            sqlx::query_scalar("select 1 from permissions where resource = $1 and action = $2")
                .bind(resource)
                .bind(action)
                .fetch_optional(&mut **tx)
                .await?;
        if exists.is_none() {
            return Err(AccessError::PermissionNotFound(
                resource.clone(),
                action.clone(),
            ));
        }

        sqlx::query(
            r#"
            insert into role_permissions (role_id, resource, action)
            values ($1, $2, $3)
            on conflict do nothing
            "#,
        )
        .bind(role_id)
        .bind(resource)
        .bind(action)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}
