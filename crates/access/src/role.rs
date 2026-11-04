//! Role CRUD and `create_owner_role`.
//!
//! Invariant (§5 p.5):
//! - `create_role`, `update_role`, `delete_role`, `list_roles` — with
//!   `authz.require(actor.id, domain, "role", "<action>")`.
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
//!
//! **Stage 3e (ADR-0004, decision A):** `create_role` emits
//! `role.created`; `update_role` emits `role.updated`. Both run **after**
//! the DB transaction commits, in a separate transaction, via
//! [`AccessState::audit_or_warn`] (failure → `tracing::warn!`).
//!
//! `delete_role` (this function) does **not** emit `role.deleted`: it
//! deletes only the `roles` row, leaving orphan `casbin_rule` and
//! `*_members` rows (documented behaviour, Stage 2d). The canonical
//! `role.deleted` emission lives in `saas::access::delete_role` — the
//! 6-step cleanup path used by the UI (`saas::access::delete_role` calls
//! `access::delete_role_by_id`, which is also audit-silent).

use audit::{events, AuditEvent};
use domain::{AuthUser, Page};
use sqlx::PgPool;
use tracing::instrument;
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
/// 1. `require(actor.id, domain, "role", "create")`.
/// 2. `INSERT roles` with `protected=false`, `immutable=false`.
/// 3. `INSERT role_permissions` for each `(resource, action)`; a missing
///    `(resource, action)` in `permissions` yields
///    [`AccessError::PermissionNotFound`].
/// 4. Commit; emit `role.created` (Stage 3e; best-effort, `warn!` on
///    failure).
///
/// `key` must be a valid [`RoleKey`].
#[instrument(
    skip(state, actor, name, description, permissions),
    fields(
        operation = "create_role",
        actor_id = %actor.id,
        domain = %domain,
        key = %key.as_str(),
    ),
)]
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
        .require(actor.id, domain, "role", "create")
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

    state
        .audit_or_warn(AuditEvent {
            event_type: events::ROLE_CREATED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("role".into()),
            target_id: Some(id),
            metadata: serde_json::json!({
                "domain": domain,
                "key": key.as_str(),
                "name": name,
            }),
        })
        .await;

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
/// 2. `require(actor.id, role.domain, "role", "manage")`.
/// 3. Reject `protected=true` ([`AccessError::Protected`]) and
///    `immutable=true` ([`AccessError::Immutable`]).
/// 4. `UPDATE roles` + replace `role_permissions` in one transaction.
/// 5. Commit; emit `role.updated` (Stage 3e).
///
/// **Forensic metadata (Stage 4.5a+).** `role.updated` carries
/// `added` / `removed` — the `(resource, action)` diff vs the role's
/// previous permissions, sorted for deterministic output. Reconstruction
/// of "who had permission X on date T" joins `role.updated` (Day N) with
/// `member.role_assigned` (Day M). **No** `member.role_*` events are
/// emitted for existing holders: the *role definition* changed, not the
/// membership — emitting `member.role_assigned` for a user who already
/// held the role would be semantically false, and N events per bulk
/// `update_role` would be audit flood, not signal. The canonical path
/// for membership changes is `saas::access::{assign_role, revoke_role}`
/// and `saas::member::change_role`; `update_role` stays role-scoped.
/// (See Appendix B §2.62 — decision recorded when 4.5a shipped.)
#[instrument(
    skip(state, actor, name, description, permissions),
    fields(
        operation = "update_role",
        actor_id = %actor.id,
        role_id = %role_id,
    ),
)]
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
        .require(actor.id, &role.domain, "role", "manage")
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

    // Stage 4.5a+: diff vs the permissions the role had *before* this
    // update. Closes the forensic gap: "who had `document:read` on date T?"
    // is answerable by temporal-joining `role.updated` (Day N) with
    // `member.role_assigned` (Day M) — without replaying `casbin_rule`.
    //
    // `role.permissions` is the pre-update set (from `fetch_role` above);
    // `permissions` is the post-update set. Both sorted for deterministic
    // metadata (tests assert exact arrays).
    let old_set: std::collections::HashSet<(String, String)> = role
        .permissions
        .iter()
        .map(|p| (p.resource.clone(), p.action.clone()))
        .collect();
    let new_set: std::collections::HashSet<(String, String)> = permissions
        .iter()
        .map(|p| (p.resource.clone(), p.action.clone()))
        .collect();
    let mut added: Vec<(String, String)> = new_set.difference(&old_set).cloned().collect();
    let mut removed: Vec<(String, String)> = old_set.difference(&new_set).cloned().collect();
    added.sort();
    removed.sort();

    state
        .audit_or_warn(AuditEvent {
            event_type: events::ROLE_UPDATED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("role".into()),
            target_id: Some(role_id),
            metadata: serde_json::json!({
                "domain": role.domain,
                "key": role.key.as_str(),
                "name": name,
                "added": added,
                "removed": removed,
            }),
        })
        .await;

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
/// **DO NOT CALL DIRECTLY.** This is a **low-level** helper. It deletes
/// only the `roles` row (`role_permissions` cascades via FK) and leaves
/// orphan `casbin_rule` (`g`+`p`) and `*_members.role` rows — a partial
/// delete that the audit log then cannot represent accurately. Use
/// `saas::access::delete_role(state, actor, role_id)`, which performs the
/// canonical 6-step cleanup (`protected` check → `require` → `purge_role`
/// → `DELETE *_members` → `delete_role_by_id`) and emits `role.deleted`.
/// The only sanctioned direct caller is `saas::access::delete_role`
/// itself; tests may call this function to construct a known-broken state
/// (see `access/tests/integration.rs`).
///
/// Order:
/// 1. Load the role (its `domain` decides the `require` scope).
/// 2. `require(actor.id, role.domain, "role", "delete")`.
/// 3. Reject `protected=true` ([`AccessError::Protected`]).
/// 4. `DELETE roles` (cascades `role_permissions`).
///
/// Residual `casbin_rule` and `*_members.role` rows for the deleted
/// `role_key` remain; `saas::access::delete_role` handles their cleanup
/// via `authz.purge_role` + `DELETE *_members` + `delete_role_by_id`
/// (Stage 2d, idempotent — retry-safe).
///
/// **Stage 3e (decision A):** this function does **not** emit
/// `role.deleted`. The canonical emission point is
/// `saas::access::delete_role` — the 6-step cleanup path. Auditing here
/// would report a "delete" that leaves orphan `casbin_rule` and
/// `*_members` rows — misleading.
#[instrument(skip(state, actor), fields(operation = "delete_role", actor_id = %actor.id, role_id = %role_id))]
pub async fn delete_role(
    state: &AccessState,
    actor: &AuthUser,
    role_id: Uuid,
) -> Result<(), AccessError> {
    let role = fetch_role(state.pool(), role_id).await?;

    state
        .authz()
        .require(actor.id, &role.domain, "role", "delete")
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
/// 1. `require(actor.id, domain, "role", "list")`.
/// 2. `SELECT roles WHERE domain = $1 ORDER BY key`.
/// 3. For each, load `permissions` via `role_permissions`.
pub async fn list_roles_paged(
    state: &AccessState,
    actor: &AuthUser,
    domain: &str,
    limit: i64,
    offset: i64,
) -> Result<Page<Role>, AccessError> {
    state
        .authz()
        .require(actor.id, domain, "role", "list")
        .await?;

    let total: i64 = sqlx::query_scalar("select count(*) from roles where domain = $1")
        .bind(domain)
        .fetch_one(state.pool())
        .await?;

    let rows: Vec<RoleRow> = sqlx::query_as(
        r#"
        select id, domain, key, name, description, protected, immutable
        from roles
        where domain = $1
        order by key
        limit $2 offset $3
        "#,
    )
    .bind(domain)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.pool())
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let permissions = get_permissions_for_role_id(state.pool(), row.id).await?;
        items.push(row.into_role(permissions));
    }

    Ok(Page {
        items,
        total,
        limit,
        offset,
    })
}

#[deprecated(note = "use list_roles_paged(..., i64::MAX, 0) for 'all rows'")]
pub async fn list_roles(
    state: &AccessState,
    actor: &AuthUser,
    domain: &str,
) -> Result<Vec<Role>, AccessError> {
    Ok(list_roles_paged(state, actor, domain, i64::MAX, 0)
        .await?
        .items)
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
///
/// Audit-silent — the caller (`saas::access::delete_role`) emits
/// `role.deleted` (Stage 3e, decision A).
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
///
/// Audit-silent: `role.created` for the owner is not emitted (the event is
/// reserved for user-facing role creation; owner is a provisioning side
/// effect). See ADR-0004 §2.5.
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
