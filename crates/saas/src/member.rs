//! Member listing and role changes across tenant and workspace scopes.
//!
//! Owner: `tenant_members` / `workspace_members` (bookkeeping; the
//! authoritative source of authorization is still `casbin_rule`, handoff
//! §5 p.4). `member::list` reads the bookkeeping rows; `change_role` and
//! `remove_role` update both the bookkeeping tables and `casbin_rule`
//! (the latter through `authz.grant_role` / `authz.revoke_role`, called
//! by `saas::access::{assign_role, revoke_role}`).
//!
//! Invariant (§5 p.5):
//! - `list` requires `(members, list)` in the target domain.
//! - `change_role` / `remove_role` require `(members, manage)` in the
//!   target domain, then delegate to `saas::access::{assign_role,
//!   revoke_role}`, which additionally require `(roles, grant)`. The
//!   extra check is recorded in handoff §16 (Stage 2c limitation).

use std::collections::HashMap;

use ::access::RoleKey;
use domain::{AuthUser, Member};
use sqlx::types::chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{access as saas_access, CoreError, SaasState};

/// Scope of a member listing or role change: one tenant or one workspace.
///
/// `platform` has no `*_members` table and is therefore not a member scope;
/// platform-level administration is handled by `#[server]` functions that
/// call `saas::platform::*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberScope {
    Tenant(Uuid),
    Workspace(Uuid),
}

impl MemberScope {
    /// Casbin domain string (`tenant:{id}` / `workspace:{id}`).
    pub fn domain(&self) -> String {
        match self {
            MemberScope::Tenant(id) => domain::tenant_domain(*id),
            MemberScope::Workspace(id) => domain::workspace_domain(*id),
        }
    }

    fn table(&self) -> &'static str {
        match self {
            MemberScope::Tenant(_) => "tenant_members",
            MemberScope::Workspace(_) => "workspace_members",
        }
    }

    fn scope_column(&self) -> &'static str {
        match self {
            MemberScope::Tenant(_) => "tenant_id",
            MemberScope::Workspace(_) => "workspace_id",
        }
    }

    fn scope_id(&self) -> Uuid {
        match self {
            MemberScope::Tenant(id) | MemberScope::Workspace(id) => *id,
        }
    }
}

/// Lists members of `scope`: one `Member` per `user_id`, with all
/// `role_key`s the user holds in this scope.
///
/// Order: `(members, list)` → SQL join → group by `user_id`. Rows come
/// sorted by user email; roles within one user are sorted by `role_key`.
pub async fn list(
    state: &SaasState,
    actor: &AuthUser,
    scope: MemberScope,
) -> Result<Vec<Member>, CoreError> {
    let domain_str = scope.domain();
    state
        .authz
        .require(actor.id, &domain_str, "members", "list")
        .await?;

    // Safe: `table` / `scope_column` come from a closed enum, never user
    // input. `scope_id()` is bound via `$1`.
    let sql = format!(
        r#"
        select u.id, u.email, m.role, u.created_at
        from {table} m
        join users u on u.id = m.user_id
        where m.{scope_column} = $1
        order by u.email, m.role
        "#,
        table = scope.table(),
        scope_column = scope.scope_column(),
    );

    let rows: Vec<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(&sql)
        .bind(scope.scope_id())
        .fetch_all(state.pool())
        .await?;

    let mut members: Vec<Member> = Vec::new();
    let mut index: HashMap<Uuid, usize> = HashMap::new();
    for (user_id, email, role, created_at) in rows {
        if let Some(&i) = index.get(&user_id) {
            members[i].roles.push(role);
        } else {
            index.insert(user_id, members.len());
            members.push(Member {
                user_id,
                email,
                roles: vec![role],
                created_at,
            });
        }
    }
    Ok(members)
}

/// Replaces `old_role_key` with `new_role_key` for `user_id` in `scope`.
///
/// Order:
/// 1. No-op if `old_role_key == new_role_key`.
/// 2. `require(actor.id, scope.domain(), "members", "manage")`.
/// 3. `saas::access::revoke_role` — removes the old role from
///    `*_members` and `casbin_rule`.
/// 4. `saas::access::assign_role` — adds the new role to `*_members` and
///    `casbin_rule`.
///
/// Not atomic: revoke and assign each run their own SQL. If assign fails
/// after revoke committed, the user loses the old role. Known limitation
/// (handoff §16, Stage 2d). `revoke_role` and `assign_role` each also
/// check `(roles, grant)`, so `change_role` performs three `require`
/// calls total; also a §16 limitation.
pub async fn change_role(
    state: &SaasState,
    actor: &AuthUser,
    scope: MemberScope,
    user_id: Uuid,
    old_role_key: &RoleKey,
    new_role_key: &RoleKey,
) -> Result<(), CoreError> {
    if old_role_key == new_role_key {
        return Ok(());
    }

    let domain_str = scope.domain();
    state
        .authz
        .require(actor.id, &domain_str, "members", "manage")
        .await?;

    saas_access::revoke_role(state, actor, user_id, &domain_str, old_role_key).await?;
    saas_access::assign_role(state, actor, user_id, &domain_str, new_role_key).await?;

    Ok(())
}

/// Removes `role_key` from `user_id` in `scope`.
///
/// Order:
/// 1. `require(actor.id, scope.domain(), "members", "manage")`.
/// 2. `saas::access::revoke_role` — removes the role from `*_members` and
///    `casbin_rule`.
///
/// Removing the last role from a member is allowed; recovery requires
/// re-invitation or a manual `assign_role`. Known limitation (handoff
/// §16).
pub async fn remove_role(
    state: &SaasState,
    actor: &AuthUser,
    scope: MemberScope,
    user_id: Uuid,
    role_key: &RoleKey,
) -> Result<(), CoreError> {
    let domain_str = scope.domain();
    state
        .authz
        .require(actor.id, &domain_str, "members", "manage")
        .await?;

    saas_access::revoke_role(state, actor, user_id, &domain_str, role_key).await?;
    Ok(())
}
