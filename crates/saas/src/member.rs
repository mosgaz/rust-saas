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
//!   extra check is recorded in handoff §16.
//!
//! Stage 2d:
//! - `change_role` performs `assign(new)` before `revoke(old)`. A partial
//!   failure leaves the user over-permissioned (both roles), recoverable
//!   idempotently by calling `change_role` again; the previous order
//!   (`revoke` then `assign`) could leave the user under-permissioned
//!   (both roles lost), which is not idempotently recoverable.
//! - `change_role` / `remove_role` guard against emptying a `protected`
//!   role: if the target role is `protected`, the user holds it, and the
//!   user is the last holder in the domain, the call returns
//!   `CoreError::Forbidden`. Non-protected roles have no last-holder guard.
//! - The guard is non-transactional (a concurrent admin can race between
//!   `count_users_with_role` and `revoke`). See handoff §16.

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
/// Order (Stage 2d: flip order + owner guard):
/// 1. No-op if `old_role_key == new_role_key`.
/// 2. `require(actor.id, scope.domain(), "members", "manage")`.
/// 3. Guard: if `old_role_key` is `protected`, the user holds it, and the
///    user is the last holder in the domain → `CoreError::Forbidden`.
/// 4. `saas::access::assign_role(new_role_key)` — adds the new role to
///    `*_members` and `casbin_rule`.
/// 5. `saas::access::revoke_role(old_role_key)` — removes the old role from
///    `*_members` and `casbin_rule`.
///
/// Not atomic: steps 4 and 5 each run their own SQL. If step 5 fails after
/// step 4 committed, the user ends up over-permissioned (both roles); this
/// is recoverable idempotently by calling `change_role` again (the previous
/// `revoke` → `assign` order was not). Known limitation (handoff §16).
/// `assign_role` and `revoke_role` each also check `(roles, grant)`, so
/// `change_role` performs three `require` calls total; also a §16
/// limitation.
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

    guard_protected_last_holder(state, user_id, &domain_str, old_role_key).await?;

    saas_access::assign_role(state, actor, user_id, &domain_str, new_role_key).await?;
    saas_access::revoke_role(state, actor, user_id, &domain_str, old_role_key).await?;

    Ok(())
}

/// Removes `role_key` from `user_id` in `scope`.
///
/// Order (Stage 2d: owner guard):
/// 1. `require(actor.id, scope.domain(), "members", "manage")`.
/// 2. Guard: if `role_key` is `protected`, the user holds it, and the user
///    is the last holder in the domain → `CoreError::Forbidden`.
/// 3. `saas::access::revoke_role` — removes the role from `*_members` and
///    `casbin_rule`.
///
/// Removing the last holder of a **non-protected** role is allowed. Owner
/// demote at `count >= 2` is allowed; at `count == 1` it is forbidden
/// (handoff §16). To transfer ownership: `assign_role` to the new owner
/// first (`count` becomes 2), then `remove_role`/`change_role` on the old
/// owner.
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

    guard_protected_last_holder(state, user_id, &domain_str, role_key).await?;

    saas_access::revoke_role(state, actor, user_id, &domain_str, role_key).await?;
    Ok(())
}

/// Rejects removing a `protected` role from the last user who holds it in
/// `domain`.
///
/// Guard condition (all three must hold to reject):
/// 1. `role.protected == true` (role is marked as `protected` in `access`;
///    currently only `owner`, but the guard does not hardcode the key).
/// 2. `authz.has_role(user_id, domain, role_key) == true` (user actually
///    holds the role; removing a role the user does not have is a no-op,
///    not an error).
/// 3. `authz.count_users_with_role(domain, role_key) <= 1` (user is the
///    last holder).
///
/// Reads `count` from `casbin_rule` (source of truth, handoff §5 p.4), not
/// from `*_members`. Non-transactional: a concurrent admin can race between
/// `count` and the caller's `revoke` (handoff §16).
async fn guard_protected_last_holder(
    state: &SaasState,
    user_id: Uuid,
    domain: &str,
    role_key: &RoleKey,
) -> Result<(), CoreError> {
    let Some(role) = ::access::get_role(state.access(), domain, role_key)
        .await
        .map_err(CoreError::from)?
    else {
        return Ok(());
    };

    if !role.protected {
        return Ok(());
    }

    let has = state
        .authz()
        .has_role(user_id, domain, role_key.as_str())
        .await?;
    if !has {
        return Ok(());
    }

    let count = state
        .authz()
        .count_users_with_role(domain, role_key.as_str())
        .await?;
    if count <= 1 {
        return Err(CoreError::Forbidden);
    }

    Ok(())
}
