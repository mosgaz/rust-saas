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
//!
//! **Stage 3h (ADR-0003 §2.3):** the owner guard is serialized by a
//! PostgreSQL advisory lock. Both `change_role` and `remove_role` open a
//! short-lived transaction that does nothing but hold
//! `pg_advisory_xact_lock(hashtext('owner-guard:{domain}:{role_key}'))`.
//! The lock is held across the guard **and** the following
//! `assign`/`revoke` calls, so two concurrent admins cannot both observe
//! `count >= 2` and both revoke the last holder — the loser sees the
//! post-revoke count (`count <= 1`) and gets `Forbidden`. The transaction
//! is a lock holder only: `assign_role`/`revoke_role` still write through
//! `state.pool` and the in-memory enforcer, so this does **not** become a
//! cross-table transaction (ADR-0003 §2.1 unchanged). The
//! `*_members` vs `casbin_rule` consistency window remains the known
//! A-lite limitation (handoff §16).
//!
//! **Stage 3e (ADR-0004, decision B):** `change_role` is composable — its
//! two inner calls `saas::access::assign_role` and
//! `saas::access::revoke_role` each emit their own audit event, and
//! `change_role` itself emits a third one (`member.role_changed`). Three
//! rows total:
//! - `member.role_assigned` — from `assign_role` (target: user,
//!   `metadata: { domain, role_key: new }`).
//! - `member.role_revoked` — from `revoke_role` (target: user,
//!   `metadata: { domain, role_key: old }`).
//! - `member.role_changed` — from `change_role` itself
//!   (target: user, `metadata: { scope, from_role, to_role }`).
//!
//! `remove_role` does **not** emit `member.role_changed`; its single
//! `saas::access::revoke_role` call already emits `member.role_revoked`.
//! `member.role_changed` is specific to a role **swap**; a plain revoke
//! is not a "change".
//!
//! `change_role` with `old_role_key == new_role_key` is a no-op: no
//! `require`, no SQL, no audit event.

use std::collections::HashMap;

use ::access::RoleKey;
use audit::{events, AuditEvent};
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
/// Order (Stage 2d: flip order + owner guard; Stage 3h: advisory lock):
/// 1. No-op if `old_role_key == new_role_key`.
/// 2. `require(actor.id, scope.domain(), "members", "manage")`.
/// 3. Begin a lock-holder transaction and acquire
///    `pg_advisory_xact_lock(hashtext('owner-guard:{domain}:{old_role}'))`.
///    The transaction does no writes; it exists only to hold the advisory
///    lock across steps 4–6 (ADR-0003 §2.3).
/// 4. Guard (under the lock): if `old_role_key` is `protected`, the user
///    holds it, and the user is the last holder in the domain →
///    `CoreError::Forbidden`.
/// 5. `saas::access::assign_role(new_role_key)` — adds the new role to
///    `*_members` and `casbin_rule`; emits `member.role_assigned`.
/// 6. `saas::access::revoke_role(old_role_key)` — removes the old role
///    from `*_members` and `casbin_rule`; emits `member.role_revoked`.
/// 7. `COMMIT` the lock-holder transaction (releases the advisory lock).
/// 8. Emit `member.role_changed` (Stage 3e — this function, on top of the
///    two events already emitted by its inner calls).
///
/// Not atomic across `*_members` and `casbin_rule`: steps 5 and 6 each run
/// their own SQL. If step 6 fails after step 5 committed, the user ends up
/// over-permissioned (both roles); recoverable idempotently by retrying
/// `change_role`. Known A-lite limitation (handoff §16). The advisory
/// lock closes only the *owner guard* race, not the atomicity window.
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

    // Stage 3h: serialize the owner guard on `(domain, old_role_key)`.
    // The transaction is a lock holder only — no writes happen inside it.
    let mut lock_tx = state.pool().begin().await?;
    let lock_key = format!("owner-guard:{}:{}", domain_str, old_role_key.as_str());
    sqlx::query("select pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(&lock_key)
        .execute(&mut *lock_tx)
        .await?;

    guard_protected_last_holder(state, user_id, &domain_str, old_role_key).await?;

    saas_access::assign_role(state, actor, user_id, &domain_str, new_role_key).await?;
    saas_access::revoke_role(state, actor, user_id, &domain_str, old_role_key).await?;

    lock_tx.commit().await?;

    state
        .audit_or_warn(AuditEvent {
            event_type: events::MEMBER_ROLE_CHANGED.into(),
            actor_id: Some(actor.id),
            actor_email: Some(actor.email.clone()),
            target_type: Some("user".into()),
            target_id: Some(user_id),
            metadata: serde_json::json!({
                "scope": domain_str,
                "from_role": old_role_key.as_str(),
                "to_role": new_role_key.as_str(),
            }),
        })
        .await;

    Ok(())
}

/// Removes `role_key` from `user_id` in `scope`.
///
/// Order (Stage 2d: owner guard; Stage 3h: advisory lock):
/// 1. `require(actor.id, scope.domain(), "members", "manage")`.
/// 2. Begin a lock-holder transaction and acquire
///    `pg_advisory_xact_lock(hashtext('owner-guard:{domain}:{role}'))`
///    (ADR-0003 §2.3).
/// 3. Guard (under the lock): if `role_key` is `protected`, the user
///    holds it, and the user is the last holder in the domain →
///    `CoreError::Forbidden`.
/// 4. `saas::access::revoke_role` — removes the role from `*_members` and
///    `casbin_rule`; emits `member.role_revoked`.
/// 5. `COMMIT` the lock-holder transaction (releases the advisory lock).
///
/// Removing the last holder of a **non-protected** role is allowed. Owner
/// demote at `count >= 2` is allowed; at `count == 1` it is forbidden.
/// To transfer ownership: `assign_role` to the new owner first (`count`
/// becomes 2), then `remove_role` / `change_role` on the old owner.
///
/// Does **not** emit `member.role_changed` — this is a revoke, not a swap
/// (decision B). The audit trail already contains `member.role_revoked`
/// from the inner `revoke_role`.
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

    // Stage 3h: serialize the owner guard on `(domain, role_key)`.
    let mut lock_tx = state.pool().begin().await?;
    let lock_key = format!("owner-guard:{}:{}", domain_str, role_key.as_str());
    sqlx::query("select pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(&lock_key)
        .execute(&mut *lock_tx)
        .await?;

    guard_protected_last_holder(state, user_id, &domain_str, role_key).await?;

    saas_access::revoke_role(state, actor, user_id, &domain_str, role_key).await?;

    lock_tx.commit().await?;

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
/// from `*_members`. Stage 3h: callers (`change_role` / `remove_role`)
/// hold a `pg_advisory_xact_lock` on `owner-guard:{domain}:{role_key}` for
/// the whole guard + mutation sequence, which serializes concurrent owner
/// removals — two admins can no longer both observe `count = 2` and both
/// revoke (ADR-0003 §2.3).
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