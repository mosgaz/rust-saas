//! Role and permission wrappers over the `access` crate.
//!
//! Invariant (§5 p.5): every mutation service calls
//! `authz.require(actor.id, domain, "role", "<action>")` first.
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
use domain::{AuthUser, Page};
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

/// Updates a role **and** resynchronises `casbin_rule` for every current
/// holder of the role.
///
/// `access::update_role` rewrites `roles` + `role_permissions` (and emits
/// `role.updated` with an `added` / `removed` permission diff), but it
/// does **not** touch `casbin_rule.p`: the source of truth for
/// authorization. Without resync, a removed permission keeps working for
/// existing holders, and an added permission does not apply to them
/// (real security bug — `saas-pluggability-04 §4.21`).
///
/// Order (Stage 4.5a):
/// 1. Snapshot holders: `SELECT DISTINCT v0 FROM casbin_rule
///    WHERE ptype='g' AND v1=$key AND v2=$domain`. Taken **before** the
///    update — a later change cannot invent a holder who was not already
///    there, and this is the same set `access::update_role`'s metadata
///    diff describes.
/// 2. `access::update_role` — rewrites `roles` + `role_permissions`,
///    returns the role with the **new** permission set.
/// 3. `authz.purge_role(domain, key)` — removes every `p`-row for the
///    role in this domain (and any orphan `g`-row, idempotent).
/// 4. For each holder: `authz.grant_role(holder, domain, key,
///    role.permissions)` — writes the `g`-row back and one `p`-row per
///    new permission. `grant_role` is idempotent on `p`-rows
///    (`has_policy` pre-check, Stage 3h).
///
/// **No `member.role_*` for holders.** The *role definition* changed, not
/// the membership — `member.role_assigned` for a user who already held
/// the role would be semantically false, and N events per bulk
/// `update_role` would be audit flood, not signal. The `role.updated`
/// event (emitted by `access::update_role`) carries the
/// `added` / `removed` diff; forensic reconstruction is a temporal join
/// with `member.role_assigned` / `member.role_revoked`. See Appendix B
/// §2.62.
///
/// **Not atomic across `role_permissions` and `casbin_rule`.** Same A-lite
/// window as `delete_role` (ADR-0003 §2.1): step 2 commits, step 4 is a
/// separate set of writes via the in-memory enforcer. A failure between
/// them leaves holders with the *old* effective permissions until a retry
/// of `update_role` re-runs step 3–4 idempotently. This is the known
/// `*_members` / `role_permissions` vs `casbin_rule` consistency window,
/// unchanged.
///
/// **`platform` domain** has no `*_members` table, but it can still have
/// holders (`seed` grants `platform` owner via `authz.grant_role`
/// directly). The `SELECT DISTINCT v0` picks them up regardless of scope —
/// no `parse_domain` filter is needed or applied.
pub async fn update_role(
    state: &SaasState,
    actor: &AuthUser,
    role_id: Uuid,
    name: String,
    description: String,
    permissions: &[(String, String)],
) -> Result<Role, CoreError> {
    // Load the role once to learn `(domain, key)` *before* the update.
    // `access::update_role` fetches its own copy internally; this load is
    // for the holder snapshot and the domain-scoped `purge_role` /
    // `grant_role` calls that follow. A `NotFound` here matches what
    // `access::update_role` would return — no behavioural difference, just
    // an earlier error.
    let existing = ::access::get_role_by_id(state.access(), role_id)
        .await
        .map_err(CoreError::from)?
        .ok_or(CoreError::NotFound)?;

    // 1. Snapshot current holders of `(domain, key)` from `casbin_rule`.
    //    `casbin_rule.v0` is `user_id::text`; parse after fetch so a
    //    malformed row (should not exist) fails loudly rather than silently
    //    skipping a holder.
    let holder_rows: Vec<String> = sqlx::query_scalar(
        r#"
        select distinct v0
        from casbin_rule
        where ptype = 'g' and v1 = $1 and v2 = $2
        "#,
    )
    .bind(existing.key.as_str())
    .bind(&existing.domain)
    .fetch_all(state.pool())
    .await?;

    let mut holders: Vec<Uuid> = Vec::with_capacity(holder_rows.len());
    for raw in holder_rows {
        let id = Uuid::parse_str(&raw).map_err(|e| {
            CoreError::Internal(format!(
                "casbin_rule g-row v0 is not a UUID (domain={}, role={}): {e}",
                existing.domain,
                existing.key.as_str()
            ))
        })?;
        holders.push(id);
    }

    // 2. Update `roles` + `role_permissions`; `role.updated` fires inside
    //    `access::update_role` (with the `added` / `removed` diff).
    let updated = ::access::update_role(
        state.access(),
        actor,
        role_id,
        name,
        description,
        permissions,
    )
    .await
    .map_err(CoreError::from)?;

    // 3. Purge the role's `p`-rows (and any leftover `g`-row) so stale
    //    permissions cannot survive the rewrite.
    state
        .authz()
        .purge_role(&updated.domain, updated.key.as_str())
        .await?;

    // 4. Re-grant to every holder with the new permission set.
    //    `updated.permissions` is `Vec<Permission>`; `grant_role` wants
    //    `&[(String, String)]`.
    let new_permissions: Vec<(String, String)> = updated
        .permissions
        .iter()
        .map(|p| (p.resource.clone(), p.action.clone()))
        .collect();
    for holder in holders {
        state
            .authz()
            .grant_role(
                holder,
                &updated.domain,
                updated.key.as_str(),
                &new_permissions,
            )
            .await?;
    }

    Ok(updated)
}

/// Deletes a role and cleans up its residuals.
///
/// Order:
/// 1. `access::get_role_by_id(role_id)` — obtain `domain`, `key`,
///    `protected` (no `actor`, §5 p.5).
/// 2. Reject `protected=true` ([`CoreError::Forbidden`]).
/// 3. `require(actor.id, role.domain, "role", "delete")`.
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
        .require(actor.id, &role.domain, "role", "delete")
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

/// Lists roles in `domain`. Delegates to `access::list_roles_paged`.
pub async fn list_roles_paged(
    state: &SaasState,
    actor: &AuthUser,
    domain: &str,
    limit: i64,
    offset: i64,
) -> Result<Page<Role>, CoreError> {
    ::access::list_roles_paged(state.access(), actor, domain, limit, offset)
        .await
        .map_err(Into::into)
}

/// Lists roles in `domain`. Delegates to `access::list_roles`.
#[deprecated(note = "use list_roles_paged(..., i64::MAX, 0) for 'all rows'")]
pub async fn list_roles(
    state: &SaasState,
    actor: &AuthUser,
    domain: &str,
) -> Result<Vec<Role>, CoreError> {
    Ok(list_roles_paged(state, actor, domain, i64::MAX, 0)
        .await?
        .items)
}

/// Lists all permissions in the reference table. Delegates to
/// `access::list_permissions_paged`.
pub async fn list_permissions_paged(
    state: &SaasState,
    limit: i64,
    offset: i64,
) -> Result<Page<Permission>, CoreError> {
    ::access::list_permissions_paged(state.access(), limit, offset)
        .await
        .map_err(Into::into)
}

/// Lists all permissions in the reference table. Delegates to
/// `access::list_permissions`.
#[deprecated(note = "use list_permissions_paged(..., i64::MAX, 0) for 'all rows'")]
pub async fn list_permissions(state: &SaasState) -> Result<Vec<Permission>, CoreError> {
    Ok(list_permissions_paged(state, i64::MAX, 0).await?.items)
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
    let reference = ::access::list_permissions_paged(state.access(), i64::MAX, 0)
        .await
        .map_err(CoreError::from)?
        .items;

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
/// 1. `require(actor.id, domain, "role", "grant")`.
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
        .require(actor.id, domain, "role", "grant")
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
/// 1. `require(actor.id, domain, "role", "grant")`.
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
        .require(actor.id, domain, "role", "grant")
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
