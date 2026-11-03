//! Canonical implementation of `authz::AuthorizationEngine` on top of Casbin.
//!
//! The Casbin model and the `g`/`p` matcher live here. Business code never
//! talks to Casbin directly. This crate does not know about business tables
//! (`users`, `tenants`, `roles`, `permissions`) or specific roles
//! (`owner`, `editor`); it only writes and reads `casbin_rule` rows.
//!
//! Stage 2d: the struct carries its own `PgPool` (shared with `saas`/`access`
//! via [`CasbinAuthz::from_pool`]) so that `has_role`, `count_users_with_role`,
//! and `purge_role` can query `casbin_rule` directly. `purge_role` is the only
//! method that uses raw `DELETE` instead of `MgmtApi` (mass delete by
//! `(role, domain)` is not expressible through `remove_filtered_grouping_policy`
//! without an N+1 loop); the in-memory model is reloaded via `load_policy()`
//! afterwards.
//!
//! Stage 3h (ADR-0003 §2.2): `grant_role` pre-checks `has_policy` /
//! `has_grouping_policy` before each `add_policy` / `add_grouping_policy`
//! call. `casbin-rs` 2.x `add_policy` does not deduplicate `p`-rows, so a
//! repeated `grant_role` would otherwise insert duplicates; `has_policy` is
//! an in-memory O(1) check and does not require modifying `sqlx-adapter`.
//! The unique index `casbin_rule_unique_idx` (migration
//! `20261110000001_casbin_rule_unique_idx.sql`) is a belt-and-suspenders
//! safety net on the database side.
//!
//! **Stage 4.5b — cross-process race on `grant_role`.** `has_policy` /
//! `has_grouping_policy` are in-memory; across processes two replicas can
//! both pass the pre-check and both call `add_*_policy`. The second insert
//! hits `casbin_rule_unique_idx` (PostgreSQL `23505`), which
//! `sqlx-adapter` surfaces as `casbin::Error::AdapterError(...)` — the
//! trait `AuthorizationEngine` would otherwise map that to
//! `AuthzError::Internal` and the caller would see HTTP 500 on an
//! idempotent `assign_role`. 4.5b treats the violation as an idempotent
//! success and reloads the in-memory model from `casbin_rule` so the
//! pre-check reflects reality for the next call. No `sqlx-adapter` fork
//! (ADR-0003 §3.65). The unique index is now load-bearing: it is the
//! only cross-process safety net this reference keeps.

use std::sync::Arc;

use async_trait::async_trait;
use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
use sqlx::PgPool;
use sqlx_adapter::SqlxAdapter;
use tokio::sync::RwLock;
use uuid::Uuid;

use authz::{AuthorizationEngine, AuthzError};

/// Casbin model: request `(sub, dom, obj, act)`; policy `(sub, dom, obj, act)`;
/// role `g(_, _, _)`; matcher requires both `g` and `p`.
const MODEL: &str = r#"
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"#;

type SharedEnforcer = Arc<RwLock<Enforcer>>;

#[derive(Clone)]
pub struct CasbinAuthz {
    enforcer: SharedEnforcer,
    pool: PgPool,
}

impl CasbinAuthz {
    /// Convenience constructor: opens its own `PgPool` and delegates to
    /// [`CasbinAuthz::from_pool`].
    ///
    /// Prefer [`CasbinAuthz::from_pool`] when the consumer already holds a
    /// `PgPool` (single connection pool per process — Stage 2d).
    pub async fn new(database_url: &str) -> Result<Self, AuthzError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;
        Self::from_pool(pool).await
    }

    /// Constructor over an existing pool. The same pool is used both by
    /// `SqlxAdapter` (Casbin persistence) and by the raw-SQL helpers
    /// (`has_role`, `count_users_with_role`, `purge_role`).
    pub async fn from_pool(pool: PgPool) -> Result<Self, AuthzError> {
        let adapter = SqlxAdapter::new_with_pool(pool.clone())
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;
        Self::from_adapter(adapter, pool).await
    }

    async fn from_adapter(adapter: SqlxAdapter, pool: PgPool) -> Result<Self, AuthzError> {
        let model = DefaultModel::from_str(MODEL)
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        let mut enforcer = Enforcer::new(model, adapter)
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;
        enforcer.enable_auto_save(true);

        Ok(Self {
            enforcer: Arc::new(RwLock::new(enforcer)),
            pool,
        })
    }
}

#[async_trait]
impl AuthorizationEngine for CasbinAuthz {
    async fn can(
        &self,
        user_id: Uuid,
        domain: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, AuthzError> {
        let enforcer = self.enforcer.read().await;
        enforcer
            .enforce((user_id.to_string(), domain, resource, action))
            .map_err(|e| AuthzError::Internal(e.to_string()))
    }

    async fn require(
        &self,
        user_id: Uuid,
        domain: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), AuthzError> {
        if self.can(user_id, domain, resource, action).await? {
            Ok(())
        } else {
            Err(AuthzError::Forbidden)
        }
    }

    async fn grant_role(
        &self,
        user_id: Uuid,
        domain: &str,
        role_key: &str,
        permissions: &[(String, String)],
    ) -> Result<(), AuthzError> {
        let mut enforcer = self.enforcer.write().await;

        // Stage 4.5b: if a cross-process race causes a unique violation on
        // `casbin_rule_unique_idx`, the offending row is already in the
        // database — treat it as an idempotent success and reload the
        // in-memory model *once* at the end. Without the reload, this
        // replica's in-memory enforcer would be missing the row another
        // replica wrote, and `can` / `require` would disagree with the
        // database. Multiple violations within one call coalesce into a
        // single reload.
        let mut needs_reload = false;

        // Idempotent `g`-row: skip `add_grouping_policy` when the user already
        // holds `role_key` in `domain`. `add_grouping_policy` normally
        // deduplicates, but the pre-check is cheap and makes the whole method
        // idempotent by construction (ADR-0003 §2.2).
        // `MgmtApi::has_grouping_policy` returns `bool` synchronously.
        let grouping = vec![
            user_id.to_string(),
            role_key.to_string(),
            domain.to_string(),
        ];
        if !enforcer.has_grouping_policy(grouping.clone()) {
            match enforcer.add_grouping_policy(grouping).await {
                Ok(_) => {}
                Err(e) if is_unique_violation(&e) => {
                    needs_reload = true;
                }
                Err(e) => return Err(AuthzError::Internal(e.to_string())),
            }
        }

        for (resource, action) in permissions {
            // Idempotent `p`-row: `casbin-rs` 2.x `add_policy` does not check
            // for an existing `(sub, dom, obj, act)` and would insert a
            // duplicate. `has_policy` is in-memory; no migration or adapter
            // change is needed for the pre-check itself (ADR-0003 §2.2).
            // `MgmtApi::has_policy` returns `bool` synchronously.
            let policy = vec![
                role_key.to_string(),
                domain.to_string(),
                resource.clone(),
                action.clone(),
            ];
            if enforcer.has_policy(policy.clone()) {
                continue;
            }
            match enforcer.add_policy(policy).await {
                Ok(_) => {}
                Err(e) if is_unique_violation(&e) => {
                    needs_reload = true;
                }
                Err(e) => return Err(AuthzError::Internal(e.to_string())),
            }
        }

        if needs_reload {
            // Reload under the same write-lock so concurrent `can` / `require`
            // reads see a consistent model. A cross-process race that produced
            // a violation means the row is in the database; `load_policy` pulls
            // it (and every other row we just wrote) into memory.
            enforcer
                .load_policy()
                .await
                .map_err(|e| AuthzError::Internal(e.to_string()))?;
        }

        Ok(())
    }

    async fn revoke_role(
        &self,
        user_id: Uuid,
        domain: &str,
        role_key: &str,
    ) -> Result<(), AuthzError> {
        let mut enforcer = self.enforcer.write().await;

        enforcer
            .remove_grouping_policy(vec![
                user_id.to_string(),
                role_key.to_string(),
                domain.to_string(),
            ])
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        Ok(())
    }

    async fn has_role(
        &self,
        user_id: Uuid,
        domain: &str,
        role_key: &str,
    ) -> Result<bool, AuthzError> {
        let exists: bool = sqlx::query_scalar(
            r#"
            select exists(
                select 1 from casbin_rule
                where ptype = 'g' and v0 = $1 and v1 = $2 and v2 = $3
            )
            "#,
        )
        .bind(user_id.to_string())
        .bind(role_key)
        .bind(domain)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthzError::Internal(e.to_string()))?;
        Ok(exists)
    }

    async fn count_users_with_role(&self, domain: &str, role_key: &str) -> Result<i64, AuthzError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            select count(distinct v0) from casbin_rule
            where ptype = 'g' and v1 = $1 and v2 = $2
            "#,
        )
        .bind(role_key)
        .bind(domain)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthzError::Internal(e.to_string()))?;
        Ok(count)
    }

    async fn purge_role(&self, domain: &str, role_key: &str) -> Result<u64, AuthzError> {
        let result = sqlx::query(
            r#"
            delete from casbin_rule
            where (ptype = 'g' and v1 = $1 and v2 = $2)
               or (ptype = 'p' and v0 = $1 and v1 = $2)
            "#,
        )
        .bind(role_key)
        .bind(domain)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthzError::Internal(e.to_string()))?;

        let mut enforcer = self.enforcer.write().await;
        enforcer
            .load_policy()
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

/// `true` iff `e` is (or wraps) a PostgreSQL unique violation raised by
/// `casbin_rule_unique_idx` — the constraint from migration
/// `20261110000001_casbin_rule_unique_idx.sql`.
///
/// **Why string matching.** `sqlx-adapter` does not preserve the typed
/// `sqlx::Error`; it wraps it in `casbin::Error::AdapterError(Box<dyn
/// Error + Send + Sync>)`. Downcasting would require matching on the
/// concrete `sqlx::Error::Database` variant, which is not reachable from
/// the trait surface without a `sqlx-adapter` fork (ADR-0003 §3.65). The
/// `Display` string is stable for PostgreSQL (SQLSTATE `23505`,
/// canonical `duplicate key …` phrasing) and, more importantly, the
/// constraint name `casbin_rule_unique_idx` is deterministic: our own
/// migration. If either ever changes, the test
/// `grant_role_survives_unique_violation` (integration) catches the
/// regression — the check then falls through to `AuthzError::Internal`
/// and the test fails, surfacing the breakage instead of silently
/// treating a genuine violation as success.
///
/// **What this is *not*.** Not a general "catch all errors" path — the
/// caller still gets `AuthzError::Internal` for any non-unique failure
/// (connection lost, FK violation, disk full, …). Only the specific
/// constraint is treated as "already there, reload and continue".
fn is_unique_violation(e: &casbin::Error) -> bool {
    let msg = e.to_string();
    // Most specific: constraint name from our own migration.
    if msg.contains("casbin_rule_unique_idx") {
        return true;
    }
    // Fallback: canonical PostgreSQL phrasing + the table name. Some
    // `sqlx-adapter` / `casbin` version pairs strip the constraint name
    // from the wrapped `Display`; the phrasing + table combination is
    // specific enough in practice (`casbin_rule` is only used by this
    // crate, and `duplicate key` only comes from a unique/PK violation).
    let lower = msg.to_lowercase();
    lower.contains("duplicate key") && msg.contains("casbin_rule")
}
