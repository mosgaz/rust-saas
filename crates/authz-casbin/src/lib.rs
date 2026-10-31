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
            enforcer
                .add_grouping_policy(grouping)
                .await
                .map_err(|e| AuthzError::Internal(e.to_string()))?;
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
            enforcer
                .add_policy(policy)
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