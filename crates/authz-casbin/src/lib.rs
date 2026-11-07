//! Canonical implementation of `authz::AuthorizationEngine` on top of Casbin.
//!
//! The Casbin model and the `g`/`p` matcher live here. Business code never
//! talks to Casbin directly. This crate does not know about business tables
//! (`users`, `tenants`, `roles`, `permissions`) or specific roles
//! (`owner`, `editor`); it only writes and reads `casbin_rule` rows.
//!
//! Phase B (ADR-0010): [`CasbinAuthz::can_request`] layers ABAC constraints
//! on top of the RBAC decision. Constraints are passed by the caller via
//! `AuthzRequest.context.constraints`; the RBAC base decision is
//! `can(subject.id, domain, resource.kind, action)`. This keeps the policy
//! store (Casbin) untouched — no `cond` column, no `eval()`-Rego, no
//! migration. ABAC rules are developer-defined (in controller / binding
//! code), which matches `rust-saas`'s "roles are data, ABAC rules are code"
//! split.

use std::sync::Arc;

use async_trait::async_trait;
use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
use serde_json::Value;
use sqlx::PgPool;
use sqlx_adapter::SqlxAdapter;
use tokio::sync::RwLock;
use uuid::Uuid;

use authz::{AuthorizationEngine, AuthzError, AuthzRequest};

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
        let mut needs_reload = false;

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

    async fn reload_in_memory(&self) -> Result<(), AuthzError> {
        let mut enforcer = self.enforcer.write().await;
        enforcer
            .load_policy()
            .await
            .map_err(|e| AuthzError::ReloadError(e.to_string()))?;
        Ok(())
    }

    /// Phase B (ADR-0010): RBAC + ABAC constraints.
    ///
    /// 1. RBAC base decision via [`Self::can`]. If denied → `Ok(false)`.
    /// 2. If `req.context.constraints` is an array, every constraint must
    ///    pass (AND semantics). If `constraints` is present but not an
    ///    array → `Ok(false)` (fail-closed on malformed input).
    /// 3. Unknown `type` → `Ok(false)` (fail-closed).
    ///
    /// # Constraints schema
    ///
    /// ```json
    /// {
    ///   "constraints": [
    ///     { "type": "owner_only" },
    ///     { "type": "status_in", "values": ["published", "active"] },
    ///     { "type": "attr_eq", "path": "status", "value": "published" },
    ///     { "type": "attr_in_subject", "attr": "department" }
    ///   ]
    /// }
    /// ```
    ///
    /// - `owner_only` — `resource.attrs.owner_id == subject.id`.
    /// - `status_in` — `resource.attrs.status ∈ values`.
    /// - `attr_eq` — `resource.attrs[path] == value`.
    /// - `attr_in_subject` — `resource.attrs[attr] == subject.attrs[attr]`.
    async fn can_request(&self, req: &AuthzRequest) -> Result<bool, AuthzError> {
        if !self
            .can(req.subject.id, &req.domain, &req.resource.kind, &req.action)
            .await?
        {
            return Ok(false);
        }

        match req.context.get("constraints") {
            None | Some(Value::Null) => Ok(true),
            Some(value) => match value.as_array() {
                Some(list) => {
                    for c in list {
                        if !evaluate_constraint(c, req) {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                None => Ok(false),
            },
        }
    }
}

/// Evaluate one ABAC constraint against `req`.
///
/// Pure function — no DB, no async. Unknown `type` → `false` (fail-closed).
fn evaluate_constraint(c: &Value, req: &AuthzRequest) -> bool {
    let kind = match c.get("type").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };
    match kind {
        "owner_only" => {
            let owner = req.resource.attrs.get("owner_id").and_then(|v| v.as_str());
            owner == Some(req.subject.id.to_string().as_str())
        }
        "status_in" => {
            let allowed = c.get("values").and_then(|v| v.as_array());
            let current = req.resource.attrs.get("status").and_then(|v| v.as_str());
            match (allowed, current) {
                (Some(list), Some(s)) => list.iter().any(|v| v.as_str() == Some(s)),
                _ => false,
            }
        }
        "attr_eq" => {
            let path = match c.get("path").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return false,
            };
            let expected = c.get("value");
            let actual = req.resource.attrs.get(path);
            match (expected, actual) {
                (Some(e), Some(a)) => e == a,
                _ => false,
            }
        }
        "attr_in_subject" => {
            let attr = match c.get("attr").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return false,
            };
            let res = req.resource.attrs.get(attr);
            let sub = req.subject.attrs.get(attr);
            match (res, sub) {
                (Some(r), Some(s)) => r == s,
                _ => false,
            }
        }
        _ => false,
    }
}

/// `true` iff `e` is (or wraps) a PostgreSQL unique violation raised by
/// `casbin_rule_unique_idx` (ADR-0003 §3.65, Stage 4.5b).
fn is_unique_violation(e: &casbin::Error) -> bool {
    let msg = e.to_string();
    if msg.contains("casbin_rule_unique_idx") {
        return true;
    }
    let lower = msg.to_lowercase();
    lower.contains("duplicate key") && msg.contains("casbin_rule")
}

#[cfg(test)]
mod abac_tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::evaluate_constraint;
    use authz::{AuthzRequest, Resource, Subject};

    fn req_with(
        attrs: serde_json::Value,
        sub_attrs: serde_json::Value,
        sub_id: Uuid,
    ) -> AuthzRequest {
        AuthzRequest {
            domain: "workspace:00000000-0000-0000-0000-000000000001".into(),
            subject: Subject {
                id: sub_id,
                roles: vec!["editor".into()],
                attrs: sub_attrs,
            },
            resource: Resource {
                kind: "document".into(),
                id: Some(Uuid::nil()),
                attrs,
            },
            action: "read".into(),
            context: serde_json::Value::Null,
        }
    }

    #[test]
    fn owner_only_allows_owner() {
        let sub = Uuid::new_v4();
        let req = req_with(json!({"owner_id": sub.to_string()}), json!({}), sub);
        assert!(evaluate_constraint(&json!({"type": "owner_only"}), &req));
    }

    #[test]
    fn owner_only_rejects_non_owner() {
        let sub = Uuid::new_v4();
        let other = Uuid::new_v4();
        let req = req_with(json!({"owner_id": other.to_string()}), json!({}), sub);
        assert!(!evaluate_constraint(&json!({"type": "owner_only"}), &req));
    }

    #[test]
    fn status_in_allows_listed() {
        let req = req_with(json!({"status": "published"}), json!({}), Uuid::nil());
        assert!(evaluate_constraint(
            &json!({"type": "status_in", "values": ["published", "active"]}),
            &req
        ));
    }

    #[test]
    fn status_in_rejects_unlisted() {
        let req = req_with(json!({"status": "archived"}), json!({}), Uuid::nil());
        assert!(!evaluate_constraint(
            &json!({"type": "status_in", "values": ["published"]}),
            &req
        ));
    }

    #[test]
    fn attr_eq_matches() {
        let req = req_with(json!({"status": "draft"}), json!({}), Uuid::nil());
        assert!(evaluate_constraint(
            &json!({"type": "attr_eq", "path": "status", "value": "draft"}),
            &req
        ));
    }

    #[test]
    fn attr_in_subject_matches() {
        let req = req_with(
            json!({"department": "engineering"}),
            json!({"department": "engineering"}),
            Uuid::nil(),
        );
        assert!(evaluate_constraint(
            &json!({"type": "attr_in_subject", "attr": "department"}),
            &req
        ));
    }

    #[test]
    fn attr_in_subject_rejects_mismatch() {
        let req = req_with(
            json!({"department": "engineering"}),
            json!({"department": "sales"}),
            Uuid::nil(),
        );
        assert!(!evaluate_constraint(
            &json!({"type": "attr_in_subject", "attr": "department"}),
            &req
        ));
    }

    #[test]
    fn unknown_type_fails_closed() {
        let req = req_with(json!({}), json!({}), Uuid::nil());
        assert!(!evaluate_constraint(&json!({"type": "unknown"}), &req));
        assert!(!evaluate_constraint(&json!({}), &req));
    }
}
