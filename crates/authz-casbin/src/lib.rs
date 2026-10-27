use std::sync::Arc;

use async_trait::async_trait;
use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
use sqlx::PgPool;
use sqlx_adapter::SqlxAdapter;
use tokio::sync::RwLock;
use uuid::Uuid;

use authz::{AuthzError, AuthorizationEngine, WorkspaceRole};
use domain::{tenant_domain, workspace_domain, PLATFORM_DOMAIN};

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
}

impl CasbinAuthz {
    /// Конструктор для production: собственный пул к `database_url` (pool_size = 8).
    /// Используется в `examples/saas-leptos/src/main.rs`.
    pub async fn new(database_url: &str) -> Result<Self, AuthzError> {
        let adapter = SqlxAdapter::new(database_url, 8)
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;
        Self::from_adapter(adapter).await
    }

    /// Конструктор поверх готового пула. Нужен потребителям, у которых уже есть
    /// `PgPool` (например, `#[sqlx::test]` в integration-тестах `saas`).
    /// `casbin_rule` должна существовать в БД, к которой подключён `pool`
    /// (у нас — через `crates/db/migrations`).
    pub async fn from_pool(pool: PgPool) -> Result<Self, AuthzError> {
        let adapter = SqlxAdapter::new_with_pool(pool)
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;
        Self::from_adapter(adapter).await
    }

    async fn from_adapter(adapter: SqlxAdapter) -> Result<Self, AuthzError> {
        let model = DefaultModel::from_str(MODEL)
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        let mut enforcer = Enforcer::new(model, adapter)
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;
        enforcer.enable_auto_save(true);

        Ok(Self {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }
}

#[async_trait]
impl AuthorizationEngine for CasbinAuthz {
    async fn can(
        &self,
        user_id: Uuid,
        domain: &str,
        object: &str,
        action: &str,
    ) -> Result<bool, AuthzError> {
        let enforcer = self.enforcer.read().await;
        enforcer
            .enforce((user_id.to_string(), domain, object, action))
            .map_err(|e| AuthzError::Internal(e.to_string()))
    }

    async fn require(
        &self,
        user_id: Uuid,
        domain: &str,
        object: &str,
        action: &str,
    ) -> Result<(), AuthzError> {
        if self.can(user_id, domain, object, action).await? {
            Ok(())
        } else {
            Err(AuthzError::Forbidden)
        }
    }

    async fn grant_platform_admin(&self, user_id: Uuid) -> Result<(), AuthzError> {
        let mut enforcer = self.enforcer.write().await;

        enforcer
            .add_grouping_policy(vec![
                user_id.to_string(),
                "platform_admin".to_string(),
                PLATFORM_DOMAIN.to_string(),
            ])
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        enforcer
            .add_policy(vec![
                "platform_admin".to_string(),
                PLATFORM_DOMAIN.to_string(),
                "tenants".to_string(),
                "create".to_string(),
            ])
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        Ok(())
    }

    async fn grant_tenant_owner(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), AuthzError> {
        let mut enforcer = self.enforcer.write().await;
        let domain = tenant_domain(tenant_id);

        enforcer
            .add_grouping_policy(vec![
                user_id.to_string(),
                "tenant_owner".to_string(),
                domain.clone(),
            ])
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        enforcer
            .add_policy(vec![
                "tenant_owner".to_string(),
                domain,
                "workspaces".to_string(),
                "create".to_string(),
            ])
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        Ok(())
    }

    async fn grant_workspace_role(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        role: WorkspaceRole,
    ) -> Result<(), AuthzError> {
        let mut enforcer = self.enforcer.write().await;
        let domain = workspace_domain(workspace_id);
        let role_name = role.as_str();

        enforcer
            .add_grouping_policy(vec![
                user_id.to_string(),
                role_name.to_string(),
                domain.clone(),
            ])
            .await
            .map_err(|e| AuthzError::Internal(e.to_string()))?;

        for (object, action) in role.permissions() {
            enforcer
                .add_policy(vec![
                    role_name.to_string(),
                    domain.clone(),
                    object.to_string(),
                    action.to_string(),
                ])
                .await
                .map_err(|e| AuthzError::Internal(e.to_string()))?;
        }

        Ok(())
    }
}