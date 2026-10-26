use std::sync::Arc;

use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
use sqlx_adapter::SqlxAdapter;
use tokio::sync::RwLock;
use uuid::Uuid;

use domain::{tenant_domain, workspace_domain, PLATFORM_DOMAIN};

pub const MODEL: &str = r#"
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
pub struct Authz {
    enforcer: SharedEnforcer,
}

impl Authz {
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        let model = DefaultModel::from_str(MODEL).await?;
        let adapter = SqlxAdapter::new(database_url, 8).await?;

        let mut enforcer = Enforcer::new(model, adapter).await?;
        enforcer.enable_auto_save(true);

        let enforcer = Arc::new(RwLock::new(enforcer));

        Ok(Self { enforcer })
    }

    pub async fn can(
        &self,
        user_id: Uuid,
        domain: &str,
        object: &str,
        action: &str,
    ) -> anyhow::Result<bool> {
        let enforcer = self.enforcer.read().await;

        Ok(enforcer.enforce((user_id.to_string(), domain, object, action))?)
    }

    pub async fn require(
        &self,
        user_id: Uuid,
        domain: &str,
        object: &str,
        action: &str,
    ) -> anyhow::Result<()> {
        if self.can(user_id, domain, object, action).await? {
            Ok(())
        } else {
            anyhow::bail!("forbidden")
        }
    }

    pub async fn grant_platform_admin(&self, user_id: Uuid) -> anyhow::Result<()> {
        let mut enforcer = self.enforcer.write().await;

        enforcer
            .add_grouping_policy(vec![
                user_id.to_string(),
                "platform_admin".to_string(),
                PLATFORM_DOMAIN.to_string(),
            ])
            .await?;

        // ВАЖНО: без p-политики enforce() всегда false, т.к. matcher требует
        // совпадения с p.sub, p.dom, p.obj, p.act. Раньше добавлялся только g,
        // поэтому create_tenant всегда возвращал "forbidden".
        enforcer
            .add_policy(vec![
                "platform_admin".to_string(),
                PLATFORM_DOMAIN.to_string(),
                "tenants".to_string(),
                "create".to_string(),
            ])
            .await?;

        Ok(())
    }

    pub async fn grant_tenant_owner(&self, user_id: Uuid, tenant_id: Uuid) -> anyhow::Result<()> {
        let mut enforcer = self.enforcer.write().await;
        let domain = tenant_domain(tenant_id);

        enforcer
            .add_grouping_policy(vec![
                user_id.to_string(),
                "tenant_owner".to_string(),
                domain.clone(),
            ])
            .await?;

        enforcer
            .add_policy(vec![
                "tenant_owner".to_string(),
                domain,
                "workspaces".to_string(),
                "create".to_string(),
            ])
            .await?;

        Ok(())
    }

    pub async fn grant_workspace_role(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        role: WorkspaceRole,
    ) -> anyhow::Result<()> {
        let mut enforcer = self.enforcer.write().await;
        let domain = workspace_domain(workspace_id);
        let role_name = role.as_str();

        enforcer
            .add_grouping_policy(vec![
                user_id.to_string(),
                role_name.to_string(),
                domain.clone(),
            ])
            .await?;

        for (object, action) in role.permissions() {
            enforcer
                .add_policy(vec![
                    role_name.to_string(),
                    domain.clone(),
                    object.to_string(),
                    action.to_string(),
                ])
                .await?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WorkspaceRole {
    Admin,
    Editor,
    Viewer,
}

impl WorkspaceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "workspace_admin",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
        }
    }

    pub fn permissions(self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Admin => vec![
                ("documents", "read"),
                ("documents", "write"),
                ("members", "manage"),
            ],
            Self::Editor => vec![("documents", "read"), ("documents", "write")],
            Self::Viewer => vec![("documents", "read")],
        }
    }
}