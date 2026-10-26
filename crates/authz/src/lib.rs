//! Абстракция авторизации: трейт `AuthorizationEngine` и типы ошибок.
//!
//! Крейт не знает о Casbin, SQL, HTTP, Leptos или JWT. Конкретная реализация
//! (например, `authz-casbin`) подключается отдельно и передаётся бизнес-коду
//! как `Arc<dyn AuthorizationEngine>`.

use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("forbidden")]
    Forbidden,
    #[error("internal authorization error: {0}")]
    Internal(String),
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

#[async_trait::async_trait]
pub trait AuthorizationEngine: Send + Sync {
    async fn can(
        &self,
        user_id: Uuid,
        domain: &str,
        object: &str,
        action: &str,
    ) -> Result<bool, AuthzError>;

    async fn require(
        &self,
        user_id: Uuid,
        domain: &str,
        object: &str,
        action: &str,
    ) -> Result<(), AuthzError>;

    async fn grant_platform_admin(&self, user_id: Uuid) -> Result<(), AuthzError>;

    async fn grant_tenant_owner(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), AuthzError>;

    async fn grant_workspace_role(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        role: WorkspaceRole,
    ) -> Result<(), AuthzError>;
}