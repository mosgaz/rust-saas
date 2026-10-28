//! Authorization abstraction: the `AuthorizationEngine` trait and error types.
//!
//! This crate is trait-only: no Casbin, no SQL, no HTTP, no Leptos, no JWT.
//! A concrete implementation (for example `authz-casbin`) is plugged in
//! separately and passed to business code as `Arc<dyn AuthorizationEngine>`.

use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("forbidden")]
    Forbidden,
    #[error("internal authorization error: {0}")]
    Internal(String),
}

/// A workspace-scoped role.
///
/// `permissions()` is the **source of truth for Casbin policies**:
/// `authz-casbin::grant_workspace_role` iterates over it and writes one
/// `p`-row per `(object, action)`. It is not a UI list.
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
                ("invitations", "create"),
                ("invitations", "revoke"),
                ("invitations", "list"),
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