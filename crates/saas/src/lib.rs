//! Бизнес-логика SaaS: platform, tenant, workspace, документы.
//!
//! Крейт не знает о Leptos, Axum, конкретных HTTP handlers, `casbin::Enforcer`,
//! JWT и Argon2. Авторизация — через `authz::AuthorizationEngine`;
//! actor — `domain::AuthUser` (приходит от `authn` в `app`).

use std::sync::Arc;

use authz::{AuthzError, AuthorizationEngine};
use domain::{AuthUser, Document, Tenant, Workspace, PLATFORM_DOMAIN};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("validation error: {0}")]
    Validation(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl From<AuthzError> for CoreError {
    fn from(e: AuthzError) -> Self {
        match e {
            AuthzError::Forbidden => CoreError::Forbidden,
            AuthzError::Internal(s) => CoreError::Internal(s),
        }
    }
}

#[derive(Clone)]
pub struct SaasState {
    pool: PgPool,
    authz: Arc<dyn AuthorizationEngine>,
}

impl SaasState {
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn authz(&self) -> &Arc<dyn AuthorizationEngine> {
        &self.authz
    }
}

pub struct SaasBuilder {
    pool: PgPool,
    authz: Option<Arc<dyn AuthorizationEngine>>,
}

impl SaasBuilder {
    pub fn new(pool: PgPool) -> Self {
        Self { pool, authz: None }
    }

    pub fn with_authz(mut self, authz: Arc<dyn AuthorizationEngine>) -> Self {
        self.authz = Some(authz);
        self
    }

    pub fn build(self) -> Result<SaasState, CoreError> {
        let authz = self
            .authz
            .ok_or_else(|| CoreError::Internal("SaasBuilder: authorization engine is required".into()))?;
        Ok(SaasState {
            pool: self.pool,
            authz,
        })
    }
}

pub mod platform {
    use super::*;

    pub async fn create_tenant(
        state: &SaasState,
        actor: &AuthUser,
        name: String,
    ) -> Result<Tenant, CoreError> {
        state
            .authz
            .require(actor.id, PLATFORM_DOMAIN, "tenants", "create")
            .await?;

        let tenant = sqlx::query_as::<_, Tenant>(
            "insert into tenants (name) values ($1) returning id, name, status, created_at",
        )
        .bind(name)
        .fetch_one(&state.pool)
        .await?;

        Ok(tenant)
    }
}

pub mod tenant {
    use super::*;

    pub async fn create_workspace(
        state: &SaasState,
        actor: &AuthUser,
        tenant_id: Uuid,
        name: String,
    ) -> Result<Workspace, CoreError> {
        let domain_str = domain::tenant_domain(tenant_id);

        state
            .authz
            .require(actor.id, &domain_str, "workspaces", "create")
            .await?;

        let workspace = sqlx::query_as::<_, Workspace>(
            r#"
            insert into workspaces (tenant_id, name)
            values ($1, $2)
            returning id, tenant_id, name, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_one(&state.pool)
        .await?;

        Ok(workspace)
    }
}

pub mod workspace {
    use super::*;

    pub async fn create_document(
        state: &SaasState,
        actor: &AuthUser,
        workspace_id: Uuid,
        title: String,
    ) -> Result<Document, CoreError> {
        let domain_str = domain::workspace_domain(workspace_id);

        state
            .authz
            .require(actor.id, &domain_str, "documents", "write")
            .await?;

        let document = sqlx::query_as::<_, Document>(
            r#"
            insert into documents (workspace_id, title)
            values ($1, $2)
            returning id, workspace_id, title, body, created_at
            "#,
        )
        .bind(workspace_id)
        .bind(title)
        .fetch_one(&state.pool)
        .await?;

        Ok(document)
    }

    pub async fn list_documents(
        state: &SaasState,
        actor: &AuthUser,
        workspace_id: Uuid,
    ) -> Result<Vec<Document>, CoreError> {
        let domain_str = domain::workspace_domain(workspace_id);

        state
            .authz
            .require(actor.id, &domain_str, "documents", "read")
            .await?;

        let documents = sqlx::query_as::<_, Document>(
            r#"
            select id, workspace_id, title, body, created_at
            from documents
            where workspace_id = $1
            order by created_at desc
            "#,
        )
        .bind(workspace_id)
        .fetch_all(&state.pool)
        .await?;

        Ok(documents)
    }
}