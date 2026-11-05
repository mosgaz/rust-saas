//! 7 handlers ported from `src/{tenant,workspace,audit}.rs` (Stage 5.0-A6).
//!
//! `State<Arc<AppState>>` -> `State<Arc<AxumAppState>>`,
//! `crate::error::AppError` -> `rust_saas::AppError`,
//! `crate::extract::CurrentUser` -> `rust_saas::CurrentUser`,
//! `crate::pagination::PaginationQuery` -> local 15 lines (not re-exported).

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use rust_saas::access::RoleKey;
use rust_saas::audit_pg::PgAuditLogger;
use rust_saas::domain::{self, AuthUser, Page};
use rust_saas::saas::{access as saas_access, platform, tenant, workspace, CoreError};
use rust_saas::{AppError, AxumAppState, CurrentUser};
use serde::Deserialize;
use uuid::Uuid;

// Pagination (local; `saas-axum` does not re-export)

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl PaginationQuery {
    pub fn clamp(&self) -> (i64, i64) {
        let limit = self.limit.unwrap_or(50).clamp(1, 200);
        let offset = self.offset.unwrap_or(0).max(0);
        (limit, offset)
    }
}

// GET /tenants

pub async fn list_my_tenants(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Query(q): Query<PaginationQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let items = tenant::list_memberships(&state.saas, &user).await?;
    let (limit, offset) = q.clamp();
    let total = items.len() as i64;
    let items: Vec<_> = items
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    Ok(Json(Page {
        items,
        total,
        limit,
        offset,
    }))
}

// POST /tenants

#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
}

pub async fn create_tenant(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Json(body): Json<CreateTenantRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let owner_key = RoleKey::parse("owner").map_err(AppError::Access)?;
    let t = platform::provision_tenant(&state.saas, &user, body.name, &user, &owner_key).await?;
    Ok(Json(t))
}

// GET /workspaces

pub async fn list_my_workspaces(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Query(q): Query<PaginationQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let items = workspace::list_memberships(&state.saas, &user).await?;
    let (limit, offset) = q.clamp();
    let total = items.len() as i64;
    let items: Vec<_> = items
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    Ok(Json(Page {
        items,
        total,
        limit,
        offset,
    }))
}

// POST /workspaces

#[derive(Debug, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub tenant_id: Uuid,
    pub name: String,
}

pub async fn create_workspace(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Json(body): Json<CreateWorkspaceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let owner_key = RoleKey::parse("owner").map_err(AppError::Access)?;
    let active = platform::resolve_active_tenant(&state.saas, &user, body.tenant_id).await?;
    let tenant_id = active.id;
    let ws = tenant::create_workspace_with_owner(
        &state.saas,
        &user,
        tenant_id,
        body.name,
        &user,
        &owner_key,
    )
    .await?;
    Ok(Json(ws))
}

// GET /documents?workspace_id=…

#[derive(Debug, Deserialize)]
pub struct ListDocumentsQuery {
    pub workspace_id: Uuid,
}

pub async fn list_documents(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Query(q): Query<ListDocumentsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let docs = workspace::list_documents(&state.saas, &user, q.workspace_id).await?;
    Ok(Json(docs))
}

// POST /documents

#[derive(Debug, Deserialize)]
pub struct CreateDocumentRequest {
    pub workspace_id: Uuid,
    pub title: String,
}

pub async fn create_document(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Json(body): Json<CreateDocumentRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let _tenant_id = resolve_ws_tenant(&state, &user, body.workspace_id).await?;
    let doc = workspace::create_document(&state.saas, &user, body.workspace_id, body.title).await?;
    Ok(Json(doc))
}

async fn resolve_ws_tenant(
    state: &AxumAppState,
    user: &AuthUser,
    workspace_id: Uuid,
) -> Result<Uuid, AppError> {
    let tenant_id: Option<Uuid> =
        sqlx::query_scalar("select tenant_id from workspaces where id = $1")
            .bind(workspace_id)
            .fetch_optional(state.saas.pool())
            .await
            .map_err(CoreError::from)?;
    let tenant_id = tenant_id.ok_or(AppError::Core(CoreError::NotFound))?;
    let active = platform::resolve_active_tenant(&state.saas, user, tenant_id).await?;
    Ok(active.id)
}

// GET /audit?limit&offset

pub type ListAuditQuery = PaginationQuery;

pub async fn list_audit(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Query(q): Query<ListAuditQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let perms = saas_access::my_permissions(&state.saas, &user, domain::PLATFORM_DOMAIN).await?;
    let allowed = perms.iter().any(|(r, a)| r == "audit" && a == "read");
    if !allowed {
        return Err(AppError::Core(CoreError::Forbidden));
    }
    let (limit, offset) = q.clamp();
    let logger = PgAuditLogger::from_pool(state.saas.pool().clone());
    let page = logger
        .list_paged(limit, offset)
        .await
        .map_err(|e| AppError::Core(CoreError::Internal(e.to_string())))?;
    Ok(Json(page))
}
