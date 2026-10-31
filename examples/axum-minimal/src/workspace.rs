//! Workspace and document handlers for `axum-minimal` (Stage 3g).
//!
//! Covers the four endpoints in plan §3:
//!
//! - `GET  /workspaces`  — `saas::workspace::list_memberships`; the
//!   workspaces the current user belongs to. Read-only; no `resolve`.
//! - `POST /workspaces`  — **`resolve_active_tenant`** → `saas::tenant::
//!   create_workspace`. The caller becomes the workspace `owner`. A
//!   non-member of the target tenant gets `Forbidden` (403); a member of a
//!   suspended tenant gets `TenantSuspended` (403).
//! - `GET  /documents?workspace_id=…` — `saas::workspace::list_documents`.
//!   Read-only; no `resolve`.
//! - `POST /documents`   — **`resolve_active_tenant`** (via `workspace_id`
//!   → `tenant_id`) → `saas::workspace::create_document`.
//!
//! **`resolve_active_tenant` only on mutations** (ADR-0002 rev.2 §2.4).
//! Reads (`list_my_workspaces`, `list_documents`) stay outside the
//! resolution path — a suspended tenant must remain readable so its members
//! can see what they belong to. Same invariant as `saas-leptos`; only the
//! call sites differ (Axum handlers here vs `#[server]` functions there).
//!
//! **`resolve_ws_tenant`** is the 3g equivalent of
//! `saas-leptos::pages::member::resolve_domain_tenant` and
//! `saas-leptos::pages::workspace::resolve_ws_tenant`. It is **not**
//! `#[cfg(feature = "ssr")]` — `axum-minimal` is a single binary with one
//! target. Returns the resolved `tenant_id`; callers today ignore it, but
//! keeping the return value explicit makes the helper reusable for future
//! mutations that must pass `tenant_id` downstream.
//!
//! **Response shapes.**
//!
//! - `GET  /workspaces` → `200` + `[ { … Workspace … }, … ]`
//! - `POST /workspaces` → `200` + `{ … Workspace … }`
//! - `GET  /documents`  → `200` + `[ { … Document … }, … ]`
//! - `POST /documents`  → `200` + `{ … Document … }`

use std::sync::Arc;

use access::RoleKey;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use domain::{Document, Workspace};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::extract::CurrentUser;
use crate::state::AppState;

// ─── GET /workspaces ────────────────────────────────────────────────────────

/// Lists workspaces the current user is a member of. Read-only; no
/// `resolve_active_tenant`.
pub async fn list_my_workspaces(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let workspaces = saas::workspace::list_memberships(&state.saas, &user).await?;
    Ok(Json(workspaces))
}

// ─── POST /workspaces ───────────────────────────────────────────────────────

/// Body of `POST /workspaces`.
#[derive(Debug, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub tenant_id: Uuid,
    pub name: String,
}

/// Creates a workspace inside a tenant. The caller becomes its `owner`.
///
/// Order:
/// 1. `resolve_active_tenant(state, actor, tenant_id)` — non-member →
///    `Forbidden` (403); suspended → `TenantSuspended` (403); missing →
///    `NotFound` (404).
/// 2. `saas::tenant::create_workspace(..., owner = actor, owner_role =
///    "owner")` — the same call `saas-leptos` makes in
///    `pages::tenant::create_workspace`.
pub async fn create_workspace(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
    Json(body): Json<CreateWorkspaceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;

    let owner_key = RoleKey::parse("owner").map_err(AppError::Access)?;

    let active =
        saas::platform::resolve_active_tenant(&state.saas, &user, body.tenant_id).await?;
    let tenant_id = active.id;

    let ws: Workspace = saas::tenant::create_workspace(
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

// ─── GET /documents?workspace_id=… ──────────────────────────────────────────

/// Query params of `GET /documents`.
#[derive(Debug, Deserialize)]
pub struct ListDocumentsQuery {
    pub workspace_id: Uuid,
}

/// Lists documents in a workspace. Read-only; no `resolve_active_tenant`.
pub async fn list_documents(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
    Query(q): Query<ListDocumentsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let docs = saas::workspace::list_documents(&state.saas, &user, q.workspace_id).await?;
    Ok(Json(docs))
}

// ─── POST /documents ────────────────────────────────────────────────────────

/// Body of `POST /documents`.
#[derive(Debug, Deserialize)]
pub struct CreateDocumentRequest {
    pub workspace_id: Uuid,
    pub title: String,
}

/// Creates a document in a workspace.
///
/// Order:
/// 1. `resolve_ws_tenant(state, actor, workspace_id)` — looks up the
///    workspace's `tenant_id` (`NotFound` if the workspace is gone), then
///    calls `resolve_active_tenant` (membership + active status). Same
///    pattern as `saas-leptos::pages::workspace::create_document`.
/// 2. `saas::workspace::create_document` — enforces `(documents, write)`
///    on `workspace:{id}` internally.
pub async fn create_document(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
    Json(body): Json<CreateDocumentRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;

    let _tenant_id = resolve_ws_tenant(&state, &user, body.workspace_id).await?;

    let doc: Document =
        saas::workspace::create_document(&state.saas, &user, body.workspace_id, body.title).await?;

    Ok(Json(doc))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Resolves the tenant that owns `workspace_id` and verifies it is active
/// for `user`.
///
/// Two steps (same as `saas-leptos::pages::workspace::resolve_ws_tenant`):
///
/// 1. `SELECT tenant_id FROM workspaces WHERE id = $1` — `NotFound` (404)
///    if the workspace row is gone.
/// 2. `saas::platform::resolve_active_tenant` — membership (`EXISTS
///    tenant_members`) + `status = 'active'`. Non-member → `Forbidden`
///    (403); suspended → `TenantSuspended` (403); missing → `NotFound`.
///
/// `sqlx::Error` is converted to [`AppError`] via [`saas::CoreError`]:
/// `CoreError::Db(#[from] sqlx::Error)` → `AppError::Core(#[from]
/// CoreError)`, so a database failure surfaces as HTTP 500 without a
/// custom mapping.
async fn resolve_ws_tenant(
    state: &AppState,
    user: &domain::AuthUser,
    workspace_id: Uuid,
) -> Result<Uuid, AppError> {
    let tenant_id: Option<Uuid> =
        sqlx::query_scalar("select tenant_id from workspaces where id = $1")
            .bind(workspace_id)
            .fetch_optional(state.saas.pool())
            .await
            .map_err(saas::CoreError::from)?;

    let tenant_id = tenant_id.ok_or(AppError::Core(saas::CoreError::NotFound))?;

    let active = saas::platform::resolve_active_tenant(&state.saas, user, tenant_id).await?;
    Ok(active.id)
}