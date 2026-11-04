//! Minimal LMS handlers: 4 routes, 5 routes, 3 E2E (A5).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use rust_saas::saas::platform::{
    resolve_active_tenant, resolve_active_workspace, resolve_tenant, resolve_workspace,
};
use rust_saas::saas::CoreError;
use rust_saas::{domain, AppError, AxumAppState, CurrentUser};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Course {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub status: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FileRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Batch {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateCourseReq {
    pub title: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateBatchReq {
    pub name: String,
}

fn pool(state: &AxumAppState) -> &PgPool {
    state.saas.pool()
}

pub async fn list_courses(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(workspace_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    resolve_workspace(&state.saas, &user, workspace_id).await?;
    let rows: Vec<Course> = sqlx::query_as(
        "select id, workspace_id, title, status from courses where workspace_id = $1 order by created_at desc",
    ).bind(workspace_id).fetch_all(pool(&state)).await.map_err(CoreError::from)?;
    Ok(Json(rows))
}

pub async fn create_course(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(workspace_id): Path<Uuid>,
    Json(body): Json<CreateCourseReq>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    resolve_active_workspace(&state.saas, &user, workspace_id).await?;
    state
        .authz
        .require(
            user.id,
            &domain::workspace_domain(workspace_id),
            "course",
            "write",
        )
        .await
        .map_err(CoreError::from)?;
    let course: Course = sqlx::query_as(
        "insert into courses (workspace_id, title) values ($1, $2) returning id, workspace_id, title, status",
    ).bind(workspace_id).bind(&body.title).fetch_one(pool(&state)).await.map_err(CoreError::from)?;
    Ok(Json(course))
}

pub async fn list_files(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(tenant_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    resolve_tenant(&state.saas, &user, tenant_id).await?;
    let rows: Vec<FileRow> = sqlx::query_as(
        "select id, tenant_id, name, size_bytes from files where tenant_id = $1 order by created_at desc",
    ).bind(tenant_id).fetch_all(pool(&state)).await.map_err(CoreError::from)?;
    Ok(Json(rows))
}

pub async fn create_batch(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(tenant_id): Path<Uuid>,
    Json(body): Json<CreateBatchReq>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    resolve_active_tenant(&state.saas, &user, tenant_id).await?;
    state
        .authz
        .require(
            user.id,
            &domain::tenant_domain(tenant_id),
            "batch",
            "manage",
        )
        .await
        .map_err(CoreError::from)?;
    let batch: Batch = sqlx::query_as(
        "insert into batches (tenant_id, name) values ($1, $2) returning id, tenant_id, name",
    )
    .bind(tenant_id)
    .bind(&body.name)
    .fetch_one(pool(&state))
    .await
    .map_err(CoreError::from)?;
    Ok(Json(batch))
}
