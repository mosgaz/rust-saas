//! Three handlers demonstrating ABAC on Casbin.
//!
//! - `create_course`: RBAC — the caller must have `course_type_a:create` or
//!   `course_type_b:create`. The default `can_request` path (RBAC) is used.
//! - `read_course`: ABAC — `owner_only` constraint on `resource.attrs.owner_id`.
//! - `update_course`: ABAC — `status_in` constraint on `resource.attrs.status`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rust_saas::{
    authz::{AuthzError, AuthzRequest, Resource, Subject},
    domain::workspace_domain,
    saas::{platform, CoreError},
    AppError, AxumAppState, CurrentUser,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateCourseReq {
    pub title: String,
    pub kind: String, // "type_a" | "type_b"
}

#[derive(Deserialize)]
pub struct UpdateCourseReq {
    pub title: String,
}

#[derive(Serialize)]
pub struct CourseResponse {
    pub id: Uuid,
    pub title: String,
    pub status: String,
    pub owner_id: Uuid,
}

#[derive(sqlx::FromRow)]
struct CourseRow {
    id: Uuid,
    workspace_id: Uuid,
    title: String,
    status: String,
    owner_id: Uuid,
}

async fn fetch_course(state: &AxumAppState, id: Uuid) -> Result<CourseRow, AppError> {
    let row = sqlx::query_as::<_, CourseRow>(
        "SELECT id, workspace_id, title, status, owner_id FROM courses WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(state.saas.pool())
    .await
    .map_err(|e| AppError::Core(CoreError::Internal(e.to_string())))?;

    row.ok_or(AppError::Core(CoreError::NotFound))
}

fn authz_err(e: AuthzError) -> AppError {
    AppError::Core(CoreError::from(e))
}

pub async fn create_course(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(workspace_id): Path<Uuid>,
    Json(req): Json<CreateCourseReq>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let user = current.require()?;

    // 1. Resolve active workspace (membership + status check).
    platform::resolve_active_workspace(&state.saas, &user, workspace_id).await?;

    // 2. RBAC: check that the caller may create this course kind.
    let domain = workspace_domain(workspace_id);
    let resource_kind = format!("course_{}", req.kind);
    let authz_req = AuthzRequest {
        domain,
        subject: Subject {
            id: user.id,
            roles: vec![],
            attrs: json!({}),
        },
        resource: Resource {
            kind: resource_kind,
            id: None,
            attrs: json!({}),
        },
        action: "create".into(),
        context: json!({}),
    };

    if !state
        .authz
        .can_request(&authz_req)
        .await
        .map_err(authz_err)?
    {
        return Err(AppError::Core(CoreError::Forbidden));
    }

    // 3. Persist.
    let row = sqlx::query_as::<_, (Uuid, String)>(
        "INSERT INTO courses (workspace_id, title, owner_id) VALUES ($1, $2, $3) RETURNING id, status",
    )
    .bind(workspace_id)
    .bind(&req.title)
    .bind(user.id)
    .fetch_one(state.saas.pool())
    .await
    .map_err(|e| AppError::Core(CoreError::Internal(e.to_string())))?;

    Ok((
        StatusCode::CREATED,
        Json(CourseResponse {
            id: row.0,
            title: req.title,
            status: row.1,
            owner_id: user.id,
        }),
    ))
}

pub async fn read_course(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(course_id): Path<Uuid>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let user = current.require()?;
    let course = fetch_course(&state, course_id).await?;
    platform::resolve_active_workspace(&state.saas, &user, course.workspace_id).await?;

    let domain = workspace_domain(course.workspace_id);

    // ABAC: only the owner may read.
    let authz_req = AuthzRequest {
        domain,
        subject: Subject {
            id: user.id,
            roles: vec![],
            attrs: json!({}),
        },
        resource: Resource {
            kind: "course".into(),
            id: Some(course.id),
            attrs: json!({ "owner_id": course.owner_id, "status": course.status }),
        },
        action: "read".into(),
        context: json!({ "constraints": [{"type": "owner_only"}] }),
    };

    if !state
        .authz
        .can_request(&authz_req)
        .await
        .map_err(authz_err)?
    {
        return Err(AppError::Core(CoreError::Forbidden));
    }

    Ok(Json(CourseResponse {
        id: course.id,
        title: course.title,
        status: course.status,
        owner_id: course.owner_id,
    }))
}

pub async fn update_course(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(course_id): Path<Uuid>,
    Json(req): Json<UpdateCourseReq>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let user = current.require()?;
    let course = fetch_course(&state, course_id).await?;
    platform::resolve_active_workspace(&state.saas, &user, course.workspace_id).await?;

    let domain = workspace_domain(course.workspace_id);

    // ABAC: may update only if the course is draft or published.
    let authz_req = AuthzRequest {
        domain,
        subject: Subject {
            id: user.id,
            roles: vec![],
            attrs: json!({}),
        },
        resource: Resource {
            kind: "course".into(),
            id: Some(course.id),
            attrs: json!({ "owner_id": course.owner_id, "status": course.status }),
        },
        action: "write".into(),
        context: json!({
            "constraints": [
                {"type": "status_in", "values": ["draft", "published"]}
            ]
        }),
    };

    if !state
        .authz
        .can_request(&authz_req)
        .await
        .map_err(authz_err)?
    {
        return Err(AppError::Core(CoreError::Forbidden));
    }

    sqlx::query("UPDATE courses SET title = $1 WHERE id = $2")
        .bind(&req.title)
        .bind(course.id)
        .execute(state.saas.pool())
        .await
        .map_err(|e| AppError::Core(CoreError::Internal(e.to_string())))?;

    Ok(Json(CourseResponse {
        id: course.id,
        title: req.title,
        status: course.status,
        owner_id: course.owner_id,
    }))
}
