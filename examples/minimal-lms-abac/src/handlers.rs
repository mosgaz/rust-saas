//! Handlers demonstrating all 4 built-in ABAC constraints on Casbin.
//!
//! - `create_course`: RBAC — the caller must have `course_type_a:create`.
//! - `read_course`: `owner_only` — only the owner can read.
//! - `update_course`: `owner_only` + `status_in` + `attr_eq` (not locked).
//! - `read_shared_course`: `attr_in_subject` (same department).

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
    pub department: String,
    pub owner_id: Uuid,
}

#[derive(sqlx::FromRow)]
struct CourseRow {
    id: Uuid,
    workspace_id: Uuid,
    title: String,
    status: String,
    department: String,
    is_locked: bool,
    owner_id: Uuid,
}

async fn fetch_course(state: &AxumAppState, id: Uuid) -> Result<CourseRow, AppError> {
    let row = sqlx::query_as::<_, CourseRow>(
        "SELECT id, workspace_id, title, status, department, is_locked, owner_id FROM courses WHERE id = $1",
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
    platform::resolve_active_workspace(&state.saas, &user, workspace_id).await?;

    let domain = workspace_domain(workspace_id);
    let resource_kind = format!("course_{}", req.kind);
    let authz_req = AuthzRequest {
        domain,
        subject: Subject { id: user.id, roles: vec![], attrs: json!({}) },
        resource: Resource { kind: resource_kind, id: None, attrs: json!({}) },
        action: "create".into(),
        context: json!({}),
    };

    if !state.authz.can_request(&authz_req).await.map_err(authz_err)? {
        return Err(AppError::Core(CoreError::Forbidden));
    }

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
            department: "general".into(),
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

    let authz_req = AuthzRequest {
        domain: workspace_domain(course.workspace_id),
        subject: Subject { id: user.id, roles: vec![], attrs: json!({}) },
        resource: Resource {
            kind: "course".into(),
            id: Some(course.id),
            attrs: json!({ "owner_id": course.owner_id }),
        },
        action: "read".into(),
        context: json!({ "constraints": [{"type": "owner_only"}] }),
    };

    if !state.authz.can_request(&authz_req).await.map_err(authz_err)? {
        return Err(AppError::Core(CoreError::Forbidden));
    }

    Ok(Json(CourseResponse {
        id: course.id,
        title: course.title,
        status: course.status,
        department: course.department,
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

    let authz_req = AuthzRequest {
        domain: workspace_domain(course.workspace_id),
        subject: Subject { id: user.id, roles: vec![], attrs: json!({}) },
        resource: Resource {
            kind: "course".into(),
            id: Some(course.id),
            attrs: json!({
                "owner_id": course.owner_id,
                "status": course.status,
                "is_locked": course.is_locked
            }),
        },
        action: "write".into(),
        context: json!({
            "constraints": [
                {"type": "owner_only"},
                {"type": "status_in", "values": ["draft", "published"]},
                {"type": "attr_eq", "path": "is_locked", "value": false}
            ]
        }),
    };

    if !state.authz.can_request(&authz_req).await.map_err(authz_err)? {
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
        department: course.department,
        owner_id: course.owner_id,
    }))
}

pub async fn read_shared_course(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Path(course_id): Path<Uuid>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let user = current.require()?;
    let course = fetch_course(&state, course_id).await?;
    platform::resolve_active_workspace(&state.saas, &user, course.workspace_id).await?;

    // In a real app, `user_department` comes from the DB or JWT claims.
    // Here we mock it based on the user's email for demonstration.
    let user_department = if user.email.contains("math") { "math" } else { "general" };

    let authz_req = AuthzRequest {
        domain: workspace_domain(course.workspace_id),
        subject: Subject {
            id: user.id,
            roles: vec![],
            attrs: json!({ "department": user_department }),
        },
        resource: Resource {
            kind: "course".into(),
            id: Some(course.id),
            attrs: json!({ "department": course.department }),
        },
        action: "read".into(),
        context: json!({ "constraints": [{"type": "attr_in_subject", "attr": "department"}] }),
    };

    if !state.authz.can_request(&authz_req).await.map_err(authz_err)? {
        return Err(AppError::Core(CoreError::Forbidden));
    }

    Ok(Json(CourseResponse {
        id: course.id,
        title: course.title,
        status: course.status,
        department: course.department,
        owner_id: course.owner_id,
    }))
}
