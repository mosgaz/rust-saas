//! minimal-lms-abac library: shared app builder and migrator.

use std::sync::Arc;

use axum::routing::{get, patch, post};
use rust_saas::{build_app_full_with, AxumAppState};
use sqlx::migrate::Migrator;

pub mod handlers;

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub fn build_app(state: Arc<AxumAppState>) -> axum::Router {
    let extra = axum::Router::<Arc<AxumAppState>>::new()
        .route(
            "/workspaces/{workspace_id}/courses",
            post(handlers::create_course),
        )
        .route("/courses/{course_id}", get(handlers::read_course))
        .route("/courses/{course_id}/shared", get(handlers::read_shared_course))
        .route("/courses/{course_id}", patch(handlers::update_course));
    build_app_full_with(state, extra)
}
