//! `build_app` for tests + `main.rs` (A5).
//!
//! `build_app_full_with` merges the standard `saas-axum` endpoints
//! (`/auth/*`, `/my_permissions*`, `/resource_types`) **and** our 4 LMS routes
//! under one middleware chain (`csrf_guard -> auto_refresh -> auth_layer`).

pub mod handlers;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use rust_saas::{build_app_full_with, AxumAppState};

pub fn build_app(state: Arc<AxumAppState>) -> Router {
    let extra: Router<Arc<AxumAppState>> = Router::new()
        .route(
            "/workspaces/{workspace_id}/courses",
            get(handlers::list_courses).post(handlers::create_course),
        )
        .route("/tenants/{tenant_id}/files", get(handlers::list_files))
        .route("/tenants/{tenant_id}/batches", post(handlers::create_batch));
    build_app_full_with(state, extra)
}
