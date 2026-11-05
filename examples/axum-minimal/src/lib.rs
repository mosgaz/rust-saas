//! `build_app` for `tests/e2e.rs` and `main.rs` (Stage 5.0-A6).
//!
//! `build_app_full_with` merges the standard `saas-axum` endpoints
//! (`/healthz`, `/readyz`, `/metrics`, `/auth/*`, `/my_permissions*`,
//! `/resource_types`) **and** our 7 consumer routes under one middleware
//! chain (`csrf_guard -> auto_refresh -> auth_layer`).

pub mod handlers;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use rust_saas::{build_app_full_with, AxumAppState};

pub fn build_app(state: Arc<AxumAppState>) -> Router {
    let extra: Router<Arc<AxumAppState>> = Router::new()
        .route(
            "/tenants",
            get(handlers::list_my_tenants).post(handlers::create_tenant),
        )
        .route(
            "/workspaces",
            get(handlers::list_my_workspaces).post(handlers::create_workspace),
        )
        .route(
            "/documents",
            get(handlers::list_documents).post(handlers::create_document),
        )
        .route("/audit", get(handlers::list_audit));
    build_app_full_with(state, extra)
}
