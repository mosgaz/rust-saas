//! `axum-minimal` library surface (Stage 4.7).
//!
//! Exposes `build_app(state)` so `tests/e2e.rs` can drive the router
//! in-process via `tower::ServiceExt::oneshot` — no TCP, no port binding.
//!
//! `main.rs` is the thin binary: reads env, wires `AppState`, calls
//! [`build_app`], then `axum::serve`. Everything else (handlers, middleware,
//! router assembly) lives here.
//!
//! The `mod audit;` declaration shadows the external `audit` crate in the
//! crate-root namespace; the external trait is imported as
//! `::audit::AuditLogger` in `main.rs` (leading `::` forces the crate path).

use std::sync::Arc;

use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub mod audit;
pub mod auth;
pub mod auth_layer;
pub mod cookie;
pub mod csrf;
pub mod email;
pub mod error;
pub mod extract;
pub mod health;
pub mod middleware;
pub mod rate_limit;
pub mod state;
pub mod tenant;
pub mod workspace;

pub use state::AppState;

/// Builds the full `axum::Router` (public + protected, all layers).
///
/// Split (ADR-0002 rev.2 §2.1):
/// - **protected** — `auto_refresh` + `csrf_guard` + `auth_layer`; routes
///   that require an actor (`/auth/refresh`, `/tenants`, `/workspaces`,
///   `/documents`, `/audit`).
/// - **public** — `/healthz`, `/auth/{register,login,logout}`.
///
/// `csrf_issue` on the whole router (issues a `csrf` cookie on first
/// request). `TraceLayer` on the whole app.
///
/// Layer order on the protected router (outermost first; note that
/// `.route_layer` calls run in **reverse** of the order written):
/// `csrf_guard` \u2192 `auto_refresh` \u2192 `auth_layer` \u2192 handler.
pub fn build_app(app_state: Arc<AppState>) -> Router {
    let protected: Router<Arc<AppState>> = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .route(
            "/tenants",
            get(tenant::list_my_tenants).post(tenant::create_tenant),
        )
        .route(
            "/workspaces",
            get(workspace::list_my_workspaces).post(workspace::create_workspace),
        )
        .route(
            "/documents",
            get(workspace::list_documents).post(workspace::create_document),
        )
        .route("/audit", get(audit::list_audit))
        // Innermost: must run *after* `auto_refresh` populated
        // `Extension<Option<AuthUser>>`.
        .route_layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_layer::auth_layer,
        ))
        // Stage 3g: verify access / rotate refresh.
        .route_layer(from_fn_with_state(
            app_state.clone(),
            middleware::auto_refresh,
        ))
        // Outermost: reject cross-origin before doing any auth work.
        .route_layer(axum::middleware::from_fn(csrf::csrf_guard));

    let public: Router<Arc<AppState>> = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout));

    protected
        .merge(public)
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            csrf::csrf_issue,
        ))
        .with_state(app_state)
}
