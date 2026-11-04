//! `build_app(state)` — router assembly for `saas-axum` (Stage 5.0-A4).
//!
//! **PR-1 scope:** public router with `/healthz` + `/metrics` + `404`
//! fallback. `TraceLayer` on the whole app. State is
//! `Arc<AxumAppState>`.
//!
//! **A4.3b will add** (do not add here):
//! - `/readyz` (handler already in `health.rs`; deferred because
//!   `check_redis()` reads `REDIS_URL` from env and `cargo test` must not
//!   depend on a running Redis);
//! - `csrf_issue` on the whole router, `csrf_guard` / `auto_refresh` /
//!   `auth_layer` as `route_layer` on the protected router (layer order:
//!   `csrf_guard` → `auto_refresh` → `auth_layer` → handler);
//! - `RouteBindings` + `PathPermissions` enforcement in `auth_layer`.
//!
//! **A4.4 will add** (do not add here): `/auth/{register,login,logout,refresh}`,
//! `/my_permissions`, `/resource_types`.
//!
//! **Public-vs-protected split** (ADR-0002 rev.2 §2.1): public routes are
//! reachable without an actor and without CSRF; protected routes require
//! both. In PR-1 there are no protected routes yet; the split is kept in
//! the docstring so A4.3b can introduce it without a rewrite.
//!
//! **Why `Arc<AxumAppState>`.** `Router::with_state` takes the state by
//! value; `build_app` consumes `Arc<AxumAppState>` so callers
//! (`main.rs`, `tests/e2e.rs`) do not need to clone the whole state into
//! every sub-router. Every handler and middleware takes
//! `State<Arc<AxumAppState>>`.

use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use tower_http::trace::TraceLayer;

use crate::health;
use crate::state::AxumAppState;

/// Builds the full `axum::Router` for `saas-axum`. See module docs for the
/// PR-1 scope and what A4.3b / A4.4 will add.
pub fn build_app(state: Arc<AxumAppState>) -> Router {
    let app: Router<Arc<AxumAppState>> = Router::new()
        // Liveness. Public, no auth, no CSRF, no DB.
        .route("/healthz", get(health::healthz))
        // Prometheus exposition (public: no session for the scraper,
        // counters only, no PII). `404` when `with_prometheus` was not
        // called.
        .route("/metrics", get(health::metrics))
        // Explicit 404 for unknown paths — the wire shape is
        // `{"error":"not found"}`, not an empty body.
        .fallback(not_found);

    app.layer(TraceLayer::new_for_http()).with_state(state)
}

async fn not_found() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not found" })),
    )
}
