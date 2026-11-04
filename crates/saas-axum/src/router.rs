//! `build_app(state)` — router assembly for `saas-axum` (Stage 5.0-A4.3b).
//!
//! **Three entry points.**
//!
//! - [`build_app`] — public surface only (`/healthz`, `/readyz`,
//!   `/metrics`, `404 fallback`). Suitable for a consumer that does not
//!   add protected routes; also what `saas-axum` ships in PR-2 (before
//!   A4.4 endpoints exist).
//! - [`build_app_with_protected`] — public + caller-supplied protected
//!   routes, with `csrf_guard` → `auto_refresh` → `auth_layer` applied
//!   to the protected router (A4.4 uses this; a consumer with custom
//!   endpoints uses it too).
//! - [`build_app_full`] — public + the standard `saas-axum` endpoints
//!   (`/auth/*`, `/my_permissions`, `/my_permissions/grouped`,
//!   `/resource_types`) wired in one call. Additive to `build_app` /
//!   `build_app_with_protected` (handoff §4.1, variant B). A consumer
//!   with custom protected routes still uses
//!   `build_app_with_protected`; a consumer that needs only the
//!   standard surface uses `build_app_full`.
//!
//! **Why the split.** `axum::Router::route_layer` panics if the router
//! has no routes ("Adding a route_layer before any routes is a no-op").
//! In PR-2 there are no protected routes yet (A4.4 adds `/auth/refresh`
//! etc.); `build_app` therefore must not apply `route_layer` to an empty
//! router. `build_app_with_protected` takes the protected `Router` as an
//! argument so the caller adds routes **first**, then `route_layer`
//! runs. Same pattern a consumer with custom protected endpoints would
//! use.
//!
//! **Layer order on protected routes** (outermost first; `route_layer`
//! calls execute in reverse order, so `auth_layer` is registered first
//! to end up innermost):
//!
//!   1. `csrf_guard` — reject cross-site mutations before any auth work.
//!   2. `auto_refresh` — verify / rotate cookies, populate
//!      `Extension<Option<AuthUser>>`.
//!   3. `auth_layer` — 401 / path-level permission / `require_active`.
//!   4. handler — `saas::*` still calls `authz.require` (authoritative).
//!
//! **Public router.** `csrf_issue` is applied to the merged router
//! (outermost, `.layer(...)` after `.with_state(...)`), so a first GET
//! bootstraps the `csrf` cookie. `csrf_issue` skips `/healthz` itself
//! (probe endpoint — no session, no cookie). The `/readyz` handler is
//! wired here for the first time (was deferred from PR-1 because
//! `check_redis()` reads `REDIS_URL` from env; tests run without it,
//! so `redis = "not_configured"` and `/readyz` → `200`).
//!
//! **`csrf_issue` on merged router.** `.layer()` (unlike `route_layer`)
//! does **not** panic on an empty router — it just applies to no routes
//! (here: public only). `TraceLayer` similar.

use std::sync::Arc;

use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::{Json, Router};
use tower_http::trace::TraceLayer;

use crate::health;
use crate::middleware::{auth_layer, auto_refresh, csrf};
use crate::state::AxumAppState;

/// Public surface: `/healthz`, `/readyz`, `/metrics`, `404 fallback`.
///
/// No protected routes, no `route_layer` chain. `csrf_issue` +
/// `TraceLayer` are applied to the merged router; `/healthz` is skipped
/// by `csrf_issue` internally.
pub fn build_app(state: Arc<AxumAppState>) -> Router {
    let public: Router<Arc<AxumAppState>> = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/metrics", get(health::metrics))
        .fallback(not_found);

    public
        .layer(TraceLayer::new_for_http())
        .layer(from_fn_with_state(state.clone(), csrf::csrf_issue))
        .with_state(state)
}

/// Public surface **plus** caller-supplied protected routes.
///
/// The `protected` argument must contain at least one `.route(...)` —
/// `route_layer` panics on an empty router. A4.4 passes
/// `Router::new().route("/auth/refresh", post(...)).route(...)`; a
/// consumer with custom endpoints does the same.
///
/// The middleware chain `csrf_guard` → `auto_refresh` → `auth_layer` is
/// applied to `protected` exactly once.
pub fn build_app_with_protected(
    state: Arc<AxumAppState>,
    protected: Router<Arc<AxumAppState>>,
) -> Router {
    // Order (reverse of registration — innermost first):
    //   auth_layer (innermost) → auto_refresh → csrf_guard (outermost).
    let protected = protected
        .route_layer(from_fn_with_state(state.clone(), auth_layer::auth_layer))
        .route_layer(from_fn_with_state(
            state.clone(),
            auto_refresh::auto_refresh,
        ))
        .route_layer(axum::middleware::from_fn(csrf::csrf_guard));

    let public: Router<Arc<AxumAppState>> = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/metrics", get(health::metrics))
        .fallback(not_found);

    protected
        .merge(public)
        .layer(TraceLayer::new_for_http())
        .layer(from_fn_with_state(state.clone(), csrf::csrf_issue))
        .with_state(state)
}

/// Public surface **plus** the standard `saas-axum` endpoints (Stage
/// 5.0-A4.4): `/auth/{register,login,logout,refresh}`, `/my_permissions`,
/// `/my_permissions/grouped`, `/resource_types`.
///
/// **Additive.** `build_app` (public-only) and `build_app_with_protected`
/// (caller-supplied protected routes) are unchanged. A consumer picks one:
/// - `build_app` — minimal; add your own protected routes via
///   `build_app_with_protected` if you need them.
/// - `build_app_with_protected` — public + custom protected; no standard
///   endpoints.
/// - `build_app_full` — public + standard endpoints; no custom protected.
///
/// **Public vs protected.**
/// - **Public:** `/healthz`, `/readyz`, `/metrics`, `/auth/{register,
///   login,logout}`. `csrf_issue` runs on the merged router (bootstraps
///   the `csrf` cookie on first GET; skips `/healthz` internally).
/// - **Protected** (middleware chain `csrf_guard` → `auto_refresh` →
///   `auth_layer` → handler): `/auth/refresh`, `/my_permissions`,
///   `/my_permissions/grouped`, `/resource_types`.
///
/// **Layer order** (identical to `build_app_with_protected`): the
/// protected router is populated **first**, then `route_layer` calls run
/// in reverse of registration, so `auth_layer` is registered first
/// (innermost) and `csrf_guard` last (outermost).
pub fn build_app_full(state: Arc<AxumAppState>) -> Router {
    build_app_full_with(state, Router::new())
}

pub fn build_app_full_with(
    state: Arc<AxumAppState>,
    extra_protected: Router<Arc<AxumAppState>>,
) -> Router {
    // `get` is module-level; only `post` needs a local import.
    use axum::routing::post;

    let protected: Router<Arc<AxumAppState>> = Router::new()
        .route("/auth/refresh", post(crate::endpoints::refresh))
        .route(
            "/my_permissions",
            get(crate::endpoints::my_permissions_flat),
        )
        .route(
            "/my_permissions/grouped",
            get(crate::endpoints::my_permissions_grouped),
        )
        .route("/resource_types", get(crate::endpoints::resource_types))
        // Merge caller-supplied routes BEFORE the layers are applied.
        .merge(extra_protected)
        // Innermost (registered first — `route_layer` reverses order).
        .route_layer(from_fn_with_state(state.clone(), auth_layer::auth_layer))
        // Middle: verify access / rotate refresh, populate Extension<AuthUser>.
        .route_layer(from_fn_with_state(
            state.clone(),
            auto_refresh::auto_refresh,
        ))
        // Outermost: reject cross-origin mutations before any auth work.
        .route_layer(axum::middleware::from_fn(csrf::csrf_guard));

    let public: Router<Arc<AxumAppState>> = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/metrics", get(health::metrics))
        .route("/auth/register", post(crate::endpoints::register))
        .route("/auth/login", post(crate::endpoints::login))
        .route("/auth/logout", post(crate::endpoints::logout))
        .fallback(not_found);

    protected
        .merge(public)
        .layer(TraceLayer::new_for_http())
        .layer(from_fn_with_state(state.clone(), csrf::csrf_issue))
        .with_state(state)
}

async fn not_found() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not found" })),
    )
}
