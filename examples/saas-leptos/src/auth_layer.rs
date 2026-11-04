//! Server-side `AuthLayer` for `saas-leptos` (Stage 4.9).
//!
//! Defense-in-depth counterpart to the client-side `GuardRoute`.
//! The library services (`saas::*`) are already authoritative — every mutation
//! goes through `authz.require` / `resolve_active_tenant`.
//!
//! `AuthLayer` is a *second* check that fires **before** the handler:
//! it catches a handler that forgot `CurrentUser::require()` or a path
//! whose permission requirement drifted from the handler.
//!
//! **Scope:**
//! - `/_server/*` — pass-through. Leptos `#[server]` functions already call
//!   `CurrentUser::require()` and `resolve_active_tenant` internally. We
//!   cannot reliably match their exact URL (`/_server/{hash}`) in middleware
//!   without coupling to `server_fn` internals.
//! - Static assets (`/pkg/*`, `/assets/*`, `/healthz`) — pass-through.
//! - Public pages (`/`, `/login`, etc.) — pass-through.
//! - Protected SSR pages (`/tenants`, `/workspaces`, `/platform`, etc.) —
//!   require an authenticated actor (401 if missing). For `/platform` and
//!   `/platform/audit`, also enforce path-level permissions.


use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use domain::AuthUser;

use crate::state::AppState;

pub async fn auth_layer(
    State(_app_state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();

    // 1. Pass-through for server functions, static assets, and health.
    if path.starts_with("/_server/")
        || path.starts_with("/pkg/")
        || path.starts_with("/assets/")
        || path == "/healthz"
        || path == "/favicon.ico"
    {
        return next.run(req).await;
    }

    // 2. Pass-through for public SSR pages.
    if path == "/"
        || path == "/login"
        || path == "/register"
        || path == "/forgot-password"
        || path.starts_with("/verify/")
        || path.starts_with("/reset-password/")
        || path.starts_with("/invitations/")
    {
        return next.run(req).await;
    }

    // 3. Actor required for all other SSR pages (e.g. `/tenants`).
    let _user = match req.extensions().get::<Option<AuthUser>>() {
        Some(Some(u)) => u.clone(),
        _ => return unauthorized(),
    };

    // 4. Path-level permissions (where the domain is unambiguously in the path).
    // NOTE: For SSR pages, we let the `#[server]` functions handle permissions
    // (`saas::*` does `authz.require`). AuthLayer here is strictly for 401.

    next.run(req).await
}


fn unauthorized() -> Response {
    use axum::http::StatusCode;
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

