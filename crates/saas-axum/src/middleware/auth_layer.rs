//! Server-side `AuthLayer` for `saas-axum` (Stage 4.1d, ported).
//!
//! Defense-in-depth counterpart to the client-side guard pattern in
//! `examples/saas-leptos` (`RouteGuard` / `GuardRoute`). The library
//! services (`saas::*`) are already authoritative — every mutation goes
//! through `authz.require` / `resolve_active_tenant`. `AuthLayer` is a
//! *second* check that fires **before** the handler: it catches a handler
//! that forgot `CurrentUser::require()` or a path whose permission
//! requirement drifted from the handler.
//!
//! **PR-1 scope (this file):**
//! - Actor required on every protected route (except the three public
//!   auth endpoints). Anonymous → 401 before the handler runs.
//! - Pass-through for the three public auth paths
//!   (`PUBLIC_AUTH_PATHS`) — same list as `csrf_guard`.
//!
//! **A4.3a will add** (do not add here):
//! - Path-level permission check via
//!   [`crate::bindings::RouteBindings`] + [`crate::bindings::PathPermissions`];
//! - Built-in precedence (built-in wins over `PathPermissions`, which
//!   wins over custom bindings, which wins over pass-through);
//! - `BindingScope::TenantFromPath` / `WorkspaceFromPath` resolution
//!   through `saas::platform::resolve_active_tenant` /
//!   `resolve_active_workspace`;
//! - `require_active` flag honored (mutations reject a suspended tenant
//!   before the handler).
//!
//! **Layer order (A4.3b will wire):** `csrf_guard` → `auto_refresh` →
//! `auth_layer` → handler. `auth_layer` runs *after* `auto_refresh`, so
//! `Extension<Option<AuthUser>>` is already populated.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use domain::AuthUser;

use crate::state::AxumAppState;

/// Public auth paths — the same set `csrf::csrf_guard` exempts. No actor is
/// required on these; the handler is responsible for whatever checks it
/// needs (login rate limit, registration validation, etc.).
const PUBLIC_AUTH_PATHS: &[&str] = &["/auth/register", "/auth/login", "/auth/logout"];

fn is_public_auth(path: &str) -> bool {
    PUBLIC_AUTH_PATHS.contains(&path)
}

/// `AuthLayer` middleware. Attach to the protected router **inside**
/// `auto_refresh` (so `Extension<Option<AuthUser>>` is populated) and
/// **outside** the handlers.
///
/// Execution order on the protected router:
///   `csrf_guard` → `auto_refresh` → `auth_layer` → handler
pub async fn auth_layer(
    State(_app_state): State<Arc<AxumAppState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    if is_public_auth(&path) {
        return next.run(req).await;
    }

    // Actor required — fail fast before the handler.
    match req.extensions().get::<Option<AuthUser>>() {
        Some(Some(_)) => next.run(req).await,
        _ => unauthorized(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_auth_paths_recognized() {
        assert!(is_public_auth("/auth/register"));
        assert!(is_public_auth("/auth/login"));
        assert!(is_public_auth("/auth/logout"));
        assert!(!is_public_auth("/auth/refresh"));
        assert!(!is_public_auth("/tenants"));
        assert!(!is_public_auth("/audit"));
    }

    #[test]
    fn public_auth_paths_are_same_as_csrf() {
        // If the two lists ever diverge, csrf_guard and auth_layer would
        // disagree about which endpoints are anonymous — that mismatch is
        // a security bug waiting to happen. Keeping the two lists aligned
        // is a contract.
        use crate::middleware::csrf::tests_support::public_auth_paths as csrf_paths;
        assert_eq!(PUBLIC_AUTH_PATHS, csrf_paths());
    }
}
