//! Server-side `AuthLayer` for `axum-minimal` (Stage 4.1d).
//!
//! Defense-in-depth counterpart to the client-side guard pattern used in
//! `saas-leptos` (`RouteGuard` / `GuardRoute`). The library services
//! (`saas::*`) are already authoritative — every mutation goes through
//! `authz.require` / `resolve_active_tenant`. `AuthLayer` is a *second*
//! check that fires **before** the handler: it catches a handler that
//! forgot `CurrentUser::require()` or a path whose permission requirement
//! drifted from the handler. The primary security boundary remains
//! `saas::*`.
//!
//! Scope (deliberate limitation):
//!
//! - **Actor required** on every protected route (except the three public
//!   auth endpoints). Anonymous → 401 before the handler runs.
//! - **Permission** on the paths where the domain is unambiguous from
//!   `(method, path)`:
//!   - `POST /tenants`   → `PLATFORM_DOMAIN` + `(tenant, create)`
//!   - `GET  /audit`     → `PLATFORM_DOMAIN` + `(audit, read)`
//! - **Pass-through** where the scope id arrives in the body (which a
//!   middleware cannot inspect without buffering and re-parsing):
//!   - `POST /workspaces`  (`tenant_id` in JSON body)
//!   - `POST /documents`   (`workspace_id` in JSON body)
//!   - `GET  /workspaces`, `GET /documents?workspace_id=…`
//!
//! For those, `saas::*` performs the `require` and `resolve_active_tenant`
//! does the suspension check; adding a body parser to the middleware
//! would duplicate deserialization and produce two independent wire
//! formats. Not worth it for the reference consumer.
//!
//! `saas-leptos` does **not** have an `AuthLayer`: Leptos `#[server]`
//! routes go to `/_server/*`, and each `#[server]` function already calls
//! `CurrentUser::require()` + `resolve_active_tenant`; the same defense is
//! achieved without a per-route middleware. See
//! `internal-docs/sass-19.md` §16.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use domain::AuthUser;

use crate::state::AppState;

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
    State(app_state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    if is_public_auth(&path) {
        return next.run(req).await;
    }

    // Actor required — fail fast before the handler.
    let user = match req.extensions().get::<Option<AuthUser>>() {
        Some(Some(u)) => u.clone(),
        _ => return unauthorized(),
    };

    // Path-level permission check, where the domain is known from path.
    let method = req.method().clone();
    let checked = if method == Method::POST && path == "/tenants" {
        check_perm(
            &app_state,
            &user,
            domain::PLATFORM_DOMAIN,
            "tenant",
            "create",
        )
        .await
    } else if method == Method::GET && path == "/audit" {
        check_perm(&app_state, &user, domain::PLATFORM_DOMAIN, "audit", "read").await
    } else {
        Ok(())
    };
    if let Err(rejection) = checked {
        return *rejection;
    }

    next.run(req).await
}

async fn check_perm(
    state: &AppState,
    user: &AuthUser,
    domain: &str,
    resource: &str,
    action: &str,
) -> Result<(), Box<Response>> {
    let perms = match saas::access::my_permissions(&state.saas, user, domain).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path_domain = %domain,
                actor_id = %user.id,
                "auth_layer: my_permissions failed"
            );
            return Err(Box::new(internal_error()));
        }
    };
    if perms.iter().any(|(r, a)| r == resource && a == action) {
        Ok(())
    } else {
        Err(Box::new(forbidden()))
    }
}

fn unauthorized() -> Response {
    use axum::http::StatusCode;
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

fn forbidden() -> Response {
    use axum::http::StatusCode;
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": "forbidden" })),
    )
        .into_response()
}

fn internal_error() -> Response {
    use axum::http::StatusCode;
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({ "error": "internal error" })),
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
        use crate::csrf::tests_support::public_auth_paths as csrf_paths;
        assert_eq!(PUBLIC_AUTH_PATHS, csrf_paths());
    }
}
