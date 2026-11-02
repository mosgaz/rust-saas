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
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use domain::AuthUser;

use crate::state::AppState;

pub async fn auth_layer(
    State(app_state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let method = req.method().clone();

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
    let user = match req.extensions().get::<Option<AuthUser>>() {
        Some(Some(u)) => u.clone(),
        _ => return unauthorized(),
    };

    // 4. Path-level permissions (where the domain is unambiguously in the path).
    if method == Method::GET && path == "/platform" {
        if let Err(resp) =
            check_perm(&app_state, &user, domain::PLATFORM_DOMAIN, "tenants", "list").await
        {
            return resp;
        }
    } else if method == Method::GET && path == "/platform/audit" {
        if let Err(resp) =
            check_perm(&app_state, &user, domain::PLATFORM_DOMAIN, "audit", "read").await
        {
            return resp;
        }
    }

    next.run(req).await
}

async fn check_perm(
    state: &AppState,
    user: &AuthUser,
    domain: &str,
    resource: &str,
    action: &str,
) -> Result<(), Response> {
    let perms = match saas::access::my_permissions(&state.saas, user, domain).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path_domain = %domain,
                actor_id = %user.id,
                "auth_layer: my_permissions failed"
            );
            return Err(internal_error());
        }
    };

    if perms.iter().any(|(r, a)| r == resource && a == action) {
        Ok(())
    } else {
        Err(forbidden())
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
