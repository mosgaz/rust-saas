//! Server-side `AuthLayer` for `saas-axum` (Stage 5.0-A4.3a).
//!
//! Defense-in-depth counterpart to the library `saas::*` checks: every
//! mutation still calls `authz.require` / `resolve_active_tenant`
//! internally. `AuthLayer` is a **second** check that fires *before* the
//! handler — it catches a handler that forgot `CurrentUser::require()` or
//! a path whose permission requirement drifted from the handler.
//!
//! **Precedence** (structural, not runtime-dispatched — see
//! [`crate::bindings`] docs):
//!
//! 1. `PUBLIC_AUTH_PATHS` (`/auth/{register,login,logout}`) — pass-through.
//!    These are also on the public router; kept here for defense in depth
//!    (a consumer that mounts `auth_layer` on a merged router gets the
//!    same behaviour).
//! 2. `PathPermissions::is_public` — pass-through (consumer-controlled).
//! 3. `RouteBindings::resolve` — built-in bindings always win over user
//!    bindings (see [`crate::bindings::RouteBindings::new`]): a user
//!    cannot accidentally make `/healthz` protected.
//!    - `AuthenticatedOnly` → require actor, then `next`.
//!    - `Platform` / `TenantFromPath` / `WorkspaceFromPath` →
//!      [`check_permission`].
//! 4. `PathPermissions::path_permission` — `Some(target)` →
//!    [`check_permission`]; `None` → pass-through.
//! 5. Otherwise — pass-through (handler is authoritative).
//!
//! **Layer order** (wired in `router.rs`, A4.3b):
//! `csrf_guard` → `auto_refresh` → `auth_layer` → handler.
//!
//! **`require_active`.** Bindings with `require_active = true` call
//! `resolve_active_tenant` / `resolve_active_workspace` (membership +
//! `status = 'active'`); a suspended tenant returns `403 tenant is
//! suspended`. `require_active = false` (reads) only checks membership
//! via `resolve_tenant` / `resolve_workspace` — a suspended tenant is
//! still readable (ADR-0002 rev.2 §2.4).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use domain::{AuthUser, PLATFORM_DOMAIN};
use uuid::Uuid;

use crate::bindings::{BindingScope, OwnedAuthzTarget, ResolvedBinding};
use crate::state::AxumAppState;

/// Public auth paths. The same set `csrf::csrf_guard` exempts.
const PUBLIC_AUTH_PATHS: &[&str] = &["/auth/register", "/auth/login", "/auth/logout"];

fn is_public_auth(path: &str) -> bool {
    PUBLIC_AUTH_PATHS.contains(&path)
}

/// `AuthLayer` middleware. Attach to the protected router **inside**
/// `auto_refresh` (so `Extension<Option<AuthUser>>` is populated).
pub async fn auth_layer(
    State(state): State<Arc<AxumAppState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // 1. Public auth endpoints.
    if is_public_auth(&path) {
        return next.run(req).await;
    }

    // 2. Consumer-owned public paths.
    if let Some(pp) = &state.path_permissions {
        if pp.is_public(&method, &path) {
            return next.run(req).await;
        }
    }

    // Actor is needed for every remaining branch.
    let actor = match req.extensions().get::<Option<AuthUser>>() {
        Some(Some(u)) => u.clone(),
        _ => return unauthorized(),
    };

    // 3. Built-in + user bindings (built-in wins — see RouteBindings::new).
    if let Some(ResolvedBinding { binding, params }) = state.bindings.resolve(&method, &path) {
        if matches!(binding.scope, BindingScope::AuthenticatedOnly) {
            return next.run(req).await;
        }
        return match check_permission(
            &state,
            &actor,
            binding.scope,
            binding.resource_type,
            binding.action,
            binding.require_active,
            &params,
        )
        .await
        {
            Ok(()) => next.run(req).await,
            Err(resp) => *resp,
        };
    }

    // 4. Consumer-owned path-level permission.
    if let Some(pp) = &state.path_permissions {
        if let Some(target) = pp.path_permission(&method, &path) {
            return match check_owned_target(&state, &actor, &target).await {
                Ok(()) => next.run(req).await,
                Err(resp) => *resp,
            };
        }
    }

    // 5. Pass-through (handler is authoritative).
    next.run(req).await
}

/// Checks `(resource_type, action)` in the domain implied by `scope`.
///
/// On `require_active`:
/// - `TenantFromPath` → `resolve_active_tenant` (membership + status);
/// - `WorkspaceFromPath` → `resolve_active_workspace` (membership + parent
///   tenant status);
/// - `Platform` / `AuthenticatedOnly` → no resolution (no tenant/workspace
///   id to resolve).
///
/// On `!require_active`: `resolve_tenant` / `resolve_workspace` (membership
/// only). A suspended tenant remains readable.
async fn check_permission(
    state: &AxumAppState,
    actor: &AuthUser,
    scope: BindingScope,
    resource: &str,
    action: &str,
    require_active: bool,
    params: &HashMap<String, String>,
) -> Result<(), Box<Response>> {
    let domain: String = match scope {
        BindingScope::AuthenticatedOnly => return Ok(()),
        BindingScope::Platform => PLATFORM_DOMAIN.to_string(),
        BindingScope::TenantFromPath(name) => {
            let id = extract_uuid(params, name)?;
            let tenant = if require_active {
                saas::platform::resolve_active_tenant(&state.saas, actor, id)
                    .await
                    .map(|t| t.into_inner())
            } else {
                saas::platform::resolve_tenant(&state.saas, actor, id).await
            };
            tenant.map_err(|e| Box::new(map_core_error(e)))?;
            domain::tenant_domain(id)
        }
        BindingScope::WorkspaceFromPath(name) => {
            let id = extract_uuid(params, name)?;
            let ws = if require_active {
                saas::platform::resolve_active_workspace(&state.saas, actor, id)
                    .await
                    .map(|w| w.into_inner())
            } else {
                saas::platform::resolve_workspace(&state.saas, actor, id).await
            };
            ws.map_err(|e| Box::new(map_core_error(e)))?;
            domain::workspace_domain(id)
        }
    };
    check_owned_target(
        state,
        actor,
        &OwnedAuthzTarget {
            domain,
            resource: resource.to_string(),
            action: action.to_string(),
        },
    )
    .await
}

/// Checks `(domain, resource, action)` via `my_permissions`.
///
/// Read-only UX helper (`saas::access::my_permissions`) — the same one
/// `auth_layer` in `examples/axum-minimal` uses. The library `saas::*`
/// methods still call `authz.require` — `AuthLayer` is a *second* check.
async fn check_owned_target(
    state: &AxumAppState,
    actor: &AuthUser,
    target: &OwnedAuthzTarget,
) -> Result<(), Box<Response>> {
    let perms = saas::access::my_permissions(&state.saas, actor, &target.domain)
        .await
        .map_err(|e| {
            tracing::warn!(
                error = %e,
                domain = %target.domain,
                actor_id = %actor.id,
                "auth_layer: my_permissions failed"
            );
            Box::new(internal_error())
        })?;
    if perms
        .iter()
        .any(|(r, a)| r == &target.resource && a == &target.action)
    {
        Ok(())
    } else {
        Err(Box::new(forbidden()))
    }
}

fn extract_uuid(params: &HashMap<String, String>, name: &str) -> Result<Uuid, Box<Response>> {
    let raw = params.get(name).ok_or_else(|| {
        tracing::warn!(param = name, "auth_layer: missing path param");
        Box::new(internal_error())
    })?;
    Uuid::parse_str(raw).map_err(|e| {
        tracing::warn!(param = name, raw = %raw, error = %e, "auth_layer: invalid UUID path param");
        Box::new(bad_request())
    })
}

fn map_core_error(e: saas::CoreError) -> Response {
    use saas::CoreError::*;
    match e {
        Forbidden => forbidden(),
        TenantSuspended => (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": "tenant is suspended" })),
        )
            .into_response(),
        NotFound => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error": "not found" })),
        )
            .into_response(),
        Validation(msg) => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
        Unauthorized => unauthorized(),
        EmailNotVerified => (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": "email not verified" })),
        )
            .into_response(),
        Internal(_) | Db(_) => internal_error(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": "forbidden" })),
    )
        .into_response()
}

fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": "invalid path parameter" })),
    )
        .into_response()
}

fn internal_error() -> Response {
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
        // If the two lists diverge, csrf_guard and auth_layer disagree
        // about which endpoints are anonymous — that mismatch is a
        // security bug. The two lists must stay aligned.
        use crate::middleware::csrf::tests_support::public_auth_paths as csrf_paths;
        assert_eq!(PUBLIC_AUTH_PATHS, csrf_paths());
    }

    #[test]
    fn extract_uuid_parses_valid() {
        let mut p = HashMap::new();
        let id = Uuid::new_v4();
        p.insert("tenant_id".to_string(), id.to_string());
        assert_eq!(extract_uuid(&p, "tenant_id").unwrap(), id);
    }

    #[test]
    fn extract_uuid_rejects_missing() {
        let p = HashMap::new();
        let resp = extract_uuid(&p, "tenant_id").unwrap_err();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn extract_uuid_rejects_invalid() {
        let mut p = HashMap::new();
        p.insert("tenant_id".to_string(), "not-a-uuid".to_string());
        let resp = extract_uuid(&p, "tenant_id").unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn map_core_error_tenant_suspended_message() {
        let resp = map_core_error(saas::CoreError::TenantSuspended);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn map_core_error_not_found() {
        let resp = map_core_error(saas::CoreError::NotFound);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn map_core_error_internal() {
        let resp = map_core_error(saas::CoreError::Internal("boom".into()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
