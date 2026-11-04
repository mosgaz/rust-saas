//! Route bindings: declarative path-level authorization (Stage 5.0-A4.3a).
//!
//! **Scope (this file, A4.3a):**
//! - [`RouteBinding`], [`BindingScope`], [`OwnedAuthzTarget`],
//!   [`PathPermissions`] — types (unchanged from A4.2).
//! - [`RouteBindings`] — matchit-based router; `resolve(method, path)`
//!   returns the matched binding + path params.
//! - [`built_in_bindings`] — the small set of public routes every
//!   consumer inherits. **Precedence:** built-in wins over custom
//!   (footgun fix; a consumer cannot accidentally make `/healthz`
//!   protected).
//! - [`validate`] — fail-fast helper called from
//!   [`crate::state::AxumAppStateBuilder::build`]: for every non-
//!   `AuthenticatedOnly` binding, `(resource, action)` must be present
//!   in `resource_types` ∪ `permissions`. Skipped for `without_rbac()`.
//!
//! **Layer order in `auth_layer` (A4.3a):** built-in public routes
//! (path prefix `healthz`/`readyz`/`metrics` + `PUBLIC_AUTH_PATHS`) →
//! `PathPermissions::is_public` → `RouteBindings::resolve` (built-in
//! bindings always win) → `PathPermissions::path_permission` →
//! pass-through. `require_active` bindings additionally call
//! `saas::platform::resolve_active_tenant` /
//! `resolve_active_workspace`; a suspended tenant returns
//! `403 tenant is suspended`.
//!
//! **`matchit` precedence.** Built-in bindings are inserted **first**;
//! user bindings are inserted **only if the path is free** in the
//! matchit `Router` (`InsertError::Conflict` → skip). This makes
//! built-in precedence structural, not a runtime check: a user cannot
//! shadow `/healthz` even by accident.
//!
//! **Why `OwnedAuthzTarget` returns owned strings.** A `PathPermissions`
//! impl may compute the domain from a path segment (`"tenant:{id}"`);
//! `&'static str` would force every impl to leak. `OwnedAuthzTarget`
//! owns `String`s; `PathPermissions::path_permission` is called at most
//! once per request.

use std::collections::{HashMap, HashSet};

use axum::http::Method;
use matchit::Router as MatchRouter;

// ─── Types (unchanged from A4.2) ──────────────────────────────────────────

/// Where the permission check gets its `domain` from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingScope {
    /// No permission check; only "actor is present" (`auth_layer` still
    /// requires a `CurrentUser`).
    AuthenticatedOnly,
    /// `domain = PLATFORM_DOMAIN`.
    Platform,
    /// `domain = tenant_domain(id)`; `id` is the named path segment.
    TenantFromPath(&'static str),
    /// `domain = workspace_domain(id)`; `id` is the named path segment.
    WorkspaceFromPath(&'static str),
}

/// One declarative binding: `(method, path)` → `(scope, resource, action)`
/// with a mutation-readiness flag.
#[derive(Debug, Clone)]
pub struct RouteBinding {
    pub method: Method,
    /// `matchit` 0.8 path pattern (`"/tenants/{tenant_id}/roles"`). See
    /// [`RouteBindings::new`] for the parameter syntax.
    pub path: &'static str,
    pub scope: BindingScope,
    /// `resource_type` in the `resource_types` registry.
    pub resource_type: &'static str,
    /// Action name in `permissions`.
    pub action: &'static str,
    pub require_active: bool,
}

impl RouteBinding {
    pub fn read(
        method: Method,
        path: &'static str,
        scope: BindingScope,
        resource_type: &'static str,
        action: &'static str,
    ) -> Self {
        Self {
            method,
            path,
            scope,
            resource_type,
            action,
            require_active: false,
        }
    }

    pub fn mutating(
        method: Method,
        path: &'static str,
        scope: BindingScope,
        resource_type: &'static str,
        action: &'static str,
    ) -> Self {
        Self {
            method,
            path,
            scope,
            resource_type,
            action,
            require_active: true,
        }
    }

    pub fn auth_only(method: Method, path: &'static str) -> Self {
        Self {
            method,
            path,
            scope: BindingScope::AuthenticatedOnly,
            resource_type: "",
            action: "",
            require_active: false,
        }
    }
}

/// A `(domain, resource, action)` tuple owned by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedAuthzTarget {
    pub domain: String,
    pub resource: String,
    pub action: String,
}

/// Consumer-supplied path-level permission source.
///
/// **Precedence:** `is_public` is consulted **after** built-in public
/// routes (`healthz`/`readyz`/`metrics` + `PUBLIC_AUTH_PATHS`) and
/// **before** `RouteBindings::resolve`. `path_permission` is consulted
/// **after** built-in + custom bindings; `Some` means "check this
/// `(domain, resource, action)` and skip custom bindings". `None` means
/// "fall through to custom bindings".
pub trait PathPermissions: Send + Sync {
    /// `true` if `(method, path)` is public (no actor required).
    fn is_public(&self, method: &Method, path: &str) -> bool;

    /// Path-level permission, or `None` for "no path-level check — fall
    /// through to custom `RouteBindings`".
    fn path_permission(&self, method: &Method, path: &str) -> Option<OwnedAuthzTarget>;
}

// ─── Built-in bindings (public routes; win over user bindings) ────────────

/// The public routes every `saas-axum` consumer inherits.
///
/// **Structural precedence.** `RouteBindings::new` inserts these first;
/// user bindings whose `(method, path)` collides with a built-in are
/// silently skipped. A user cannot accidentally make `/healthz`
/// protected by adding a binding — the built-in wins.
///
/// **Not in this list:**
/// - `/auth/refresh` — protected (requires an actor); the endpoint is
///   added in A4.4, so no built-in binding until then.
/// - Endpoints from A4.4 that require `(audit, read)` /
///   `(tenant, list|manage)` etc. — those are user bindings, not
///   built-in.
/// - Leptos `/_server/*` — `saas-axum` has no Leptos dependency.
pub fn built_in_bindings() -> Vec<RouteBinding> {
    vec![
        RouteBinding::auth_only(Method::GET, "/healthz"),
        RouteBinding::auth_only(Method::GET, "/readyz"),
        RouteBinding::auth_only(Method::GET, "/metrics"),
        RouteBinding::auth_only(Method::POST, "/auth/register"),
        RouteBinding::auth_only(Method::POST, "/auth/login"),
        RouteBinding::auth_only(Method::POST, "/auth/logout"),
    ]
}

// ─── RouteBindings (matchit-based) ────────────────────────────────────────

/// The set of active route bindings. Built-in bindings are prepended;
/// user bindings that collide with a built-in are skipped.
///
/// **Two representations:**
/// - `all: Vec<RouteBinding>` — flat list for `iter()` (used by
///   `AxumAppStateBuilder` for diagnostics and by `validate`).
/// - `routers: HashMap<Method, MatchRouter<usize>>` — index into `all`
///   for matching (one `matchit::Router` per HTTP method). `matchit` is
///   an O(path-length) match; no per-request allocation.
///
/// **`resolve` lifetime.** Returns `(&RouteBinding, HashMap<String, String>)`.
/// The binding is borrowed from `self.all`; the params map is owned
/// (extracted from `matchit::Match`). Callers that need only the
/// binding (no params) can use [`Self::resolve_only`].
pub struct RouteBindings {
    all: Vec<RouteBinding>,
    routers: HashMap<Method, MatchRouter<usize>>,
}

/// Result of [`RouteBindings::resolve`]: the matched binding (borrowed)
/// plus the extracted path params (owned).
pub struct ResolvedBinding<'a> {
    pub binding: &'a RouteBinding,
    pub params: HashMap<String, String>,
}

impl RouteBindings {
    /// Builds from user bindings. Built-in bindings are prepended;
    /// collisions (user path equals a built-in path for the same method)
    /// are silently skipped — built-in wins.
    ///
    /// **Path syntax.** `matchit` 0.8 / Axum 0.8: `{name}` for parameters,
    /// `*rest` for wildcard, **no** `:name` (that was matchit 0.7 /
    /// axum 0.7). A `:name` segment is treated as a literal and will never
    /// match a parameterised path — e.g. use `"/tenants/{tenant_id}/roles"`,
    /// not `"/tenants/:tenant_id/roles"`.
    pub fn new(user_bindings: Vec<RouteBinding>) -> Self {
        let mut all: Vec<RouteBinding> = built_in_bindings();
        let mut routers: HashMap<Method, MatchRouter<usize>> = HashMap::new();

        // Insert built-ins first (built-in precedence is structural: any
        // user binding that would collide is skipped below).
        for (i, b) in all.iter().enumerate() {
            let router = routers.entry(b.method.clone()).or_default();
            router.insert(b.path, i).expect(
                "built-in path collision — built_in_bindings() must not have duplicate paths",
            );
        }

        // Insert user bindings, skipping collisions.
        for b in user_bindings {
            let router = routers.entry(b.method.clone()).or_default();
            let idx = all.len();
            if router.insert(b.path, idx).is_ok() {
                all.push(b);
            }
            // On collision: drop the user binding (built-in wins).
        }

        Self { all, routers }
    }

    /// Empty set: only built-ins.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// `true` if there are no bindings at all (including built-ins).
    /// Note: this is almost always `false` (built-ins are always present).
    /// Kept for API symmetry; use [`Self::iter`] to inspect.
    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    /// Iterates over all active bindings (built-ins + non-colliding user
    /// bindings). Order: built-ins first, then user bindings in input
    /// order.
    pub fn iter(&self) -> impl Iterator<Item = &RouteBinding> {
        self.all.iter()
    }

    /// Resolves `(method, path)` to a binding + params, or `None` for an
    /// unbound path (pass-through).
    pub fn resolve(&self, method: &Method, path: &str) -> Option<ResolvedBinding<'_>> {
        let router = self.routers.get(method)?;
        let m = router.at(path).ok()?;
        let binding = &self.all[*m.value];
        let params = m
            .params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Some(ResolvedBinding { binding, params })
    }
}

impl std::fmt::Debug for RouteBindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteBindings")
            .field("bindings", &self.all)
            .finish()
    }
}

// ─── Fail-fast validation (called from AxumAppStateBuilder::build) ───────

/// Validates user bindings against `resource_types` ∪ `permissions`.
///
/// For every binding whose `scope != AuthenticatedOnly`, both
/// `resource_type` and `(resource_type, action)` must be present in the
/// registry / reference table. Built-in bindings are `AuthenticatedOnly`
/// and are not checked (they have no `resource`/`action`).
///
/// Called from [`AxumAppStateBuilder::build`] **after** bootstrap, so
/// custom types declared via `with_resource_types(...)` are already
/// visible in `resource_types` ∪ `permissions`. Skipped on
/// `without_rbac()` builds (`access.is_none()`).
///
/// `Err(String)` — message names the offending binding so the operator
/// can fix `with_binding(...)`. The caller wraps it in
/// `AppError::Core(CoreError::Validation(_))`.
pub fn validate(
    user_bindings: &[RouteBinding],
    resource_types: &HashSet<String>,
    permissions: &HashSet<(String, String)>,
) -> Result<(), String> {
    for b in user_bindings {
        if matches!(b.scope, BindingScope::AuthenticatedOnly) {
            continue;
        }
        if !resource_types.contains(b.resource_type) {
            return Err(format!(
                "unknown resource_type `{}` in binding {} {} — \
                 declare it with `with_resource_types(...)` first",
                b.resource_type, b.method, b.path
            ));
        }
        let pair = (b.resource_type.to_string(), b.action.to_string());
        if !permissions.contains(&pair) {
            return Err(format!(
                "unknown permission `{}:{}` in binding {} {} — \
                 add it via `bootstrap_resource_type` (default_actions) \
                 or `register_resource_type`",
                b.resource_type, b.action, b.method, b.path
            ));
        }
    }
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_scope(rt: &'static str) -> BindingScope {
        if rt.is_empty() {
            BindingScope::AuthenticatedOnly
        } else {
            BindingScope::Platform
        }
    }

    fn perm_set(items: &[(&str, &str)]) -> HashSet<(String, String)> {
        items
            .iter()
            .map(|(r, a)| (r.to_string(), a.to_string()))
            .collect()
    }

    fn rt_set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn built_ins_are_present_by_default() {
        let rb = RouteBindings::empty();
        let paths: Vec<&str> = rb.iter().map(|b| b.path).collect();
        assert!(paths.contains(&"/healthz"));
        assert!(paths.contains(&"/readyz"));
        assert!(paths.contains(&"/metrics"));
        assert!(paths.contains(&"/auth/register"));
        assert!(paths.contains(&"/auth/login"));
        assert!(paths.contains(&"/auth/logout"));
    }

    #[test]
    fn user_binding_is_added() {
        let rb = RouteBindings::new(vec![RouteBinding::read(
            Method::GET,
            "/tenants/{tenant_id}/roles",
            BindingScope::TenantFromPath("tenant_id"),
            "role",
            "list",
        )]);
        let resolved = rb
            .resolve(&Method::GET, "/tenants/abc/roles")
            .expect("must match");
        assert_eq!(resolved.binding.path, "/tenants/{tenant_id}/roles");
        assert_eq!(
            resolved.params.get("tenant_id").map(String::as_str),
            Some("abc")
        );
    }

    #[test]
    fn built_in_wins_over_user_collision() {
        // User tries to shadow `/healthz` with a custom binding.
        let rb = RouteBindings::new(vec![RouteBinding::read(
            Method::GET,
            "/healthz",
            BindingScope::Platform,
            "tenant",
            "list",
        )]);
        let resolved = rb.resolve(&Method::GET, "/healthz").expect("must match");
        // The matched binding is the built-in `auth_only`, not the user
        // `Platform` one.
        assert!(matches!(
            resolved.binding.scope,
            BindingScope::AuthenticatedOnly
        ));
    }

    #[test]
    fn unknown_path_returns_none() {
        let rb = RouteBindings::new(Vec::new());
        assert!(rb.resolve(&Method::GET, "/nonexistent").is_none());
    }

    #[test]
    fn wrong_method_returns_none() {
        let rb = RouteBindings::new(Vec::new());
        // `/healthz` is GET-only.
        assert!(rb.resolve(&Method::POST, "/healthz").is_none());
    }

    #[test]
    fn validate_accepts_known_permission() {
        let b = RouteBinding::read(
            Method::GET,
            "/tenants/{id}/roles",
            BindingScope::TenantFromPath("id"),
            "role",
            "list",
        );
        let rts = rt_set(&["role", "tenant"]);
        let perms = perm_set(&[("role", "list")]);
        assert!(validate(&[b], &rts, &perms).is_ok());
    }

    #[test]
    fn validate_rejects_unknown_resource_type() {
        let b = RouteBinding::read(Method::GET, "/x", BindingScope::Platform, "nope", "read");
        let rts = rt_set(&["role"]);
        let perms = perm_set(&[]);
        let err = validate(&[b], &rts, &perms).unwrap_err();
        assert!(err.contains("unknown resource_type `nope`"), "got {err}");
    }

    #[test]
    fn validate_rejects_unknown_permission() {
        let b = RouteBinding::read(Method::GET, "/x", BindingScope::Platform, "role", "nope");
        let rts = rt_set(&["role"]);
        let perms = perm_set(&[("role", "list")]);
        let err = validate(&[b], &rts, &perms).unwrap_err();
        assert!(err.contains("unknown permission `role:nope`"), "got {err}");
    }

    #[test]
    fn validate_skips_authenticated_only() {
        let b = RouteBinding::auth_only(Method::GET, "/whoami");
        let rts = rt_set(&[]);
        let perms = perm_set(&[]);
        assert!(validate(&[b], &rts, &perms).is_ok());
    }

    #[test]
    fn mk_scope_helper() {
        assert!(matches!(mk_scope(""), BindingScope::AuthenticatedOnly));
        assert!(matches!(mk_scope("role"), BindingScope::Platform));
    }
}
