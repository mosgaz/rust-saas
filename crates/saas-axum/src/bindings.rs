//! Route bindings: declarative path-level authorization (Stage 5.0-A4.3a).
//!
//! **PR-1 scope (this file, Stage 5.0-A4.2):** types only. `RouteBinding`,
//! `BindingScope`, `RouteBindings`, `OwnedAuthzTarget`, `PathPermissions`.
//! No matching, no precedence, no fail-fast (those are A4.3a). `build()`
//! in [`crate::state::AxumAppStateBuilder`] stores `Arc<RouteBindings>`
//! verbatim; it does not interpret the bindings.
//!
//! **A4.3a will add** (do not add here):
//! - `RouteBindings::resolve(&Method, &str) -> Option<&RouteBinding>`
//!   (matchit-based matching, `BuiltinPrecedence` — built-in bindings win
//!   over `PathPermissions`, which wins over custom bindings, which wins
//!   over pass-through);
//! - fail-fast in `build()` for `(resource_type, action)` not declared in
//!   `resource_types` ∪ `permissions` (skipped for `AuthenticatedOnly`);
//! - `auth_layer` wiring that consults `RouteBindings` + `PathPermissions`.
//!
//! **Why declare the types now.** `AxumAppState` stores
//! `Arc<RouteBindings>` (see `state.rs`); `build()` cannot compile without
//! a `RouteBindings` type. Declaring types now keeps the state struct
//! complete and lets A4.3a land as a pure-logic addition without a
//! breaking change to `AxumAppState`.
//!
//! **`Method`.** We use `axum::http::Method` (re-export of `http::Method`)
//! — same type `Router::route` expects. Storing a `Method` in a `const`
//! is not possible (`Method::GET` is `Method`, not `&'static Method`),
//! so `RouteBinding` owns its `Method` (`Method: Clone + Eq + Hash`).

use std::collections::HashMap;

use axum::http::Method;

/// Where the permission check gets its `domain` from.
///
/// - `AuthenticatedOnly` — no permission check; only "actor is present"
///   (the `auth_layer` still requires a `CurrentUser`).
/// - `Platform` — `domain = PLATFORM_DOMAIN`.
/// - `TenantFromPath(&'static str)` — `domain = tenant_domain(id)`; `id`
///   is the named path segment (e.g. `"tenant_id"` in
///   `"/tenants/:tenant_id/roles"`).
/// - `WorkspaceFromPath(&'static str)` — `domain = workspace_domain(id)`;
///   `id` is the named path segment (e.g. `"workspace_id"` in
///   `"/workspaces/:workspace_id/documents"`).
///
/// A4.3a's `auth_layer` resolves the path via `matchit::Router` and pulls
/// the named parameter; in PR-1, `BindingScope` is inert data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingScope {
    AuthenticatedOnly,
    Platform,
    TenantFromPath(&'static str),
    WorkspaceFromPath(&'static str),
}

/// One declarative binding: `(method, path)` → `(scope, resource, action)`
/// with a mutation-readiness flag.
///
/// `require_active` distinguishes read-only (`false`) from mutating
/// (`true`) endpoints: mutating endpoints require `resolve_active_tenant` /
/// `resolve_active_workspace` (a suspended tenant returns `403
/// tenant is suspended`); reads do not (ADR-0002 rev.2 §2.4).
///
/// Construction is via [`RouteBinding::read`], [`RouteBinding::mutating`],
/// or [`RouteBinding::auth_only`]. Field access is public for tests and for
/// A4.3a's `RouteBindings::resolve`.
#[derive(Debug, Clone)]
pub struct RouteBinding {
    pub method: Method,
    /// `matchit`-style path pattern (`"/tenants/:tenant_id/roles"`).
    pub path: &'static str,
    pub scope: BindingScope,
    /// `resource_type` in the `resource_types` registry (e.g. `"role"`).
    /// Empty string for `AuthenticatedOnly`.
    pub resource_type: &'static str,
    /// Action name in `permissions` (e.g. `"list"`). Empty for
    /// `AuthenticatedOnly`.
    pub action: &'static str,
    pub require_active: bool,
}

impl RouteBinding {
    /// Read-only binding: `require_active = false`. A suspended tenant
    /// still allows the read (ADR-0002 rev.2 §2.4).
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

    /// Mutating binding: `require_active = true`. A suspended tenant
    /// returns `403 tenant is suspended` before the handler runs.
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

    /// Auth-only binding: actor is required, no permission check.
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
///
/// `PathPermissions::path_permission` returns this (strings are owned,
/// not `&'static`, because a `PathPermissions` impl may compute the domain
/// from the path — e.g. `"tenant:uuid"` from `/:tenant_id/...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedAuthzTarget {
    pub domain: String,
    pub resource: String,
    pub action: String,
}

/// Consumer-supplied path-level permission source (A4.3a).
///
/// `auth_layer` consults it **after** built-in bindings (built-in wins —
/// footgun fix; see A4.3a and Appendix B) and **before** custom
/// `RouteBindings`. A consumer that needs a path-dependent domain
/// (e.g. `"tenant:{id}"` computed from a path segment) implements this
/// trait; the default `RouteBindings` path handles the static cases.
///
/// In PR-1 the trait is declared (so `AxumAppState` can hold
/// `Option<Arc<dyn PathPermissions>>`); the `auth_layer` that calls it
/// arrives in A4.3a.
pub trait PathPermissions: Send + Sync {
    /// `true` if `(method, path)` is public (no actor required).
    ///
    /// **Precedence:** consulted only for paths **not** matched by a
    /// built-in binding; built-in bindings always run. See A4.3a.
    fn is_public(&self, method: &Method, path: &str) -> bool;

    /// Path-level permission, or `None` for "no path-level check — fall
    /// through to custom `RouteBindings`". `Some` means "require this
    /// `(domain, resource, action)`; do not consult custom bindings".
    fn path_permission(&self, method: &Method, path: &str) -> Option<OwnedAuthzTarget>;
}

/// A set of [`RouteBinding`]s.
///
/// **PR-1:** stores the bindings verbatim; exposes `new` / `empty` /
/// `is_empty` / `iter`. `resolve` (matching by `matchit`) — A4.3a.
///
/// The `HashMap<Method, Vec<RouteBinding>>` is a placeholder for the
/// eventual matchit router; A4.3a replaces the body without changing the
/// public API (`iter` stays, `resolve` is added). The field is private so
/// the representation can change without a semver event.
#[derive(Debug, Clone, Default)]
pub struct RouteBindings {
    by_method: HashMap<Method, Vec<RouteBinding>>,
}

impl RouteBindings {
    /// Builds from a flat `Vec<RouteBinding>`.
    pub fn new(bindings: Vec<RouteBinding>) -> Self {
        let mut by_method: HashMap<Method, Vec<RouteBinding>> = HashMap::new();
        for b in bindings {
            by_method.entry(b.method.clone()).or_default().push(b);
        }
        Self { by_method }
    }

    /// Empty set (no bindings). Used by `AxumAppStateBuilder::build()`
    /// when no `with_binding(s)` calls were made.
    pub fn empty() -> Self {
        Self::default()
    }

    /// `true` if there are no bindings.
    pub fn is_empty(&self) -> bool {
        self.by_method.values().all(|v| v.is_empty())
    }

    /// Iterates over all bindings (any method). Order is unspecified —
    /// callers that need deterministic order sort by `(path, method)`
    /// themselves.
    pub fn iter(&self) -> impl Iterator<Item = &RouteBinding> {
        self.by_method.values().flat_map(|v| v.iter())
    }
}
