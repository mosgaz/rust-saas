//! Middleware stack for `saas-axum`.
//!
//! Three submodules, each portable from `examples/axum-minimal` (with
//! `State<Arc<AppState>>` replaced by `State<Arc<AxumAppState>>`):
//!
//! - [`auto_refresh`] — verify access JWT, rotate refresh token on expiry.
//!   Inserts `Extension<Option<AuthUser>>`; [`crate::extract::CurrentUser`]
//!   reads it.
//! - [`csrf`] — double-submit CSRF (`csrf` cookie + `X-CSRF-Token` header).
//!   `csrf_issue` on the public router; `csrf_guard` on the protected
//!   router.
//! - [`auth_layer`] — 401 for anonymous requests on the protected router.
//!   In PR-1 it is 401-only; path-level permissions (via
//!   [`crate::bindings::RouteBindings`] + [`crate::bindings::PathPermissions`])
//!   are A4.3a.
//!
//! **PR-1 wiring:** none of these are attached to `build_app` yet — that
//! happens in A4.3b (see `router.rs` module docs). The modules exist here
//! so the shape of the middleware stack is stable before wiring; A4.3b is
//! then three `.route_layer(...)` calls plus tests.
//!
//! **Design constraint:** each middleware takes
//! `State<Arc<AxumAppState>>` (not `State<(Arc<Authn>, Arc<CookieConfig>)>`
//! as `examples/saas-leptos` does). The adapter has one state type; a
//! tuple state would force every handler to know about the split. The
//! `AxumAppState` is cheap to clone (`Arc`-wrapped fields).

pub mod auth_layer;
pub mod auto_refresh;
pub mod csrf;
