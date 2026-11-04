//! Axum HTTP adapter for `rust-saas` (Stage 5.0-A4).
//!
//! Internal crate: consumer-facing entry is `rust-saas = { features = ["axum"] }`
//! (see `crates/rust-saas/src/lib.rs`). `saas-axum` is not a public
//! dependency of any consumer; it exists so `rust-saas` can re-export
//! `AxumAppState`, `AxumAppStateBuilder`, `build_app`, and the supporting
//! types under one Cargo entry.
//!
//! **Stage 5.0-A4 scope (PR-1, this crate's skeleton):**
//! - `state` — `AxumAppState` + `AxumAppStateBuilder` (`build()` — A4.2).
//! - `router` — `build_app(state)` skeleton: `/healthz` + `TraceLayer`
//!   + 404 fallback.
//! - `bindings` — `RouteBinding` / `BindingScope` / `RouteBindings`
//!   (matching + `PathPermissions` precedence — A4.3a).
//! - `cookie` — `CookieConfig`.
//! - `error` — `AppError` + `IntoResponse`.
//! - `extract` — `CurrentUser` via `axum::extract::FromRequestParts`.
//! - `health` — `/healthz`, `/readyz`, `/metrics`.
//! - `pagination` — `PaginationQuery::clamp`.
//! - `middleware` — `auto_refresh`, `csrf_guard`, `auth_layer`
//!   (wiring — A4.3b).
//!
//! **Not in PR-1 (deferred):** `PathPermissions` precedence (A4.3a),
//! endpoints `/auth/*` / `/my_permissions` / `/resource_types` (A4.4),
//! `examples/axum-minimal` migration (A6), `examples/minimal-lms` (A5),
//! `saas-leptos` single-dependency (A7').
//!
//! **Design constraint.** No `leptos*`. No `lettre`. `saas-axum` is
//! `axum` + `tower-http` + `sqlx` + the `rust-saas` library crates.

pub mod bindings;
pub mod cookie;
pub mod email;
pub mod endpoints;
pub mod error;
pub mod extract;
pub mod health;
pub mod middleware;
pub mod pagination;
pub mod router;
pub mod state;

pub use bindings::{BindingScope, OwnedAuthzTarget, PathPermissions, RouteBinding, RouteBindings};
pub use cookie::CookieConfig;
pub use email::{EmailResult, EmailSender, NoopEmailSender};
pub use endpoints::auth::{login, logout, refresh, register, RegisterRequest, RegisterResponse};
pub use endpoints::my_permissions::{
    my_permissions_flat, my_permissions_grouped, MyPermissionsQuery,
};
pub use endpoints::resource_types::{resource_types, ResourceTypeView};
pub use error::AppError;
pub use extract::CurrentUser;
pub use router::{build_app, build_app_full, build_app_full_with, build_app_with_protected};
pub use state::{AxumAppState, AxumAppStateBuilder};
