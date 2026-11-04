//! Compile-only test: the `axum` feature exposes the expected API under
//! `rust_saas::*`.
//!
//! Does not run a server, does not touch a DB. Its value is "if this
//! test compiles, the public surface promised by Stage 5.0-A4.0 exists."
//! Behaviour (state construction, routing, bindings) is tested in
//! `saas-axum`'s own `tests/state.rs` and in the E2E suites of
//! `examples/axum-minimal` (once A6 migrates it onto `saas-axum`).
//!
//! Guarded by `#[cfg(feature = "axum")]` so `cargo test -p rust-saas`
//! (without `--features axum`) compiles an empty test binary — no
//! accidental build of the whole adapter stack.

#![cfg(feature = "axum")]

// Re-import every re-exported symbol — the `use` statement itself is the
// assertion. Unused-import warnings are silenced to keep the file
// readable; the compiler still errors if a name is missing.
#[allow(unused_imports)]
use rust_saas::{
    build_app, AppError, AxumAppState, AxumAppStateBuilder, BindingScope, CookieConfig,
    CurrentUser, EmailResult, EmailSender, NoopEmailSender, OwnedAuthzTarget, PathPermissions,
    RouteBinding, RouteBindings,
};

#[test]
fn axum_feature_reexports_compile() {
    // Type-level assertion: every re-exported name has the expected kind.
    // `const _:` is not possible for all of them (traits, generic
    // functions), so `_ = ... as _` plus explicit `fn`-typed bindings.
    let _: fn(sqlx::PgPool, String) -> AxumAppStateBuilder = AxumAppStateBuilder::new;
    let _: fn(sqlx::PgPool, String) -> AxumAppStateBuilder = AxumAppState::builder;
    let _: fn(std::sync::Arc<AxumAppState>) -> axum::Router = build_app;
    let _: fn(axum::http::Method, &'static str) -> RouteBinding = RouteBinding::auth_only;
    let _: fn(Vec<RouteBinding>) -> RouteBindings = RouteBindings::new;
    let _: fn() -> RouteBindings = RouteBindings::empty;
    let _: BindingScope = BindingScope::Platform;

    // `CookieConfig` is a struct with public fields; construct one.
    let _ = CookieConfig {
        secure: false,
        access_ttl: chrono::TimeDelta::minutes(1),
        refresh_ttl: chrono::TimeDelta::days(1),
    };

    // Trait objects: `Arc<dyn EmailSender>` and `Arc<dyn PathPermissions>`
    // must be constructible from `NoopEmailSender` and any impl.
    let _: std::sync::Arc<dyn EmailSender> = std::sync::Arc::new(NoopEmailSender);
    let _: Option<std::sync::Arc<dyn PathPermissions>> = None;

    // DTOs / errors are exported by value or by type.
    let _: Option<EmailResult> = None;
    let _: Option<AppError> = None;
    let _: Option<OwnedAuthzTarget> = None;
    let _: Option<CurrentUser> = None;
}
