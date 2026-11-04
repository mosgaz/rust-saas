//! Meta-crate: a single Cargo entry over the eleven `rust-saas` library
//! crates (Stage 4.0, Variant A — opt-in).
//!
//! The reference examples (`examples/saas-leptos`, `examples/axum-minimal`)
//! keep their per-crate `path = "../../crates/*"` dependencies on purpose:
//! Stage 3g's portability proof is about *the individual crates* composing,
//! not about a single façade. External consumers who want one Cargo entry
//! can depend on `rust-saas = { ..., features = ["ssr"] }` instead.
//!
//! Feature matrix:
//! - `default`  — `domain` (pure types) + `authz` + `audit` (trait-only).
//!   No `sqlx`. Suitable for a WASM-only consumer.
//! - `hydrate`  — same as `default`; named feature for parity with
//!   `saas-leptos` Cargo manifests.
//! - `ssr`      — `default` + `domain/ssr` (sqlx derives) + every
//!   sqlx-backed crate (`access`, `authz-casbin`, `identity`, `authn`,
//!   `saas`, `db`, `audit-pg`).
//!
//! The crate is deliberately empty apart from re-exports; it adds no
//! behavior and no dependency that the individual crates do not already
//! pull in. Removing it is a Cargo.toml-only change for any consumer.

pub use audit;
pub use authz;
pub use domain;
pub use rate_limiter;

#[cfg(feature = "ssr")]
pub use access;
#[cfg(feature = "ssr")]
pub use audit_pg;
#[cfg(feature = "ssr")]
pub use authn;
#[cfg(feature = "ssr")]
pub use authz_casbin;
#[cfg(feature = "ssr")]
pub use db;
#[cfg(feature = "ssr")]
pub use identity;
#[cfg(feature = "ssr")]
pub use saas;

// ── Stage 5.0-A4.0: `axum` feature ────────────────────────────────────────
//
// Re-exports `saas-axum` (internal Axum HTTP adapter) under one feature
// flag. Enabled together with `ssr`; the adapter is server-only.
//
// **Consumer surface.** The adapter is an internal crate; consumers pull
// `rust-saas = { features = ["axum"] }` and get everything they need from
// `rust_saas::*`. `saas-axum` itself is not a dependency of any consumer.
#[cfg(feature = "axum")]
pub use saas_axum;
#[cfg(feature = "axum")]
pub use saas_axum::{
    build_app, build_app_full, build_app_full_with, build_app_with_protected, AppError,
    AxumAppState, AxumAppStateBuilder, BindingScope, CookieConfig, CurrentUser, EmailResult,
    EmailSender, NoopEmailSender, OwnedAuthzTarget, PathPermissions, RouteBinding, RouteBindings,
};

/// Applies the workspace-wide migration set (`crates/db/migrations/`).
///
/// Thin wrapper over [`db::migrate`]; the name is the
/// `saas-external-02.md` §5.2 quick-start entry point for an Axum
/// consumer with **no** custom migrations.
///
/// ```ignore
/// let pool = db::connect(&url).await?;
/// rust_saas::migrate_all(&pool).await?;
/// ```
#[cfg(feature = "ssr")]
pub async fn migrate_all(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    db::migrate_composed(pool, &[]).await
}

/// Applies the workspace-wide migration set **plus** one consumer
/// migrator.
///
/// The consumer migrator must:
/// - use versions **greater than** `db::MIGRATOR`'s max (see
///   [`db::CONSUMER_VERSION_FLOOR`], `90000000000000`);
/// - not reuse any rust-saas version (collision is a hard error).
///
/// See [`db::migrate_composed`] for the full contract.
///
/// ```ignore
/// static MY_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
///
/// let pool = db::connect(&url).await?;
/// rust_saas::migrate_extended(&pool, &MY_MIGRATOR).await?;
/// ```
#[cfg(feature = "ssr")]
pub async fn migrate_extended(
    pool: &sqlx::PgPool,
    consumer: &sqlx::migrate::Migrator,
) -> anyhow::Result<()> {
    db::migrate_composed(pool, &[consumer]).await
}
