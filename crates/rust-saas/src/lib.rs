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
pub use rate_limiter;
pub use domain;

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
