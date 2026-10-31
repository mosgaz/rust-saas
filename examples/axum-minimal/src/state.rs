//! Shared application state for `axum-minimal` (Stage 3g).
//!
//! Mirrors `examples/saas-leptos/src/state.rs` with two deliberate
//! differences:
//!
//! - **No `LeptosOptions` field.** There is no Leptos in `axum-minimal`.
//! - **No `#[cfg(feature = "ssr")]` gating.** `axum-minimal` is a single
//!   binary, SSR-only, with no hydration target.
//!
//! The `config` field that plan §4 lists is intentionally absent: nothing
//! in the 3g endpoint set needs a config object (`BIND_ADDR` is read in
//! `main.rs`, `JWT_SECRET` is consumed by `Authn`, `SMTP_URL` is moot
//! without an SMTP transport). Keeping the struct minimal keeps the
//! portability proof honest — every field here is actually used by a
//! handler.
//!
//! `FromRef` implementations let handlers extract individual pieces
//! (`State<Arc<Authn>>`, `State<Arc<SaasState>>`, …) when that is more
//! convenient than `State<Arc<AppState>>`. The reference handlers all take
//! `State<Arc<AppState>>`; the impls are kept for parity with
//! `saas-leptos` and for consumer flexibility.

use std::sync::Arc;

use authn::Authn;
use saas::SaasState;

use crate::email::EmailSender;
use crate::rate_limit::SimpleRateLimiter;

/// Process-wide state, cloned into every request handler.
///
/// Cheap to clone (`Arc` everywhere). The same `PgPool` is shared by
/// `authn`, `saas`, and the audit logger (Stage 2d: one pool per process);
/// `AppState` does not carry the pool directly — it is owned by `Authn`
/// and `SaasState` and reachable via `state.saas.pool()`.
#[derive(Clone)]
pub struct AppState {
    /// Authentication mechanism: Argon2, JWT access, opaque refresh,
    /// rotation with grace window, email verification.
    pub authn: Arc<Authn>,

    /// Business logic: platform / tenant / workspace / invitation /
    /// member / access services, plus `resolve_active_tenant` and
    /// `ActiveTenant` (Stage 3f).
    pub saas: Arc<SaasState>,

    /// `NoopEmailSender` in 3g (no SMTP transport). The trait exists so a
    /// future consumer can plug in a real sender without changing
    /// `AppState`.
    pub email: Arc<dyn EmailSender>,

    /// In-memory rate limiter; used by `POST /auth/register`
    /// (3 / 1 h per email). Process-local; not distributed (see
    /// `rate_limit.rs`).
    pub rate_limit: Arc<SimpleRateLimiter>,
}

impl axum::extract::FromRef<AppState> for Arc<Authn> {
    fn from_ref(state: &AppState) -> Self {
        state.authn.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<SaasState> {
    fn from_ref(state: &AppState) -> Self {
        state.saas.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<dyn EmailSender> {
    fn from_ref(state: &AppState) -> Self {
        state.email.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<SimpleRateLimiter> {
    fn from_ref(state: &AppState) -> Self {
        state.rate_limit.clone()
    }
}