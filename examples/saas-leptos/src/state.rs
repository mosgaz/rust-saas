#[cfg(feature = "ssr")]
use std::sync::Arc;

#[cfg(feature = "ssr")]
use authn::Authn;
#[cfg(feature = "ssr")]
use leptos::prelude::LeptosOptions;
#[cfg(feature = "ssr")]
use metrics_exporter_prometheus::PrometheusHandle;
#[cfg(feature = "ssr")]
use saas::SaasState;

#[cfg(feature = "ssr")]
use crate::cookie::CookieConfig;
#[cfg(feature = "ssr")]
use crate::email::EmailSender;
#[cfg(feature = "ssr")]
use rate_limiter::RateLimiter;

#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct AppState {
    pub authn: Arc<Authn>,
    pub saas: Arc<SaasState>,
    pub leptos_options: LeptosOptions,
    /// SMTP transport (real `SmtpEmailSender` when `SMTP_URL` is set;
    /// `NoopEmailSender` otherwise). `#[server]`-функции читают его через
    /// `AppState`; `None` здесь нет — `NoopEmailSender` уже даёт
    /// `EmailResult::Disabled`.
    pub email: Arc<dyn EmailSender>,
    /// Process-local rate limiter for email-verification requests
    /// (3 / 1 h per email — enforced in `#[server] request_email_verification`).
    /// Not distributed; see `rate_limit.rs` module docs.
    pub rate_limit: Arc<dyn RateLimiter>,
    /// Cookie policy (Secure/SameSite/Max-Age) resolved from env at startup
    /// (Stage 4.1b). Shared with `middleware::auto_refresh` and the auth
    /// handlers in `src/auth.rs`.
    pub cookie: Arc<CookieConfig>,
    /// Prometheus recorder handle (Stage 4.10). Set once in `main.rs` /
    /// `tests/e2e.rs` via `PrometheusBuilder::build_recorder()`;
    /// `/metrics` renders it.
    pub prometheus: PrometheusHandle,
}

#[cfg(feature = "ssr")]
impl axum::extract::FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}
