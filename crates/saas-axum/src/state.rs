//! Shared application state for `saas-axum` (Stage 5.0-A4).
//!
//! [`AxumAppState`] is the process-wide state passed to every handler via
//! `State<Arc<AxumAppState>>`. [`AxumAppStateBuilder`] wires the
//! `rust-saas` library crates: `authz` (Casbin), `audit` (PgAuditLogger),
//! `access` (AccessState, optional), `authn` (Authn with TTLs), `saas`
//! (SaasState via `SaasBuilder`).
//!
//! **`build()` steps** (plan §A4.2):
//! 1. `CasbinAuthz::from_pool` — authz.
//! 2. `PgAuditLogger::from_pool` (unless overridden via `with_audit`).
//! 3. `AccessState` (unless `without_rbac()`).
//! 4. `Authn::with_ttl(...).with_audit(...)`.
//! 5. `SaasBuilder::new(pool).with_authz(authz).with_audit(audit)` +
//!    `with_access(access)` / `without_access()`.
//! 6. `access::registry::bootstrap_all_core` (idempotent; only when
//!    `access` is `Some`).
//! 7. `access::registry::bootstrap_resource_types(&custom_types)` (only
//!    if `with_resource_types(...)` was called; only when `access` is
//!    `Some`).
//! 8. `RouteBindings::new(user_bindings)` — no built-in bindings, no
//!    fail-fast (those are A4.3a).
//! 9. `CookieConfig` (defaults from `127.0.0.1:3395` + `COOKIE_SECURE`
//!    env; a deploying consumer sets `COOKIE_SECURE=1` or uses
//!    `with_cookie(...)`).
//! 10. `NoopEmailSender` / `InMemoryRateLimiter` defaults.
//!
//! **`without_rbac()`** skips steps 3, 6, 7 — matches
//! `SaasBuilder::without_access`. The resulting `AxumAppState.access` is
//! `None`, `SaasState::access()` returns `Internal("RBAC not configured")`,
//! and `bootstrap_*` never runs. `authz` is still required (low-level
//! methods call `authz.require`).
//!
//! **Not in PR-1 (A4.3a):** `PathPermissions` matching, built-in binding
//! precedence, fail-fast for undeclared `(resource, action)`. The
//! `bindings` field stores user bindings verbatim; `path_permissions` is
//! stored as-is.

use std::net::SocketAddr;
use std::sync::Arc;

use access::{AccessState, ResourceType};
use audit::AuditLogger;
use audit_pg::PgAuditLogger;
use authn::Authn;
use authz::AuthorizationEngine;
use authz_casbin::CasbinAuthz;
use axum::http::Extensions;
use chrono::TimeDelta;
use metrics_exporter_prometheus::PrometheusHandle;
use rate_limiter::RateLimiter;
use saas::{CoreError, SaasBuilder, SaasState};

use crate::bindings::{PathPermissions, RouteBinding, RouteBindings};
use crate::cookie::CookieConfig;
use crate::email::{EmailSender, NoopEmailSender};
use crate::error::AppError;

/// Process-wide state for `saas-axum`. Cheap to clone via `Arc`; every
/// field is either `Arc` or a small value (`Extensions` — `Clone` if all
/// inserted values are, `Clone + Send + Sync + 'static`).
pub struct AxumAppState {
    /// Authentication mechanism (Argon2, JWT access, opaque refresh).
    pub authn: Arc<Authn>,

    /// Business logic: platform / tenant / workspace / invitation / member /
    /// access services, `resolve_active_tenant`, `ActiveTenant`.
    pub saas: Arc<SaasState>,

    /// Authorization engine (Casbin). Shared with `access` and `saas`.
    /// Cloned into `AxumAppState` so consumers that do not use RBAC
    /// (`without_rbac()`) still reach the engine directly.
    pub authz: Arc<dyn AuthorizationEngine>,

    /// Role/permission state (`None` iff built via `without_rbac()`).
    /// Mirrors `SaasState::access()` but avoids the `Result` when the
    /// consumer explicitly opted out.
    pub access: Option<Arc<AccessState>>,

    /// Email transport. `NoopEmailSender` by default; `SmtpEmailSender`
    /// stays consumer-local (not in `saas-axum`).
    pub email: Arc<dyn EmailSender>,

    /// Rate limiter. `InMemoryRateLimiter` by default; `RedisRateLimiter`
    /// via `with_rate_limit(Arc::new(RedisRateLimiter::from_url(...)))`.
    pub rate_limit: Arc<dyn RateLimiter>,

    /// Cookie policy (`Secure` / `SameSite` / `Max-Age`).
    pub cookie: Arc<CookieConfig>,

    /// Prometheus recorder handle (if `with_prometheus` was called).
    /// `/metrics` renders it; `None` → `404` on `/metrics` (A4.3b).
    pub prometheus: Option<PrometheusHandle>,

    /// Route bindings (declarative path-level authorization). Matching and
    /// precedence — A4.3a. PR-1 stores them verbatim.
    pub bindings: Arc<RouteBindings>,

    /// Consumer-supplied path-level permission source (A4.3a).
    pub path_permissions: Option<Arc<dyn PathPermissions>>,

    /// Free-form per-app extensions (available to consumer handlers via
    /// `req.extensions()`). Empty unless `with_extension(...)` was called.
    pub extensions: Extensions,
}

impl AxumAppState {
    /// Entry-point: `AxumAppState::builder(pool, "jwt-secret").build().await`.
    pub fn builder(pool: sqlx::PgPool, jwt_secret: impl Into<String>) -> AxumAppStateBuilder {
        AxumAppStateBuilder::new(pool, jwt_secret)
    }
}

/// Builder for [`AxumAppState`]. See module docs for the full `build()`
/// sequence. Every setter is optional; defaults are documented on each
/// method.
pub struct AxumAppStateBuilder {
    pool: sqlx::PgPool,
    jwt_secret: String,
    access_ttl: Option<TimeDelta>,
    refresh_ttl: Option<TimeDelta>,
    audit: Option<Arc<dyn AuditLogger>>,
    email: Option<Arc<dyn EmailSender>>,
    rate_limit: Option<Arc<dyn RateLimiter>>,
    cookie: Option<CookieConfig>,
    prometheus: Option<PrometheusHandle>,
    bindings: Vec<RouteBinding>,
    path_permissions: Option<Arc<dyn PathPermissions>>,
    resource_types: Vec<ResourceType>,
    access_skipped: bool,
    extensions: Extensions,
}

impl AxumAppStateBuilder {
    /// `pool` and `jwt_secret` are required; everything else has a default.
    pub fn new(pool: sqlx::PgPool, jwt_secret: impl Into<String>) -> Self {
        Self {
            pool,
            jwt_secret: jwt_secret.into(),
            access_ttl: None,
            refresh_ttl: None,
            audit: None,
            email: None,
            rate_limit: None,
            cookie: None,
            prometheus: None,
            bindings: Vec::new(),
            path_permissions: None,
            resource_types: Vec::new(),
            access_skipped: false,
            extensions: Extensions::new(),
        }
    }

    /// Overrides the default access / refresh token TTLs
    /// (`15 min` / `30 days`, matching `authn::DEFAULT_*`).
    pub fn with_ttl(mut self, access: TimeDelta, refresh: TimeDelta) -> Self {
        self.access_ttl = Some(access);
        self.refresh_ttl = Some(refresh);
        self
    }

    /// Overrides the default `PgAuditLogger` with a consumer-supplied logger
    /// (e.g. `NoopAuditLogger` in tests, `PgAuditLogger` with a custom pool).
    pub fn with_audit(mut self, audit: Arc<dyn AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Overrides the default `NoopEmailSender`.
    pub fn with_email(mut self, email: Arc<dyn EmailSender>) -> Self {
        self.email = Some(email);
        self
    }

    /// Overrides the default `InMemoryRateLimiter`. Pass
    /// `Arc::new(RedisRateLimiter::from_url(&url).await?)` for a
    /// distributed limiter.
    pub fn with_rate_limit(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.rate_limit = Some(limiter);
        self
    }

    /// Overrides the default `CookieConfig` (env-derived from
    /// `127.0.0.1:3395` + `COOKIE_SECURE`).
    pub fn with_cookie(mut self, cookie: CookieConfig) -> Self {
        self.cookie = Some(cookie);
        self
    }

    /// Installs a Prometheus recorder handle. `/metrics` renders it; without
    /// this call `/metrics` returns `404`.
    pub fn with_prometheus(mut self, handle: PrometheusHandle) -> Self {
        self.prometheus = Some(handle);
        self
    }

    /// Adds one route binding.
    pub fn with_binding(mut self, binding: RouteBinding) -> Self {
        self.bindings.push(binding);
        self
    }

    /// Adds multiple route bindings.
    pub fn with_bindings(mut self, bindings: impl IntoIterator<Item = RouteBinding>) -> Self {
        self.bindings.extend(bindings);
        self
    }

    /// Installs a consumer-supplied [`PathPermissions`] (A4.3a).
    pub fn with_path_permissions(mut self, perms: Arc<dyn PathPermissions>) -> Self {
        self.path_permissions = Some(perms);
        self
    }

    /// Declares custom resource types (in addition to the 8 core ones).
    /// `bootstrap_resource_types` runs only when `access` is `Some`.
    pub fn with_resource_types(mut self, types: &[ResourceType]) -> Self {
        self.resource_types.extend(types.iter().cloned());
        self
    }

    /// Opts out of RBAC: skips `AccessState` creation and the
    /// `bootstrap_all_core` / `bootstrap_resource_types` steps. Low-level
    /// methods (`create_tenant`, `create_workspace`, …) still work — they
    /// only call `authz.require` + SQL.
    pub fn without_rbac(mut self) -> Self {
        self.access_skipped = true;
        self
    }

    /// Inserts a value into the state's `Extensions`.
    pub fn with_extension<T: Send + Sync + Clone + 'static>(mut self, ext: T) -> Self {
        self.extensions.insert(ext);
        self
    }

    /// Builds the state. See module docs for the step list.
    ///
    /// Errors are wrapped in [`AppError`]: `CasbinAuthz::from_pool` failures
    /// become `AppError::Core(Internal(_))`; `SaasBuilder::build` failures
    /// propagate as `AppError::Core`; `bootstrap_all_core` /
    /// `bootstrap_resource_types` failures become `AppError::Core(Validation
    /// / Internal)` per `CoreError::from(AccessError)`.
    pub async fn build(self) -> Result<AxumAppState, AppError> {
        // 1. Authorization engine (Casbin).
        let authz: Arc<dyn AuthorizationEngine> = Arc::new(
            CasbinAuthz::from_pool(self.pool.clone())
                .await
                .map_err(CoreError::from)?,
        );

        // 2. Audit logger (default = real PgAuditLogger).
        let audit: Arc<dyn AuditLogger> = self
            .audit
            .unwrap_or_else(|| Arc::new(PgAuditLogger::from_pool(self.pool.clone())));

        // 3. Access state (skipped when `without_rbac`).
        let access_state: Option<Arc<AccessState>> = if self.access_skipped {
            None
        } else {
            Some(Arc::new(
                AccessState::new(self.pool.clone(), authz.clone()).with_audit(audit.clone()),
            ))
        };

        // 4. Authn (Argon2 / JWT / refresh tokens).
        let authn = Arc::new(
            Authn::with_ttl(
                self.pool.clone(),
                self.jwt_secret.clone(),
                self.access_ttl.unwrap_or_else(|| TimeDelta::minutes(15)),
                self.refresh_ttl.unwrap_or_else(|| TimeDelta::days(30)),
            )
            .with_audit(audit.clone()),
        );

        // 5. SaasState (business logic).
        let mut saas_builder = SaasBuilder::new(self.pool.clone())
            .with_authz(authz.clone())
            .with_audit(audit.clone());
        saas_builder = match access_state.clone() {
            Some(a) => saas_builder.with_access(a),
            None => saas_builder.without_access(),
        };
        let saas: Arc<SaasState> = Arc::new(saas_builder.build()?);

        // 6. Bootstrap (only if RBAC is enabled).
        if let Some(a) = &access_state {
            access::registry::bootstrap_all_core(a.pool(), a.authz())
                .await
                .map_err(|e| AppError::Core(CoreError::from(e)))?;
            // 7. Custom resource types (only if declared).
            if !self.resource_types.is_empty() {
                access::registry::bootstrap_resource_types(
                    a.pool(),
                    a.authz(),
                    &self.resource_types,
                )
                .await
                .map_err(|e| AppError::Core(CoreError::from(e)))?;
            }
        }

        // 8. Route bindings (user-supplied; built-ins — A4.3a).
        let bindings = Arc::new(RouteBindings::new(self.bindings));

        // 9. Cookie config (default = env + loopback bind address).
        let default_bind: SocketAddr = "127.0.0.1:3395"
            .parse()
            .expect("static SocketAddr must parse");
        let cookie = Arc::new(
            self.cookie
                .unwrap_or_else(|| CookieConfig::from_env(&default_bind)),
        );

        // 10. Email + rate limiter (defaults).
        let email: Arc<dyn EmailSender> = self.email.unwrap_or_else(|| Arc::new(NoopEmailSender));
        let rate_limit: Arc<dyn RateLimiter> = self
            .rate_limit
            .unwrap_or_else(|| Arc::new(rate_limiter::InMemoryRateLimiter::new()));

        Ok(AxumAppState {
            authn,
            saas,
            authz,
            access: access_state,
            email,
            rate_limit,
            cookie,
            prometheus: self.prometheus,
            bindings,
            path_permissions: self.path_permissions,
            extensions: self.extensions,
        })
    }
}
