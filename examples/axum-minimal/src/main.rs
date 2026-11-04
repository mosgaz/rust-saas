//! `axum-minimal` entry point.
//!
//! Thin binary: reads env, wires `AppState` (one `PgPool`, one
//! `CasbinAuthz`, one `PgAuditLogger`, one `Authn`, one `SaasState`),
//! then serves `axum_minimal::build_app(app_state)`.
//!
//! Everything else (handlers, middleware, router assembly) lives in the
//! library crate \u2014 that is what `tests/e2e.rs` drives in-process via
//! `tower::ServiceExt::oneshot` (Stage 4.7).
//!
//! Deliberate deviation from ADR-0002 rev.2 \u00a73.8: `crate::extract::CurrentUser`
//! is a real `axum::extract::FromRequestParts` impl (Axum-native pipeline);
//! `saas-leptos` uses a plain helper because Leptos `#[server]` functions
//! do not go through Axum's extractor pipeline. Recorded in handoff \u00a716
//! and Appendix B \u00a72.50.

use std::sync::Arc;

use ::audit::AuditLogger;
use audit_pg::PgAuditLogger;
use authz::AuthorizationEngine;
use axum_minimal::email::NoopEmailSender;
use axum_minimal::state::AppState;
use axum_minimal::{build_app, cookie};
use metrics_exporter_prometheus::PrometheusBuilder;
use rate_limiter::RateLimiter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind_addr: std::net::SocketAddr = match std::env::var("BIND_ADDR") {
        Ok(raw) => raw
            .trim()
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid BIND_ADDR={raw:?}: {e}"))?,
        Err(_) => "127.0.0.1:3395"
            .parse()
            .expect("static SocketAddr must parse"),
    };

    let database_url = std::env::var("DATABASE_URL")?;
    let jwt_secret = std::env::var("JWT_SECRET")?;

    let access_ttl_minutes = std::env::var("ACCESS_TOKEN_TTL_MINUTES")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(authn::DEFAULT_ACCESS_TTL_MINUTES);
    let refresh_ttl_days = std::env::var("REFRESH_TOKEN_TTL_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(authn::DEFAULT_REFRESH_TTL_DAYS);

    // \u2500\u2500 Database + migrations \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    // \u2500\u2500 Authorization engine \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    let authz: Arc<dyn AuthorizationEngine> =
        Arc::new(authz_casbin::CasbinAuthz::from_pool(pool.clone()).await?);

    // \u2500\u2500 Audit logger (Stage 3e) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    let audit: Arc<dyn AuditLogger> = Arc::new(PgAuditLogger::from_pool(pool.clone()));

    // \u2500\u2500 AccessState (access crate) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    let access =
        Arc::new(access::AccessState::new(pool.clone(), authz.clone()).with_audit(audit.clone()));

    // \u2500\u2500 Authn \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    let authn = Arc::new(
        authn::Authn::with_ttl(
            pool.clone(),
            jwt_secret,
            chrono::Duration::minutes(access_ttl_minutes),
            chrono::Duration::days(refresh_ttl_days),
        )
        .with_audit(audit.clone()),
    );

    // \u2500\u2500 SaasState (business logic) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    let saas = Arc::new(
        saas::SaasBuilder::new(pool)
            .with_authz(authz)
            .with_access(access)
            .with_audit(audit)
            .build()?,
    );

    // \u2500\u2500 Email transport + rate limiter \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    // SMTP out of scope for 3g \u2014 `NoopEmailSender` only.
    let email: Arc<dyn axum_minimal::email::EmailSender> = Arc::new(NoopEmailSender);
    let rate_limit: Arc<dyn RateLimiter> = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => Arc::new(
            rate_limiter::RedisRateLimiter::from_url(&url)
                .await
                .map_err(|e| anyhow::anyhow!("failed to connect to Redis: {e}"))?,
        ),
        _ => Arc::new(rate_limiter::InMemoryRateLimiter::new()),
    };

    // Stage 4.1b: cookie policy (Secure/SameSite/Max-Age).
    let cookie_cfg = Arc::new(cookie::CookieConfig::from_env(&bind_addr));

    // Stage 4.10: install the Prometheus recorder once per process.
    // `install_recorder` is a global singleton — a second call panics.
    // `main.rs` is the only install site for the binary; `tests/e2e.rs`
    // uses `metrics::try_recorder()` + `build_recorder()` (idempotent).
    let prometheus = PrometheusBuilder::new().install_recorder()?;

    let app_state = Arc::new(AppState {
        authn: authn.clone(),
        saas,
        email,
        rate_limit,
        cookie: cookie_cfg,
        prometheus,
    });

    let router = build_app(app_state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {bind_addr}: {e}"))?;
    tracing::info!("axum-minimal listening on http://{bind_addr}");

    axum::serve(listener, router).await?;
    Ok(())
}
