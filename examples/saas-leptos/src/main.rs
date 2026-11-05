//! `saas-leptos` entry point.
//!
//! Thin binary: env → `AppState` → `axum::serve(build_app(state))`.
//! Everything else (handlers, middleware, router assembly) lives in
//! `lib.rs::build_app`, which is what `tests/e2e.rs` drives in-process via
//! `tower::ServiceExt::oneshot` (Stage 4.7).
//!
//! Kept `#[cfg(feature = "ssr")]` on `main` so `cargo check --features
//! hydrate` on the host (without `ssr`) compiles an empty binary — the
//! SSR wiring needs `axum`, `authn`, `saas`, `db`, all `ssr`-only.

#[cfg(feature = "ssr")]
use std::sync::Arc;

#[cfg(feature = "ssr")]
use rust_saas::audit::AuditLogger;
#[cfg(feature = "ssr")]
use rust_saas::audit_pg::PgAuditLogger;
#[cfg(feature = "ssr")]
use rust_saas::authz::AuthorizationEngine;
#[cfg(feature = "ssr")]
use leptos::config::get_configuration;
#[cfg(feature = "ssr")]
use metrics_exporter_prometheus::PrometheusBuilder;
#[cfg(feature = "ssr")]
use rust_saas::rate_limiter::RateLimiter;

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    for key in ["LEPTOS_SITE_ADDR", "LEPTOS_RELOAD_PORT"] {
        if std::env::var(key)
            .map(|v| v.trim().is_empty())
            .unwrap_or(false)
        {
            std::env::remove_var(key);
        }
    }

    let conf = get_configuration(None)?;
    let leptos_options = conf.leptos_options;

    let bind_addr: std::net::SocketAddr = match std::env::var("BIND_ADDR") {
        Ok(raw) => match raw.trim().parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!(
                    "BIND_ADDR={raw:?} is not a valid SocketAddr ({e}); falling back to leptos_options.site_addr"
                );
                leptos_options.site_addr
            }
        },
        Err(_) => leptos_options.site_addr,
    };

    let database_url = std::env::var("DATABASE_URL")?;
    let jwt_secret = std::env::var("JWT_SECRET")?;

    let access_ttl_minutes = std::env::var("ACCESS_TOKEN_TTL_MINUTES")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(rust_saas::authn::DEFAULT_ACCESS_TTL_MINUTES);
    let refresh_ttl_days = std::env::var("REFRESH_TOKEN_TTL_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(rust_saas::authn::DEFAULT_REFRESH_TTL_DAYS);

    let cookie_cfg = Arc::new(saas_leptos::cookie::CookieConfig::from_env(&bind_addr));

    let pool = rust_saas::db::connect(&database_url).await?;
    rust_saas::db::migrate(&pool).await?;

    let authz: Arc<dyn AuthorizationEngine> =
        Arc::new(rust_saas::authz_casbin::CasbinAuthz::from_pool(pool.clone()).await?);

    let audit: Arc<dyn AuditLogger> = Arc::new(PgAuditLogger::from_pool(pool.clone()));

    let access =
        Arc::new(rust_saas::access::AccessState::new(pool.clone(), authz.clone()).with_audit(audit.clone()));

    let authn = Arc::new(
        rust_saas::authn::Authn::with_ttl(
            pool.clone(),
            jwt_secret,
            chrono::Duration::minutes(access_ttl_minutes),
            chrono::Duration::days(refresh_ttl_days),
        )
        .with_audit(audit.clone()),
    );

    let saas = Arc::new(
        rust_saas::saas::SaasBuilder::new(pool)
            .with_authz(authz)
            .with_access(access)
            .with_audit(audit)
            .build()?,
    );

    let base_url = std::env::var("BASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("http://{bind_addr}"));
    let smtp_from = std::env::var("SMTP_FROM")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "noreply@example.test".to_string());

    let email: Arc<dyn saas_leptos::email::EmailSender> = match std::env::var("SMTP_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(smtp_url) => Arc::new(
            saas_leptos::email::SmtpEmailSender::new(&smtp_url, &smtp_from, &base_url)
                .map_err(|e| anyhow::anyhow!("failed to build SmtpEmailSender: {e}"))?,
        ),
        None => {
            tracing::warn!(
                    "SMTP_URL is not set; using NoopEmailSender (verification emails will not be delivered)"
                );
            Arc::new(saas_leptos::email::NoopEmailSender)
        }
    };

    let rate_limit: Arc<dyn RateLimiter> = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => Arc::new(
            rust_saas::rate_limiter::RedisRateLimiter::from_url(&url)
                .await
                .map_err(|e| anyhow::anyhow!("failed to connect to Redis: {e}"))?,
        ),
        _ => Arc::new(rust_saas::rate_limiter::InMemoryRateLimiter::new()),
    };

    // Stage 4.10: install the Prometheus recorder once per process.
    // `install_recorder` is a global singleton — a second call panics.
    let prometheus = PrometheusBuilder::new().install_recorder()?;

    let app_state = saas_leptos::state::AppState {
        authn: authn.clone(),
        saas,
        leptos_options: leptos_options.clone(),
        email,
        rate_limit,
        cookie: cookie_cfg.clone(),
        prometheus,
    };

    let router = saas_leptos::build_app(app_state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {bind_addr}: {e}"))?;
    tracing::info!("listening on http://{bind_addr}");

    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn main() {}
