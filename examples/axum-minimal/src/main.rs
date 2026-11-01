//! `axum-minimal` entry point — Stage 3g portability proof.
//!
//! A second consumer of `rust-saas` on pure Axum, no Leptos. It uses the
//! same public contracts (`saas::*`, `authn::*`, `access::*`, `audit::*`,
//! `domain::*`) and the same `resolve_active_tenant` calls in mutation
//! handlers as `examples/saas-leptos` — that is the point of Stage 3g
//! (plan §1).
//!
//! **Wiring** mirrors `examples/saas-leptos/src/main.rs` without the
//! Leptos-specific pieces:
//!
//! - `db::connect` + `db::migrate` — same startup step.
//! - `CasbinAuthz::from_pool` — one `PgPool`, one authorization engine.
//! - `PgAuditLogger::from_pool` — one `PgPool`, one audit logger.
//! - `AccessState::with_audit`, `Authn::with_audit`,
//!   `SaasBuilder::with_audit` — real logger plugged into every layer
//!   (Stage 3e contract: `with_audit` is additive; missing it is a
//!   deployment mistake, not a compile error).
//! - `auto_refresh` on the **protected** router — public routes
//!   (`register`, `login`, `logout`) bypass it.
//! - `TraceLayer` on the whole app.
//!
//! **Router split** (same rationale as `saas-leptos`, ADR-0002 rev.2 §2.1):
//!
//! - **protected** — `POST /auth/refresh`, `GET|POST /tenants`,
//!   `GET|POST /workspaces`, `GET|POST /documents`, `GET /audit`. All
//!   routes that read `CurrentUser::require()` go here, so `auto_refresh`
//!   has already populated `Extension<Option<AuthUser>>`.
//! - **public** — `POST /auth/register`, `POST /auth/login`,
//!   `POST /auth/logout`. No actor is required; `login`/`logout` read
//!   cookies directly. `logout` does **not** require a valid access token
//!   (it revokes whatever refresh cookie is present — a stale access token
//!   must not block a logout).
//!
//! **Module shadowing note.** `mod audit;` declares the local handler
//! module (our `src/audit.rs`), which shadows the external `audit` crate in
//! the crate-root namespace. Therefore the external trait is imported as
//! `::audit::AuditLogger` (leading `::` forces the crate path). The local
//! module is still reachable as `audit::list_audit` — that is what the
//! router uses.
//!
//! **`Arc<AppState>` as router state.** Handlers take
//! `State<Arc<AppState>>` (cheap clones, `Arc` is shared across requests),
//! so the routers are `Router<Arc<AppState>>` and `with_state` receives
//! `Arc::new(app_state)` — not the bare `AppState`.
//!
//! **Deliberate deviation from ADR-0002 rev.2 §3.8.** `saas-leptos` uses a
//! plain helper `CurrentUser::from_request()` and deliberately avoids
//! `axum::extract::FromRequestParts`; `axum-minimal` does the opposite —
//! `crate::extract::CurrentUser` is a real `FromRequestParts` impl. That is
//! exactly what 3g demonstrates (plan §2, §6); recorded in `handoff §16`
//! and Appendix B §2.48.

use std::sync::Arc;

use ::audit::AuditLogger;
use audit_pg::PgAuditLogger;
use authz::AuthorizationEngine;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

mod audit;
mod auth_layer;
mod auth;
mod cookie;
mod csrf;
mod email;
mod error;
mod extract;
mod health;
mod middleware;
mod rate_limit;
mod state;
mod tenant;
mod workspace;

use crate::email::NoopEmailSender;
use crate::rate_limit::SimpleRateLimiter;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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

    // ── Database + migrations ──────────────────────────────────────────────
    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    // ── Authorization engine ───────────────────────────────────────────────
    let authz: Arc<dyn AuthorizationEngine> =
        Arc::new(authz_casbin::CasbinAuthz::from_pool(pool.clone()).await?);

    // ── Audit logger (Stage 3e) ────────────────────────────────────────────
    let audit: Arc<dyn AuditLogger> = Arc::new(PgAuditLogger::from_pool(pool.clone()));

    // ── AccessState (access crate) ─────────────────────────────────────────
    let access = Arc::new(
        access::AccessState::new(pool.clone(), authz.clone()).with_audit(audit.clone()),
    );

    // ── Authn ──────────────────────────────────────────────────────────────
    let authn = Arc::new(
        authn::Authn::with_ttl(
            pool.clone(),
            jwt_secret,
            chrono::Duration::minutes(access_ttl_minutes),
            chrono::Duration::days(refresh_ttl_days),
        )
        .with_audit(audit.clone()),
    );

    // ── SaasState (business logic) ─────────────────────────────────────────
    let saas = Arc::new(
        saas::SaasBuilder::new(pool)
            .with_authz(authz)
            .with_access(access)
            .with_audit(audit)
            .build()?,
    );

    // ── Email transport + rate limiter ─────────────────────────────────────
    // `axum-minimal` ships only `NoopEmailSender` (plan §1: SMTP out of
    // scope). The `EmailSender` trait exists so a future consumer can plug
    // in a real sender without changing `AppState`.
    let email: Arc<dyn email::EmailSender> = Arc::new(NoopEmailSender);
    let rate_limit = Arc::new(SimpleRateLimiter::new());

    // Stage 4.1b: cookie policy (Secure/SameSite/Max-Age).
    let cookie_cfg = std::sync::Arc::new(
        cookie::CookieConfig::from_env(&bind_addr),
    );

    let app_state = Arc::new(AppState {
        authn: authn.clone(),
        saas,
        email,
        rate_limit,
        cookie: cookie_cfg.clone(),
    });

    // ── Router: public vs protected ────────────────────────────────────────
    //
    // `auto_refresh` is attached only to the protected group. It is
    // parametrised over `Arc<Authn>` (see `middleware.rs`), so
    // `from_fn_with_state` supplies the `Authn` explicitly — the router's
    // own state stays `Arc<AppState>`.
    let protected: Router<Arc<AppState>> = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .route(
            "/tenants",
            get(tenant::list_my_tenants).post(tenant::create_tenant),
        )
        .route(
            "/workspaces",
            get(workspace::list_my_workspaces).post(workspace::create_workspace),
        )
        .route(
            "/documents",
            get(workspace::list_documents).post(workspace::create_document),
        )
        .route("/audit", get(audit::list_audit))
        // Axum note: the *last* `.route_layer` is the outermost. So the
        // calls below are in reverse execution order — the request runs
        // them top-to-bottom of this list.
        //
        // Stage 4.1d: server-side AuthLayer (innermost of the three — must
        // run *after* auto_refresh has populated Extension<Option<AuthUser>>).
        .route_layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_layer::auth_layer,
        ))
        // Stage 3g: auto_refresh (verify access / rotate refresh).
        .route_layer(from_fn_with_state(app_state.clone(), middleware::auto_refresh))
        // Stage 4.1c: CSRF guard (outermost — reject cross-origin before
        // doing any auth work).
        .route_layer(axum::middleware::from_fn(csrf::csrf_guard));

    let public: Router<Arc<AppState>> = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout));

    let router = protected
        .merge(public)
        .layer(TraceLayer::new_for_http())
        // Stage 4.1c: issue a `csrf` cookie on the first request
        // (runs after the handler; if the client already has one, no-op).
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            csrf::csrf_issue,
        ))
        .with_state(app_state);

    // ── Serve ──────────────────────────────────────────────────────────────
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {bind_addr}: {e}"))?;
    tracing::info!("axum-minimal listening on http://{bind_addr}");

    axum::serve(listener, router).await?;
    Ok(())
}