#[cfg(feature = "ssr")]
use std::sync::Arc;

#[cfg(feature = "ssr")]
use authz::AuthorizationEngine;
#[cfg(feature = "ssr")]
use axum::Router;
#[cfg(feature = "ssr")]
use leptos::config::get_configuration;
#[cfg(feature = "ssr")]
use leptos_axum::{generate_route_list, LeptosRoutes};
#[cfg(feature = "ssr")]
use tower_http::trace::TraceLayer;

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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
        .unwrap_or(authn::DEFAULT_ACCESS_TTL_MINUTES);
    let refresh_ttl_days = std::env::var("REFRESH_TOKEN_TTL_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(authn::DEFAULT_REFRESH_TTL_DAYS);

    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    let authz: Arc<dyn AuthorizationEngine> =
        Arc::new(authz_casbin::CasbinAuthz::new(&database_url).await?);

    let authn = Arc::new(authn::Authn::with_ttl(
        pool.clone(),
        jwt_secret,
        chrono::Duration::minutes(access_ttl_minutes),
        chrono::Duration::days(refresh_ttl_days),
    ));

    let saas = Arc::new(
        saas::SaasBuilder::new(pool)
            .with_authz(authz)
            .build()?,
    );

    let app_state = saas_leptos::state::AppState {
        authn: authn.clone(),
        saas,
        leptos_options: leptos_options.clone(),
    };

    let routes = generate_route_list(saas_leptos::App);

    let router = Router::new()
        .leptos_routes_with_context(
            &app_state,
            routes,
            {
                let state = app_state.clone();
                move || leptos::prelude::provide_context(state.clone())
            },
            {
                let opts = leptos_options.clone();
                move || saas_leptos::shell(opts.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler::<saas_leptos::state::AppState, _>(saas_leptos::shell))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            authn,
            saas_leptos::middleware::auto_refresh,
        ))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {bind_addr}: {e}"))?;
    tracing::info!("listening on http://{bind_addr}");

    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn main() {}