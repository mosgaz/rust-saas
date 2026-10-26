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

    // cargo-leptos может передать пустые LEPTOS_* переменные — leptos_config
    // падает на .parse::<u32>() с "invalid port value".
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

    // BIND_ADDR — только override. Если в нём есть мусор (например, '\r' из
    // прошлого export CRLF-.env), он не должен ронять приложение. Пробуем
    // распарсить как SocketAddr; на неудаче откатываемся на leptos_options.site_addr,
    // который гарантированно валиден (get_configuration уже отработал).
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

    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    let authz = std::sync::Arc::new(authz::Authz::new(&database_url).await?);

    let app_state = app::state::AppState {
        pool,
        authz,
        jwt_secret,
        leptos_options: leptos_options.clone(),
    };

    let routes = generate_route_list(app::App);

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
                move || app::shell(opts.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler::<app::state::AppState, _>(app::shell))
        .layer(TraceLayer::new_for_http())
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