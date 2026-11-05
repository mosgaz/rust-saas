//! `axum-minimal` entry point (Stage 5.0-A6).
//!
//! Thin binary: env -> pool -> migrations -> AxumAppState -> build_app ->
//! axum::serve. All HTTP plumbing (auth endpoints, middleware, /healthz,
//! /readyz, /metrics) comes from `rust_saas::build_app_full_with` inside
//! `axum_minimal::build_app`.

use std::sync::Arc;

use axum_minimal::build_app;
use rust_saas::{db, AxumAppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3395".into());
    let database_url = std::env::var("DATABASE_URL")?;
    let jwt_secret = std::env::var("JWT_SECRET")?;

    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    let state = AxumAppState::builder(pool, jwt_secret).build().await?;

    let app = build_app(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {bind_addr}: {e}"))?;
    tracing::info!("axum-minimal listening on http://{bind_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
