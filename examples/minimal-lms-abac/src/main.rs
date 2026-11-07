use std::sync::Arc;

use anyhow::Context;
use minimal_lms_abac::{build_app, MIGRATOR};
use rust_saas::access::registry::ResourceType;
use rust_saas::AxumAppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_init();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let jwt_secret = std::env::var("JWT_SECRET").context("JWT_SECRET must be set")?;
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3398".into());

    let pool = rust_saas::db::connect(&database_url)
        .await
        .context("db::connect")?;
    rust_saas::db::migrate_composed(&pool, &[&MIGRATOR])
        .await
        .context("migrate_composed")?;

    let state = AxumAppState::builder(pool, jwt_secret)
        .with_resource_types(&[
            ResourceType::workspace("course", &["read", "write"]),
            ResourceType::workspace("course_type_a", &["create"]),
            ResourceType::workspace("course_type_b", &["create"]),
        ])
        .build()
        .await
        .context("AxumAppState::builder")?;

    let app = build_app(Arc::new(state));
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .context("bind")?;
    tracing::info!("minimal-lms-abac listening on {bind_addr}");
    axum::serve(listener, app).await.context("serve")?;
    Ok(())
}

fn tracing_init() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}
