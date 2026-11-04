//! `minimal-lms` binary: env -> pool -> migrations -> state -> router -> serve.

use std::sync::Arc;

use rust_saas::access::ResourceType;
use rust_saas::db;
use rust_saas::{AxumAppState, BindingScope, RouteBinding};
use sqlx::migrate::Migrator;

static MY_MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")?;
    let jwt_secret = std::env::var("JWT_SECRET")?;

    let pool = db::connect(&database_url).await?;
    db::migrate_composed(&pool, &[&MY_MIGRATOR]).await?;

    let state = AxumAppState::builder(pool, jwt_secret)
        .with_resource_types(&[
            ResourceType::workspace("course", &["read", "write", "publish"]),
            ResourceType::workspace("assignment", &["read", "grade"]),
            ResourceType::tenant("batch", &["read", "manage"]),
            ResourceType::tenant("file", &["read", "write", "delete"]),
        ])
        .with_bindings([
            RouteBinding::read(
                axum::http::Method::GET,
                "/workspaces/{workspace_id}/courses",
                BindingScope::WorkspaceFromPath("workspace_id"),
                "course",
                "read",
            ),
            RouteBinding::mutating(
                axum::http::Method::POST,
                "/workspaces/{workspace_id}/courses",
                BindingScope::WorkspaceFromPath("workspace_id"),
                "course",
                "write",
            ),
            RouteBinding::read(
                axum::http::Method::GET,
                "/tenants/{tenant_id}/files",
                BindingScope::TenantFromPath("tenant_id"),
                "file",
                "read",
            ),
            RouteBinding::mutating(
                axum::http::Method::POST,
                "/tenants/{tenant_id}/batches",
                BindingScope::TenantFromPath("tenant_id"),
                "batch",
                "manage",
            ),
        ])
        .build()
        .await?;

    let app = minimal_lms::build_app(Arc::new(state));

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3395".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("minimal-lms listening on http://{addr}");
    axum::serve(listener, app).await?;

    Ok(())
}
