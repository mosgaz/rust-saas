//! Bootstrap binary for demo data (see handoff §11).
//!
//! Creates a platform admin, tenant Acme, its owner, workspace Engineering,
//! editor, viewer, the first document, and the Casbin policies. Idempotent:
//! re-running re-hashes passwords, skips existing tenants/workspaces, and
//! re-applies roles and policies without creating duplicates.
//!
//! Bootstrap flow:
//! - Platform admin is granted the `owner` role in the `platform` domain.
//! - Tenant and workspace are created via `saas::platform::provision_tenant`
//!   and `saas::tenant::create_workspace` with `owner_role_key = "owner"`.
//! - Demo custom roles (`editor`, `viewer`) are created via
//!   `saas::access::create_role` and assigned via `saas::access::assign_role`.

use std::sync::Arc;

use access::{AccessState, RoleKey};
use authz::AuthorizationEngine;
use domain::{AuthUser, Tenant, Workspace};
use saas::{access as saas_access, platform, tenant, workspace, SaasBuilder};
use sqlx::PgPool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    let authz: Arc<dyn AuthorizationEngine> =
        Arc::new(authz_casbin::CasbinAuthz::new(&database_url).await?);
    let access_state = Arc::new(AccessState::new(pool.clone(), authz.clone()));

    let state = SaasBuilder::new(pool.clone())
        .with_authz(authz.clone())
        .with_access(access_state)
        .build()?;

    let platform_admin =
        upsert_user(&pool, "platform-admin@example.test", "PlatformAdmin123!").await?;
    let tenant_owner = upsert_user(&pool, "owner@acme.test", "Owner123!").await?;
    let editor_user = upsert_user(&pool, "editor@acme.test", "Editor123!").await?;
    let viewer_user = upsert_user(&pool, "viewer@acme.test", "Viewer123!").await?;

    let owner_key = RoleKey::parse("owner")?;

    // Grant platform admin the `owner` role in the `platform` domain.
    let platform_perms =
        ::access::get_permissions_for_role(state.access(), "platform", &owner_key).await?;
    state
        .authz()
        .grant_role(
            platform_admin.id,
            "platform",
            owner_key.as_str(),
            &platform_perms,
        )
        .await?;

    // Ensure tenant exists.
    let tenant = match sqlx::query_as::<_, Tenant>(
        "select id, name, status, created_at from tenants where name = 'Acme' order by created_at limit 1",
    )
    .fetch_optional(&pool)
    .await?
    {
        Some(t) => t,
        None => {
            platform::provision_tenant(
                &state,
                &platform_admin,
                "Acme".to_string(),
                &tenant_owner,
                &owner_key,
            )
            .await?
        }
    };

    // Ensure workspace exists.
    let ws = match sqlx::query_as::<_, Workspace>(
        "select id, tenant_id, name, created_at from workspaces where tenant_id = $1 and name = 'Engineering'",
    )
    .bind(tenant.id)
    .fetch_optional(&pool)
    .await?
    {
        Some(w) => w,
        None => {
            tenant::create_workspace(
                &state,
                &tenant_owner,
                tenant.id,
                "Engineering".to_string(),
                &tenant_owner,
                &owner_key,
            )
            .await?
        }
    };

    let ws_domain = domain::workspace_domain(ws.id);
    let editor_key = RoleKey::parse("editor")?;
    let viewer_key = RoleKey::parse("viewer")?;

    let roles = saas_access::list_roles(&state, &tenant_owner, &ws_domain).await?;

    // Create custom roles if they don't exist yet.
    if !roles.iter().any(|r| r.key == editor_key) {
        saas_access::create_role(
            &state,
            &tenant_owner,
            &ws_domain,
            &editor_key,
            "Editor".to_string(),
            "Can edit documents".to_string(),
            &[
                ("documents".to_string(), "read".to_string()),
                ("documents".to_string(), "write".to_string()),
            ],
        )
        .await?;
    }

    if !roles.iter().any(|r| r.key == viewer_key) {
        saas_access::create_role(
            &state,
            &tenant_owner,
            &ws_domain,
            &viewer_key,
            "Viewer".to_string(),
            "Can read documents".to_string(),
            &[("documents".to_string(), "read".to_string())],
        )
        .await?;
    }

    // Assign roles. `assign_role` is idempotent (ON CONFLICT DO NOTHING for
    // `*_members` and `add_policy` for `casbin_rule`).
    saas_access::assign_role(
        &state,
        &tenant_owner,
        editor_user.id,
        &ws_domain,
        &editor_key,
    )
    .await?;
    saas_access::assign_role(
        &state,
        &tenant_owner,
        viewer_user.id,
        &ws_domain,
        &viewer_key,
    )
    .await?;

    // Create the first document if it doesn't exist.
    let doc_exists: bool = sqlx::query_scalar(
        "select exists(select 1 from documents where workspace_id = $1 and title = 'Welcome')",
    )
    .bind(ws.id)
    .fetch_one(&pool)
    .await?;

    if !doc_exists {
        workspace::create_document(&state, &tenant_owner, ws.id, "Welcome".to_string()).await?;
    }

    println!("Seed complete");
    println!("platform admin:   platform-admin@example.test / PlatformAdmin123!");
    println!("tenant owner:     owner@acme.test / Owner123!");
    println!("workspace editor: editor@acme.test / Editor123!");
    println!("workspace viewer: viewer@acme.test / Viewer123!");
    println!();
    println!("tenant id:    {}", tenant.id);
    println!("workspace id: {}", ws.id);

    Ok(())
}

/// Creates or updates a user by email; returns its `AuthUser`.
///
/// Idempotent: re-running re-hashes the password and updates the existing row.
async fn upsert_user(pool: &PgPool, email: &str, password: &str) -> anyhow::Result<AuthUser> {
    let hash = authn::hash_password(password)?;
    let user = identity::upsert_user(pool, email, &hash).await?;
    Ok(user)
}
