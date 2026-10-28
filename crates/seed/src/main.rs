//! Bootstrap binary for demo data (see handoff §11).
//!
//! Creates a platform admin, tenant Acme, its owner, workspace Engineering,
//! editor, viewer, the first document, and the Casbin policies. Idempotent:
//! re-running re-hashes passwords and re-applies policies without creating
//! duplicate rows.
//!
//! **Policy re-grant (Stage 2a).** This binary calls `grant_platform_admin`,
//! `grant_tenant_owner`, and `grant_workspace_role` on every invocation.
//! `add_policy` in Casbin deduplicates existing `p`-rows and adds new ones;
//! this is how existing seed tenants/workspaces pick up permission sets
//! introduced by later library versions (for example, `invitations:*` in
//! Stage 2a) without a separate migration. Fresh databases get the same
//! policies on first run; re-runs only extend, never duplicate.
//!
//! **Why not `saas::*` services?** `seed` does not use `saas::*` (see handoff
//! §11): `authz.require` would deny bootstrap operations, since the admin has
//! no policies yet at that point. Business rows are written with inline SQL;
//! policies are granted through `authz-casbin`.

use authz::{AuthorizationEngine, WorkspaceRole};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    let authz = authz_casbin::CasbinAuthz::new(&database_url).await?;

    let platform_admin =
        upsert_user(&pool, "platform-admin@example.test", "PlatformAdmin123!").await?;

    let tenant_owner = upsert_user(&pool, "owner@acme.test", "Owner123!").await?;
    let editor = upsert_user(&pool, "editor@acme.test", "Editor123!").await?;
    let viewer = upsert_user(&pool, "viewer@acme.test", "Viewer123!").await?;

    authz.grant_platform_admin(platform_admin).await?;

    let tenant_id: Uuid = if let Some(id) = sqlx::query_scalar(
        r#"select id from tenants where name = 'Acme' order by created_at limit 1"#,
    )
    .fetch_optional(&pool)
    .await?
    {
        id
    } else {
        sqlx::query_scalar(r#"insert into tenants (name) values ('Acme') returning id"#)
            .fetch_one(&pool)
            .await?
    };

    sqlx::query(
        r#"
        insert into tenant_members (tenant_id, user_id, role)
        values ($1, $2, 'owner')
        on conflict do nothing
        "#,
    )
    .bind(tenant_id)
    .bind(tenant_owner)
    .execute(&pool)
    .await?;

    authz.grant_tenant_owner(tenant_owner, tenant_id).await?;

    let workspace_id: Uuid = sqlx::query_scalar(
        r#"
        insert into workspaces (tenant_id, name)
        values ($1, 'Engineering')
        on conflict (tenant_id, name) do update set name = excluded.name
        returning id
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await?;

    sqlx::query(
        r#"
        insert into workspace_members (workspace_id, user_id, role)
        values ($1, $2, 'editor')
        on conflict do nothing
        "#,
    )
    .bind(workspace_id)
    .bind(editor)
    .execute(&pool)
    .await?;

    authz
        .grant_workspace_role(editor, workspace_id, WorkspaceRole::Editor)
        .await?;

    sqlx::query(
        r#"
        insert into workspace_members (workspace_id, user_id, role)
        values ($1, $2, 'viewer')
        on conflict do nothing
        "#,
    )
    .bind(workspace_id)
    .bind(viewer)
    .execute(&pool)
    .await?;

    authz
        .grant_workspace_role(viewer, workspace_id, WorkspaceRole::Viewer)
        .await?;

    sqlx::query(
        r#"
        insert into documents (workspace_id, title, body)
        select $1, 'Welcome', 'This is the first document.'
        where not exists (
            select 1 from documents
            where workspace_id = $1 and title = 'Welcome'
        )
        "#,
    )
    .bind(workspace_id)
    .execute(&pool)
    .await?;

    println!("Seed complete");
    println!("platform admin:   platform-admin@example.test / PlatformAdmin123!");
    println!("tenant owner:     owner@acme.test / Owner123!");
    println!("workspace editor: editor@acme.test / Editor123!");
    println!("workspace viewer: viewer@acme.test / Viewer123!");
    println!();
    println!("tenant id:    {tenant_id}");
    println!("workspace id: {workspace_id}");

    Ok(())
}

/// Creates or updates a user by email; returns its `id`.
///
/// Idempotent: re-running re-hashes the password and updates the existing row.
async fn upsert_user(pool: &PgPool, email: &str, password: &str) -> anyhow::Result<Uuid> {
    let hash = authn::hash_password(password)?;
    let user = identity::upsert_user(pool, email, &hash).await?;
    Ok(user.id)
}