use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    let authz = authz::Authz::new(&database_url).await?;

    let platform_admin =
        upsert_user(&pool, "platform-admin@example.test", "PlatformAdmin123!").await?;

    let tenant_owner = upsert_user(&pool, "owner@acme.test", "Owner123!").await?;

    let editor = upsert_user(&pool, "editor@acme.test", "Editor123!").await?;

    let viewer = upsert_user(&pool, "viewer@acme.test", "Viewer123!").await?;

    authz.grant_platform_admin(platform_admin).await?;

    // --- Tenant: find-or-create ---
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

    // --- Workspace: find-or-create ---
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

    // editor
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
        .grant_workspace_role(editor, workspace_id, authz::WorkspaceRole::Editor)
        .await?;

    // viewer — нужен для проверки DoD «viewer может читать, но не создавать».
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
        .grant_workspace_role(viewer, workspace_id, authz::WorkspaceRole::Viewer)
        .await?;

    // --- Document: insert only if not exists ---
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

async fn upsert_user(pool: &PgPool, email: &str, password: &str) -> anyhow::Result<Uuid> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    let id: Uuid = sqlx::query_scalar(
        r#"
        insert into users (email, password_hash)
        values ($1, $2)
        on conflict (email) do update
        set password_hash = excluded.password_hash
        returning id
        "#,
    )
    .bind(email)
    .bind(hash)
    .fetch_one(pool)
    .await?;

    Ok(id)
}