//! Integration-тесты `saas` на реальной PostgreSQL + `authz-casbin`.
//!
//! `#[sqlx::test]` для каждого теста создаёт изолированную БД, накатывает
//! `crates/db/migrations` (включая `casbin_rule`) и удаляет её после теста.
//! `CasbinAuthz::from_pool` подключается к этому же пулу — политики живут
//! в тестовой БД.
//!
//! Ручной `createdb` больше не нужен. `DATABASE_URL` должен указывать на сервер,
//! где пользователь имеет право `CREATE DATABASE`.

use std::sync::Arc;

use authz::AuthorizationEngine;
use authz_casbin::CasbinAuthz;
use domain::AuthUser;
use saas::{platform, tenant, workspace, CoreError, SaasBuilder, SaasState};
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> (Arc<CasbinAuthz>, SaasState) {
    let casbin = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let saas = SaasBuilder::new(pool.clone())
        .with_authz(casbin.clone() as Arc<dyn AuthorizationEngine>)
        .build()
        .expect("saas builder");
    (casbin, saas)
}

async fn make_user(pool: &PgPool, label: &str) -> AuthUser {
    let email = format!("{label}-{}@test.local", Uuid::new_v4());
    let hash = authn::hash_password("Password123!").expect("hash");
    identity::create_user(pool, &email, &hash)
        .await
        .expect("user must be created")
}

fn unique_name(label: &str) -> String {
    format!("{label}-{}", Uuid::new_v4())
}

#[sqlx::test(migrations = "../db/migrations")]
async fn create_tenant_grants_owner_and_membership(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin
        .grant_platform_admin(admin.id)
        .await
        .expect("grant platform admin");

    let tenant = platform::create_tenant(&saas, &admin, unique_name("Acme"))
        .await
        .expect("create_tenant must succeed");

    let role: Option<String> = sqlx::query_scalar(
        "select role from tenant_members where tenant_id = $1 and user_id = $2",
    )
    .bind(tenant.id)
    .bind(admin.id)
    .fetch_optional(&pool)
    .await
    .expect("query tenant_members");
    assert_eq!(role.as_deref(), Some("owner"));

    let can = casbin
        .can(
            admin.id,
            &domain::tenant_domain(tenant.id),
            "workspaces",
            "create",
        )
        .await
        .expect("casbin can");
    assert!(can, "creator must be able to create workspace in new tenant");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn create_workspace_grants_admin_and_membership(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::create_tenant(&saas, &admin, unique_name("Acme"))
        .await
        .unwrap();

    let ws = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("Eng"))
        .await
        .expect("create_workspace must succeed");

    let role: Option<String> = sqlx::query_scalar(
        "select role from workspace_members where workspace_id = $1 and user_id = $2",
    )
    .bind(ws.id)
    .bind(admin.id)
    .fetch_optional(&pool)
    .await
    .expect("query workspace_members");
    assert_eq!(role.as_deref(), Some("admin"));

    let can = casbin
        .can(
            admin.id,
            &domain::workspace_domain(ws.id),
            "documents",
            "write",
        )
        .await
        .expect("casbin can");
    assert!(can, "workspace admin must be able to write documents");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn platform_admin_cannot_create_document_without_workspace_role(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "pa").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::create_tenant(&saas, &admin, unique_name("Acme"))
        .await
        .unwrap();

    let owner = make_user(&pool, "owner").await;
    casbin
        .grant_tenant_owner(owner.id, tenant.id)
        .await
        .unwrap();
    let ws = tenant::create_workspace(&saas, &owner, tenant.id, unique_name("Eng"))
        .await
        .unwrap();

    let err = workspace::create_document(&saas, &admin, ws.id, "doc".into())
        .await
        .expect_err("platform admin must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn cross_workspace_isolation(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::create_tenant(&saas, &admin, unique_name("Acme"))
        .await
        .unwrap();

    let ws1 = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("ws1"))
        .await
        .unwrap();
    let ws2 = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("ws2"))
        .await
        .unwrap();

    workspace::create_document(&saas, &admin, ws1.id, "private".into())
        .await
        .unwrap();

    let outsider = make_user(&pool, "outsider").await;

    let read_err = workspace::list_documents(&saas, &outsider, ws2.id)
        .await
        .expect_err("outsider must be forbidden");
    assert!(matches!(read_err, CoreError::Forbidden), "got {read_err:?}");

    let write_err = workspace::create_document(&saas, &outsider, ws2.id, "x".into())
        .await
        .expect_err("outsider must be forbidden");
    assert!(matches!(write_err, CoreError::Forbidden), "got {write_err:?}");

    let docs = workspace::list_documents(&saas, &admin, ws1.id)
        .await
        .expect("admin can read");
    assert_eq!(docs.len(), 1);
}