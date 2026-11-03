//! `saas::platform` resolve / is_* tests (Stage 5.0-A2.1).
//!
//! Companion to `integration.rs` (which covers mutation flows). This
//! file focuses on the six platform helpers added in A2.1:
//!
//! - `resolve_tenant` / `resolve_workspace` — read-path (no status check);
//! - `resolve_active_workspace` — mutation-path (parent tenant active);
//! - `is_tenant_member` / `is_workspace_member` — UI gating.
//!
//! The pre-existing `resolve_active_tenant` is already tested in
//! `integration.rs` (Stage 3f); not repeated here.

use std::sync::Arc;

use access::{AccessState, RoleKey};
use authz::AuthorizationEngine;
use authz_casbin::CasbinAuthz;
use domain::{AuthUser, TenantStatus};
use saas::{platform, CoreError, SaasBuilder, SaasState};
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> SaasState {
    let casbin = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let authz: Arc<dyn AuthorizationEngine> = casbin;
    let access = Arc::new(AccessState::new(pool.clone(), authz.clone()));
    SaasBuilder::new(pool.clone())
        .with_authz(authz)
        .with_access(access)
        .build()
        .expect("saas builder")
}

async fn make_user(pool: &PgPool, label: &str) -> AuthUser {
    let email = format!("{label}-{}@test.local", Uuid::new_v4());
    let hash = authn::hash_password("Password123!").expect("hash");
    identity::create_user(pool, &email, &hash)
        .await
        .expect("user must be created")
}

async fn grant_platform_admin(state: &SaasState, user: &AuthUser) {
    let owner_key = RoleKey::parse("owner").unwrap();
    let perms = ::access::get_permissions_for_role(state.access(), "platform", &owner_key)
        .await
        .unwrap();
    state
        .authz()
        .grant_role(user.id, "platform", "owner", &perms)
        .await
        .unwrap();
}

fn unique_name(label: &str) -> String {
    format!("{label}-{}", Uuid::new_v4())
}

async fn provision_tenant_and_workspace(
    pool: &PgPool,
    saas: &SaasState,
) -> (Uuid, Uuid, AuthUser) {
    let admin = make_user(pool, "admin").await;
    grant_platform_admin(saas, &admin).await;
    let owner = make_user(pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .expect("provision_tenant");

    let ws = saas::tenant::create_workspace(
        saas,
        &owner,
        tenant.id,
        unique_name("Eng"),
        &owner,
        &owner_key,
    )
    .await
    .expect("create_workspace");

    (tenant.id, ws.id, owner)
}

async fn suspend_tenant(pool: &PgPool, tenant_id: Uuid) {
    sqlx::query("update tenants set status = 'suspended' where id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("suspend tenant");
}

// ─── resolve_tenant ────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_tenant_active_member(pool: PgPool) {
    let saas = setup(&pool).await;
    let (tenant_id, _ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;

    let tenant = platform::resolve_tenant(&saas, &owner, tenant_id)
        .await
        .expect("member of active tenant must resolve");
    assert_eq!(tenant.id, tenant_id);
    assert_eq!(tenant.status, TenantStatus::Active);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_tenant_suspended_ok(pool: PgPool) {
    let saas = setup(&pool).await;
    let (tenant_id, _ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;
    suspend_tenant(&pool, tenant_id).await;

    let tenant = platform::resolve_tenant(&saas, &owner, tenant_id)
        .await
        .expect("read path must resolve a suspended tenant");
    assert_eq!(tenant.status, TenantStatus::Suspended);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_tenant_non_member_returns_forbidden(pool: PgPool) {
    let saas = setup(&pool).await;
    let (tenant_id, _ws_id, _owner) = provision_tenant_and_workspace(&pool, &saas).await;
    let outsider = make_user(&pool, "outsider").await;

    let err = platform::resolve_tenant(&saas, &outsider, tenant_id)
        .await
        .expect_err("non-member must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

// ─── resolve_workspace ─────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_workspace_active_member(pool: PgPool) {
    let saas = setup(&pool).await;
    let (_tid, ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;

    let ws = platform::resolve_workspace(&saas, &owner, ws_id)
        .await
        .expect("member of active workspace must resolve");
    assert_eq!(ws.id, ws_id);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_workspace_suspended_ok(pool: PgPool) {
    let saas = setup(&pool).await;
    let (tenant_id, ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;
    suspend_tenant(&pool, tenant_id).await;

    let ws = platform::resolve_workspace(&saas, &owner, ws_id)
        .await
        .expect("read path must resolve a workspace in a suspended tenant");
    assert_eq!(ws.id, ws_id);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_workspace_non_member_returns_forbidden(pool: PgPool) {
    let saas = setup(&pool).await;
    let (_tid, ws_id, _owner) = provision_tenant_and_workspace(&pool, &saas).await;
    let outsider = make_user(&pool, "outsider").await;

    let err = platform::resolve_workspace(&saas, &outsider, ws_id)
        .await
        .expect_err("non-member must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

// ─── resolve_active_workspace ──────────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_active_workspace_active_member(pool: PgPool) {
    let saas = setup(&pool).await;
    let (tid, ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;

    let active = platform::resolve_active_workspace(&saas, &owner, ws_id)
        .await
        .expect("active tenant + member must resolve");
    assert_eq!(active.id, ws_id);
    assert_eq!(active.tenant_id, tid);
    let unwrapped = active.into_inner();
    assert_eq!(unwrapped.id, ws_id);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_active_workspace_suspended_returns_tenant_suspended(pool: PgPool) {
    let saas = setup(&pool).await;
    let (tenant_id, ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;
    suspend_tenant(&pool, tenant_id).await;

    let err = platform::resolve_active_workspace(&saas, &owner, ws_id)
        .await
        .expect_err("suspended parent tenant must be rejected");
    assert!(matches!(err, CoreError::TenantSuspended), "got {err:?}");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn resolve_active_workspace_non_member_returns_forbidden(pool: PgPool) {
    let saas = setup(&pool).await;
    let (_tid, ws_id, _owner) = provision_tenant_and_workspace(&pool, &saas).await;
    let outsider = make_user(&pool, "outsider").await;

    let err = platform::resolve_active_workspace(&saas, &outsider, ws_id)
        .await
        .expect_err("non-member must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

// ─── is_tenant_member / is_workspace_member ────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn is_tenant_member_true_false(pool: PgPool) {
    let saas = setup(&pool).await;
    let (tenant_id, _ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;
    let outsider = make_user(&pool, "outsider").await;

    assert!(
        platform::is_tenant_member(&saas, owner.id, tenant_id)
            .await
            .unwrap(),
        "owner must be a tenant member"
    );
    assert!(
        !platform::is_tenant_member(&saas, outsider.id, tenant_id)
            .await
            .unwrap(),
        "outsider must not be a tenant member"
    );
    assert!(
        !platform::is_tenant_member(&saas, owner.id, Uuid::new_v4())
            .await
            .unwrap(),
        "random tenant_id → false"
    );
}

#[sqlx::test(migrations = "../db/migrations")]
async fn is_workspace_member_true_false(pool: PgPool) {
    let saas = setup(&pool).await;
    let (_tid, ws_id, owner) = provision_tenant_and_workspace(&pool, &saas).await;
    let outsider = make_user(&pool, "outsider").await;

    assert!(
        platform::is_workspace_member(&saas, owner.id, ws_id)
            .await
            .unwrap(),
        "owner must be a workspace member"
    );
    assert!(
        !platform::is_workspace_member(&saas, outsider.id, ws_id)
            .await
            .unwrap(),
        "outsider must not be a workspace member"
    );
    assert!(
        !platform::is_workspace_member(&saas, owner.id, Uuid::new_v4())
            .await
            .unwrap(),
        "random workspace_id → false"
    );
}
