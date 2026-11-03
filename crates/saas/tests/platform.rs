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
    let perms = ::access::get_permissions_for_role(
        state.access().expect("access"),
        "platform",
        &owner_key,
    )
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

    let ws = saas::tenant::create_workspace_with_owner(
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


// ─── Stage 5.0-A2.3: without_access + create_workspace_with_owner ──────────

/// Stage 5.0-A2.3: on a `without_access()` build, both
/// `create_tenant` (low-level) and `create_workspace` (bare, 4-arg)
/// succeed. Only `authz.require` + SQL, no `access::*`.
#[sqlx::test(migrations = "../db/migrations")]
async fn without_access_create_tenant_and_workspace(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    // Same pool, fresh CasbinAuthz (sees the g-row written above), no
    // AccessState.
    let casbin: Arc<dyn AuthorizationEngine> = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let no_rbac = SaasBuilder::new(pool.clone())
        .with_authz(casbin)
        .without_access()
        .build()
        .expect("build without_access");

    let tenant = platform::create_tenant(&no_rbac, &admin, unique_name("BareAcme"))
        .await
        .expect("create_tenant must work without access");

    // Create a g-row for `workspace:create` in the tenant domain so
    // `create_workspace`'s `authz.require` passes. `grant_role` is on
    // the engine, not on `access`, so it works on no_rbac.
    no_rbac
        .authz()
        .grant_role(
            admin.id,
            &domain::tenant_domain(tenant.id),
            "owner",
            &[("workspace".to_string(), "create".to_string())],
        )
        .await
        .unwrap();

    let ws = saas::tenant::create_workspace(&no_rbac, &admin, tenant.id, unique_name("BareEng"))
        .await
        .expect("create_workspace must work without access");
    assert_eq!(ws.tenant_id, tenant.id);
}

/// Stage 5.0-A2.3: RBAC-required methods on a `without_access()` build
/// fail with `Internal("RBAC not configured")` — the typed fast-fail
/// path that makes `without_access` auditable.
#[sqlx::test(migrations = "../db/migrations")]
async fn without_access_rbac_methods_fail(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let casbin: Arc<dyn AuthorizationEngine> = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let no_rbac = SaasBuilder::new(pool.clone())
        .with_authz(casbin)
        .without_access()
        .build()
        .expect("build without_access");

    // `provision_tenant` needs `access` for owner-role assignment.
    match platform::provision_tenant(
        &no_rbac,
        &admin,
        unique_name("ShouldFail"),
        &owner,
        &owner_key,
    )
    .await
    {
        Err(CoreError::Internal(msg)) => {
            assert!(msg.contains("RBAC not configured"), "msg: {msg}")
        }
        Err(other) => panic!("provision_tenant: expected Internal, got {other:?}"),
        Ok(_) => panic!("provision_tenant must fail without access"),
    }

    // `create_workspace_with_owner` — same story. Need a tenant first,
    // but we can't create one through provision_tenant (fails above).
    // Use `create_tenant` (low-level) and then hit the RBAC method.
    let tenant = platform::create_tenant(&no_rbac, &admin, unique_name("BareAcme"))
        .await
        .expect("create_tenant must work");
    // Grant `workspace:create` so the require inside
    // `create_workspace_with_owner` passes; the failure we're testing
    // is the `state.access()?` call, not the require.
    no_rbac
        .authz()
        .grant_role(
            admin.id,
            &domain::tenant_domain(tenant.id),
            "owner",
            &[("workspace".to_string(), "create".to_string())],
        )
        .await
        .unwrap();

    match saas::tenant::create_workspace_with_owner(
        &no_rbac,
        &admin,
        tenant.id,
        unique_name("ShouldFailEng"),
        &owner,
        &owner_key,
    )
    .await
    {
        Err(CoreError::Internal(msg)) => {
            assert!(msg.contains("RBAC not configured"), "msg: {msg}")
        }
        Err(other) => {
            panic!("create_workspace_with_owner: expected Internal, got {other:?}")
        }
        Ok(_) => panic!("create_workspace_with_owner must fail without access"),
    }
}

/// Stage 5.0-A2.3: `without_access()` without `with_authz(...)` fails at
/// `build()` time with `Internal("authorization engine is required")`.
/// Mirrors the inline unit test in `crates/saas/src/lib.rs`, but at the
/// integration layer (real `PgPool` type, not `connect_lazy`).
#[sqlx::test(migrations = "../db/migrations")]
async fn without_access_partial_authz_errors(pool: PgPool) {
    let result = SaasBuilder::new(pool).without_access().build();
    match result {
        Err(CoreError::Internal(msg)) => {
            assert!(
                msg.contains("authorization engine is required"),
                "unexpected message: {msg}"
            );
        }
        Err(other) => panic!("expected Internal, got {other:?}"),
        Ok(_) => panic!("build must fail without authz"),
    }
}

/// Stage 5.0-A2.3: contrast case for A2.2d
/// (`create_workspace_without_owner_does_not_assign`).
/// `create_workspace_with_owner` writes the owner into
/// `workspace_members` and a g-row into `casbin_rule`.
#[sqlx::test(migrations = "../db/migrations")]
async fn create_workspace_with_owner_assigns_owner(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let ws = saas::tenant::create_workspace_with_owner(
        &saas,
        &owner,
        tenant.id,
        unique_name("Eng"),
        &owner,
        &owner_key,
    )
    .await
    .expect("create_workspace_with_owner must succeed");

    let member_role: Option<String> = sqlx::query_scalar(
        "select role from workspace_members where workspace_id = $1 and user_id = $2",
    )
    .bind(ws.id)
    .bind(owner.id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(member_role.as_deref(), Some("owner"));

    let g_row: bool = sqlx::query_scalar(
        "select exists(select 1 from casbin_rule \
         where ptype = 'g' and v0 = $1 and v1 = 'owner' and v2 = $2)",
    )
    .bind(owner.id.to_string())
    .bind(domain::workspace_domain(ws.id))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(g_row, "create_workspace_with_owner must write a g-row");
}
