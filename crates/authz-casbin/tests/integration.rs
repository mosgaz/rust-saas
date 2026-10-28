//! Integration tests for `authz-casbin` against a real PostgreSQL.
//!
//! `#[sqlx::test]` creates an isolated database per test, applies
//! `crates/db/migrations` (including `casbin_rule`), and drops it afterwards.
//!
//! `CasbinAuthz::from_pool` shares the test pool, so policies live in that
//! test database.

use authz::{AuthorizationEngine, AuthzError};
use authz_casbin::CasbinAuthz;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> CasbinAuthz {
    CasbinAuthz::from_pool(pool.clone())
        .await
        .expect("casbin init")
}

#[sqlx::test(migrations = "../db/migrations")]
async fn grant_role_grants_permissions_and_can_checks_them(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain = "tenant:test-grant";
    let role_key = "editor";

    let permissions = vec![
        ("documents".to_string(), "read".to_string()),
        ("documents".to_string(), "write".to_string()),
    ];

    authz
        .grant_role(user_id, domain, role_key, &permissions)
        .await
        .expect("grant_role must succeed");

    let can_read = authz
        .can(user_id, domain, "documents", "read")
        .await
        .unwrap();
    let can_write = authz
        .can(user_id, domain, "documents", "write")
        .await
        .unwrap();
    let can_delete = authz
        .can(user_id, domain, "documents", "delete")
        .await
        .unwrap();

    assert!(can_read, "must be able to read");
    assert!(can_write, "must be able to write");
    assert!(!can_delete, "must not be able to delete");

    authz
        .require(user_id, domain, "documents", "read")
        .await
        .expect("require must pass");
    let err = authz
        .require(user_id, domain, "documents", "delete")
        .await
        .expect_err("require must fail");
    assert!(matches!(err, AuthzError::Forbidden));
}

#[sqlx::test(migrations = "../db/migrations")]
async fn revoke_role_removes_permissions(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain = "tenant:test-revoke";
    let role_key = "editor";

    let permissions = vec![("documents".to_string(), "read".to_string())];

    authz
        .grant_role(user_id, domain, role_key, &permissions)
        .await
        .unwrap();

    let can_before = authz
        .can(user_id, domain, "documents", "read")
        .await
        .unwrap();
    assert!(can_before, "must have permission before revoke");

    authz
        .revoke_role(user_id, domain, role_key)
        .await
        .expect("revoke_role must succeed");

    let can_after = authz
        .can(user_id, domain, "documents", "read")
        .await
        .unwrap();
    assert!(!can_after, "must not have permission after revoke");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn domain_isolation(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain_a = "tenant:a";
    let domain_b = "tenant:b";

    let permissions = vec![("documents".to_string(), "read".to_string())];

    authz
        .grant_role(user_id, domain_a, "editor", &permissions)
        .await
        .unwrap();

    let can_a = authz
        .can(user_id, domain_a, "documents", "read")
        .await
        .unwrap();
    let can_b = authz
        .can(user_id, domain_b, "documents", "read")
        .await
        .unwrap();

    assert!(can_a, "must have permission in domain_a");
    assert!(!can_b, "must not have permission in domain_b");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn multiple_roles_in_same_domain_are_additive(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain = "workspace:test-multi";

    let role1_perms = vec![("documents".to_string(), "read".to_string())];
    let role2_perms = vec![("documents".to_string(), "write".to_string())];

    authz
        .grant_role(user_id, domain, "viewer", &role1_perms)
        .await
        .unwrap();
    authz
        .grant_role(user_id, domain, "editor", &role2_perms)
        .await
        .unwrap();

    let can_read = authz
        .can(user_id, domain, "documents", "read")
        .await
        .unwrap();
    let can_write = authz
        .can(user_id, domain, "documents", "write")
        .await
        .unwrap();

    assert!(can_read, "must have read from viewer role");
    assert!(can_write, "must have write from editor role");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn grant_role_is_idempotent(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain = "tenant:test-idempotent";
    let permissions = vec![("documents".to_string(), "read".to_string())];

    authz
        .grant_role(user_id, domain, "editor", &permissions)
        .await
        .expect("first grant");
    authz
        .grant_role(user_id, domain, "editor", &permissions)
        .await
        .expect("second grant must not fail");

    let can_read = authz
        .can(user_id, domain, "documents", "read")
        .await
        .unwrap();
    assert!(can_read, "permission must persist after duplicate grant");
}
