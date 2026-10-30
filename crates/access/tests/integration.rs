//! Integration tests for `access` against a real PostgreSQL.
//!
//! `#[sqlx::test]` creates an isolated database per test, applies
//! `crates/db/migrations` (which include the `permissions` reference table
//! and the bootstrap `platform` owner role), and drops it afterwards.
//!
//! A mock `AuthorizationEngine` is used to simulate the Casbin behavior. By
//! default it grants every action; a `deny` mode is available for negative
//! tests.

use std::sync::Arc;

use access::{AccessError, AccessState, RoleKey};
use authz::{AuthorizationEngine, AuthzError};
use chrono::Utc;
use domain::AuthUser;
use sqlx::PgPool;
use uuid::Uuid;

struct MockAuthz {
    deny: bool,
}

#[async_trait::async_trait]
impl AuthorizationEngine for MockAuthz {
    async fn can(
        &self,
        _user_id: Uuid,
        _domain: &str,
        _resource: &str,
        _action: &str,
    ) -> Result<bool, AuthzError> {
        Ok(!self.deny)
    }

    async fn require(
        &self,
        _user_id: Uuid,
        _domain: &str,
        _resource: &str,
        _action: &str,
    ) -> Result<(), AuthzError> {
        if self.deny {
            Err(AuthzError::Forbidden)
        } else {
            Ok(())
        }
    }

    async fn grant_role(
        &self,
        _user_id: Uuid,
        _domain: &str,
        _role_key: &str,
        _permissions: &[(String, String)],
    ) -> Result<(), AuthzError> {
        Ok(())
    }

    async fn revoke_role(
        &self,
        _user_id: Uuid,
        _domain: &str,
        _role_key: &str,
    ) -> Result<(), AuthzError> {
        Ok(())
    }

    async fn has_role(
        &self,
        _user_id: Uuid,
        _domain: &str,
        _role_key: &str,
    ) -> Result<bool, AuthzError> {
        Ok(false)
    }

    async fn count_users_with_role(
        &self,
        _domain: &str,
        _role_key: &str,
    ) -> Result<i64, AuthzError> {
        Ok(0)
    }

    async fn purge_role(&self, _domain: &str, _role_key: &str) -> Result<u64, AuthzError> {
        Ok(0)
    }
}

fn setup(pool: PgPool, deny: bool) -> Arc<AccessState> {
    let authz = Arc::new(MockAuthz { deny });
    Arc::new(AccessState::new(pool, authz))
}

fn actor() -> AuthUser {
    AuthUser {
        id: Uuid::new_v4(),
        email: "admin@example.test".to_string(),
        email_verified: true,
        created_at: Utc::now(),
    }
}

#[sqlx::test(migrations = "../db/migrations")]
async fn create_owner_role_grants_all_permissions_and_is_idempotent(pool: PgPool) {
    let state = setup(pool.clone(), false);
    let domain = "tenant:test-owner";

    let role1 = access::create_owner_role(&state, domain)
        .await
        .expect("create_owner_role must succeed");
    assert_eq!(role1.key.as_str(), "owner");
    assert!(role1.protected);
    assert!(role1.immutable);

    let all_perms = access::list_permissions(&state).await.unwrap();
    assert_eq!(
        role1.permissions.len(),
        all_perms.len(),
        "owner must have all permissions from the reference table"
    );

    let role2 = access::create_owner_role(&state, domain)
        .await
        .expect("idempotent create_owner_role must succeed");
    assert_eq!(
        role1.id, role2.id,
        "idempotent call must return the same row"
    );

    let count: i64 = sqlx::query_scalar("select count(*) from roles where domain = $1")
        .bind(domain)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "idempotent call must not insert a duplicate role");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn create_role_persists_role_and_permissions(pool: PgPool) {
    let state = setup(pool.clone(), false);
    let actor = actor();
    let domain = "tenant:test-create";
    let key = RoleKey::parse("test_role").unwrap();

    let permissions = vec![
        ("documents".to_string(), "read".to_string()),
        ("documents".to_string(), "write".to_string()),
    ];

    let role = access::create_role(
        &state,
        &actor,
        domain,
        &key,
        "Test Role".to_string(),
        "A test role".to_string(),
        &permissions,
    )
    .await
    .expect("create_role must succeed");

    assert_eq!(role.key.as_str(), "test_role");
    assert!(!role.protected);
    assert!(!role.immutable);
    assert_eq!(role.permissions.len(), 2);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn create_role_rejects_unknown_permission(pool: PgPool) {
    let state = setup(pool, false);
    let actor = actor();
    let domain = "tenant:test-invalid-perm";
    let key = RoleKey::parse("bad_role").unwrap();

    let permissions = vec![("unknown".to_string(), "action".to_string())];

    let err = access::create_role(
        &state,
        &actor,
        domain,
        &key,
        "Bad Role".to_string(),
        "".to_string(),
        &permissions,
    )
    .await
    .expect_err("unknown permission must be rejected");

    assert!(matches!(err, AccessError::PermissionNotFound(_, _)));
}

#[sqlx::test(migrations = "../db/migrations")]
async fn update_and_delete_protected_role_are_rejected(pool: PgPool) {
    let state = setup(pool, false);
    let actor = actor();
    let domain = "tenant:test-protected";

    let role = access::create_owner_role(&state, domain).await.unwrap();

    let update_err = access::update_role(
        &state,
        &actor,
        role.id,
        "New Name".to_string(),
        "".to_string(),
        &[],
    )
    .await
    .expect_err("updating protected role must fail");
    assert!(matches!(update_err, AccessError::Protected));

    let delete_err = access::delete_role(&state, &actor, role.id)
        .await
        .expect_err("deleting protected role must fail");
    assert!(matches!(delete_err, AccessError::Protected));
}

#[sqlx::test(migrations = "../db/migrations")]
async fn get_role_and_get_permissions_for_role(pool: PgPool) {
    let state = setup(pool, false);
    let actor = actor();
    let domain = "tenant:test-get";
    let key = RoleKey::parse("custom").unwrap();

    access::create_role(
        &state,
        &actor,
        domain,
        &key,
        "Custom".to_string(),
        "".to_string(),
        &[("documents".to_string(), "read".to_string())],
    )
    .await
    .unwrap();

    let role = access::get_role(&state, domain, &key).await.unwrap();
    assert!(role.is_some());
    assert_eq!(role.unwrap().key.as_str(), "custom");

    let perms = access::get_permissions_for_role(&state, domain, &key)
        .await
        .unwrap();
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0], ("documents".to_string(), "read".to_string()));

    let missing = access::get_role(&state, domain, &RoleKey::parse("missing").unwrap())
        .await
        .unwrap();
    assert!(missing.is_none());
}

#[sqlx::test(migrations = "../db/migrations")]
async fn require_fails_if_authz_denies(pool: PgPool) {
    let state = setup(pool, true); // deny = true
    let actor = actor();
    let domain = "tenant:test-deny";

    let err = access::create_role(
        &state,
        &actor,
        domain,
        &RoleKey::parse("denied").unwrap(),
        "Denied".to_string(),
        "".to_string(),
        &[],
    )
    .await
    .expect_err("require must deny");

    assert!(matches!(err, AccessError::Forbidden));
}
