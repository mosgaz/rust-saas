//! API-level tests for `access::registry` (Stage 5.0-A1.5c).
//!
//! Mirror of `registry.rs` (SQL-level, A1.3): these go through the Rust
//! API (`bootstrap_resource_type(s)`, `register_resource_type`,
//! `add_action`) and assert both the DB state and the in-memory enforcer
//! (which `reload_in_memory` from A1.4 refreshes).
//!
//! `CasbinAuthz` is used as the concrete `AuthorizationEngine` — the
//! "in-memory enforcer sees the new permission same-process" assertions
//! (regression for blocker B3) only make sense with a real engine.

use std::sync::Arc;

use access::registry::{self, ResourceType};
use access::{AccessError, AccessState};
use authz::AuthorizationEngine;
use authz_casbin::CasbinAuthz;
use chrono::Utc;
use domain::AuthUser;
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> (AccessState, Arc<dyn AuthorizationEngine>) {
    let casbin = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let authz: Arc<dyn AuthorizationEngine> = casbin;
    let state = AccessState::new(pool.clone(), authz.clone());
    (state, authz)
}

fn actor() -> AuthUser {
    AuthUser {
        id: Uuid::new_v4(),
        email: "admin@example.test".to_string(),
        email_verified: true,
        created_at: Utc::now(),
    }
}

/// Grant the `platform` `owner` role to `user_id` using the current
/// `permissions` reference table. Mirrors what `seed` does in `main.rs`.
async fn grant_platform_owner(
    pool: &PgPool,
    authz: &Arc<dyn AuthorizationEngine>,
    user_id: Uuid,
) {
    let owner_key = access::RoleKey::parse("owner").unwrap();
    let perms = access::get_permissions_for_role(
        &AccessState::new(pool.clone(), authz.clone()),
        domain::PLATFORM_DOMAIN,
        &owner_key,
    )
    .await
    .unwrap();
    authz
        .grant_role(user_id, domain::PLATFORM_DOMAIN, "owner", &perms)
        .await
        .unwrap();
}

// ─── bootstrap_resource_type / bootstrap_resource_types ────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn bootstrap_resource_type_creates_row_and_permissions(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    registry::bootstrap_resource_type(
        &pool,
        &authz,
        &ResourceType::workspace("course", &["read", "write", "publish"])
            .with_description("LMS course"),
    )
    .await
    .expect("bootstrap must succeed");

    let row: (String, Vec<String>, String) = sqlx::query_as(
        "select scope, default_actions, description from resource_types where name = 'course'",
    )
    .fetch_one(&pool)
    .await
    .expect("course row must exist");
    assert_eq!(row.0, "workspace");
    assert_eq!(row.1, vec!["publish", "read", "write"]);
    assert_eq!(row.2, "LMS course");

    for action in ["read", "write", "publish"] {
        let exists: bool = sqlx::query_scalar(
            "select exists(select 1 from permissions \
             where resource = 'course' and action = $1)",
        )
        .bind(action)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(exists, "permissions must contain ('course', {action})");
    }
}

#[sqlx::test(migrations = "../db/migrations")]
async fn bootstrap_resource_type_idempotent(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    let rt = ResourceType::workspace("course", &["read", "write"]);

    registry::bootstrap_resource_type(&pool, &authz, &rt)
        .await
        .expect("first bootstrap");
    registry::bootstrap_resource_type(&pool, &authz, &rt)
        .await
        .expect("second bootstrap must not fail");

    let count: i64 =
        sqlx::query_scalar("select count(*) from resource_types where name = 'course'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1, "second bootstrap must not add a duplicate row");

    let perms: i64 = sqlx::query_scalar(
        "select count(*) from permissions where resource = 'course'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(perms, 2, "second bootstrap must not add duplicate permissions");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn bootstrap_resource_type_merges_actions_and_metadata(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    let first = ResourceType::workspace("course", &["read"])
        .with_metadata(serde_json::json!({"tag": "lms", "tier": "free"}));
    registry::bootstrap_resource_type(&pool, &authz, &first)
        .await
        .unwrap();

    let second = ResourceType::workspace("course", &["read", "write"])
        .with_metadata(serde_json::json!({"tier": "pro"}));
    registry::bootstrap_resource_type(&pool, &authz, &second)
        .await
        .unwrap();

    let (actions, metadata): (Vec<String>, serde_json::Value) = sqlx::query_as(
        "select default_actions, metadata from resource_types where name = 'course'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actions, vec!["read", "write"], "actions are unioned");
    assert_eq!(metadata["tag"], "lms", "metadata is merged (old key kept)");
    assert_eq!(metadata["tier"], "pro", "metadata is merged (new value wins)");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn bootstrap_resource_type_rejects_scope_change(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    let ws = ResourceType::workspace("course", &["read"]);
    registry::bootstrap_resource_type(&pool, &authz, &ws)
        .await
        .unwrap();

    let tenant = ResourceType::tenant("course", &["read"]);
    let err = registry::bootstrap_resource_type(&pool, &authz, &tenant)
        .await
        .expect_err("scope change must be rejected");
    match err {
        AccessError::ScopeMismatch {
            name,
            existing,
            requested,
        } => {
            assert_eq!(name, "course");
            assert_eq!(existing, "workspace");
            assert_eq!(requested, "tenant");
        }
        other => panic!("expected ScopeMismatch, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../db/migrations")]
async fn bootstrap_resource_types_batch_one_reload(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    // Spy: count `reload_in_memory` calls. Wrapping `CasbinAuthz` is
    // heavier than the assertion is worth, so we assert the observable
    // outcome instead: after one batch call, the in-memory enforcer
    // knows every new permission.
    let owner_id = Uuid::new_v4();
    grant_platform_owner(&pool, &authz, owner_id).await;

    let batch = [
        ResourceType::workspace("course", &["read"]),
        ResourceType::workspace("assignment", &["read", "grade"]),
        ResourceType::tenant("batch", &["read", "manage"]),
        ResourceType::tenant("file", &["read", "write", "delete"]),
        ResourceType::platform("report", &["read"]),
    ];
    registry::bootstrap_resource_types(&pool, &authz, &batch)
        .await
        .expect("batch bootstrap must succeed");

    // Owner must see every new permission in memory (regression for B3).
    for (resource, action) in [
        ("course", "read"),
        ("assignment", "read"),
        ("assignment", "grade"),
        ("batch", "read"),
        ("batch", "manage"),
        ("file", "read"),
        ("file", "write"),
        ("file", "delete"),
        ("report", "read"),
    ] {
        assert!(
            authz
                .can(owner_id, domain::PLATFORM_DOMAIN, resource, action)
                .await
                .unwrap(),
            "owner must see ({resource}, {action}) after batch bootstrap"
        );
    }
}

#[sqlx::test(migrations = "../db/migrations")]
async fn bootstrap_resource_types_rejects_duplicate_scope_mismatch(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    let batch = [
        ResourceType::workspace("course", &["read"]),
        ResourceType::tenant("course", &["read"]),
    ];
    let err = registry::bootstrap_resource_types(&pool, &authz, &batch)
        .await
        .expect_err("in-batch scope mismatch must be rejected");
    assert!(matches!(err, AccessError::ScopeMismatch { .. }));

    // Nothing got committed (pre-flight is outside the tx).
    let count: i64 =
        sqlx::query_scalar("select count(*) from resource_types where name = 'course'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0, "rejected batch must not have written anything");
}

// ─── In-memory reload (B3 regression) ──────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn owner_sees_new_resource_type_in_enforce_same_process(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    let owner_id = Uuid::new_v4();
    grant_platform_owner(&pool, &authz, owner_id).await;

    // Sanity: `course:read` is not granted yet.
    assert!(
        !authz
            .can(owner_id, domain::PLATFORM_DOMAIN, "course", "read")
            .await
            .unwrap(),
        "setup: `course:read` must not be granted yet"
    );

    registry::bootstrap_resource_type(
        &pool,
        &authz,
        &ResourceType::workspace("course", &["read"]),
    )
    .await
    .unwrap();

    // Regression for B3: the in-memory enforcer must see the new
    // `(course, read)` permission without a process restart.
    assert!(
        authz
            .can(owner_id, domain::PLATFORM_DOMAIN, "course", "read")
            .await
            .unwrap(),
        "in-memory enforcer must see `course:read` after bootstrap + reload"
    );
}

// ─── register_resource_type / add_action (permission-checked) ──────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn register_resource_type_requires_platform_resource_manage(pool: PgPool) {
    let (state, authz) = setup(&pool).await;
    let admin = actor();
    // Not a platform owner — must be rejected by `require`.
    let err = registry::register_resource_type(
        &state,
        &admin,
        &ResourceType::workspace("course", &["read"]),
    )
    .await
    .expect_err("non-platform-owner must be forbidden");
    assert!(matches!(err, AccessError::Forbidden), "got {err:?}");

    // Sanity: nothing was inserted.
    let count: i64 =
        sqlx::query_scalar("select count(*) from resource_types where name = 'course'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);

    // Now grant platform owner to `admin` and retry.
    grant_platform_owner(&pool, &authz, admin.id).await;

    registry::register_resource_type(
        &state,
        &admin,
        &ResourceType::workspace("course", &["read"]),
    )
    .await
    .expect("platform owner must be allowed");

    let count: i64 =
        sqlx::query_scalar("select count(*) from resource_types where name = 'course'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn add_action_unknown_resource_type_returns_typed_error(pool: PgPool) {
    let (state, authz) = setup(&pool).await;
    let admin = actor();
    grant_platform_owner(&pool, &authz, admin.id).await;

    let err = registry::add_action(&state, &admin, "nonexistent", "read")
        .await
        .expect_err("unknown resource type must be rejected");
    match err {
        AccessError::UnknownResourceType { name } => assert_eq!(name, "nonexistent"),
        other => panic!("expected UnknownResourceType, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../db/migrations")]
async fn runtime_add_action_propagates_to_owner_same_process(pool: PgPool) {
    let (state, authz) = setup(&pool).await;
    let admin = actor();
    grant_platform_owner(&pool, &authz, admin.id).await;

    // Declare a resource type with one action, then add a second.
    registry::bootstrap_resource_type(
        &pool,
        &authz,
        &ResourceType::workspace("course", &["read"]),
    )
    .await
    .unwrap();

    // Owner sees `course:read` but not `course:publish` yet.
    assert!(
        authz
            .can(admin.id, domain::PLATFORM_DOMAIN, "course", "read")
            .await
            .unwrap()
    );
    assert!(
        !authz
            .can(admin.id, domain::PLATFORM_DOMAIN, "course", "publish")
            .await
            .unwrap()
    );

    registry::add_action(&state, &admin, "course", "publish")
        .await
        .expect("add_action must succeed");

    // Owner sees the new permission in memory (A1.4 reload).
    assert!(
        authz
            .can(admin.id, domain::PLATFORM_DOMAIN, "course", "publish")
            .await
            .unwrap(),
        "in-memory enforcer must see `course:publish` after add_action"
    );
}

// ─── list_resource_types / bootstrap_all_core ───────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn list_resource_types_returns_all(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    // 8 core from A1.1.
    let core = registry::list_resource_types(&pool).await.unwrap();
    assert_eq!(core.len(), 8, "8 core types from A1.1");

    // Add one custom type; now 9.
    registry::bootstrap_resource_type(
        &pool,
        &authz,
        &ResourceType::workspace("course", &["read"]),
    )
    .await
    .unwrap();

    let all = registry::list_resource_types(&pool).await.unwrap();
    assert_eq!(all.len(), 9);
    let course = all.iter().find(|r| r.name == "course").unwrap();
    assert!(matches!(course.scope, access::registry::ResourceScope::Workspace));
}

#[sqlx::test(migrations = "../db/migrations")]
async fn bootstrap_all_core_creates_8_types(pool: PgPool) {
    let (_state, authz) = setup(&pool).await;

    // The migration already inserted them; `bootstrap_all_core` is
    // idempotent and must not error or duplicate.
    registry::bootstrap_all_core(&pool, &authz)
        .await
        .expect("bootstrap_all_core must be idempotent");

    let count: i64 = sqlx::query_scalar("select count(*) from resource_types")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 8);
}

// ─── Scope declared, not enforced ──────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn scope_is_declared_not_enforced(pool: PgPool) {
    // The migration sets `document` → `workspace`. A `p`-row in a tenant
    // domain that references `document` is legal (scope is declared, not
    // enforced — see A1.1's header). We insert such a row directly
    // (bypassing `grant_role`) — no FK violation, no check.
    let _ = sqlx::query(
        "insert into casbin_rule (ptype, v0, v1, v2, v3, v4, v5) \
         values ('p', 'editor', 'tenant:test-scope', 'document', 'read', '', '')",
    )
    .execute(&pool)
    .await
    .expect("scope must not be enforced at the DB level");

    // Sanity: the `workspace` scope declared in the migration is still
    // what `list_resource_types` reports.
    let scope: String =
        sqlx::query_scalar("select scope from resource_types where name = 'document'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(scope, "workspace");
}
