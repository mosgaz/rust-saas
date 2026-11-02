//! Integration tests for `authz-casbin` against a real PostgreSQL.
//!
//! `#[sqlx::test]` creates an isolated database per test, applies
//! `crates/db/migrations` (including `casbin_rule`), and drops it afterwards.
//!
//! `CasbinAuthz::from_pool` shares the test pool, so policies live in that
//! test database.
//!
//! Stage 3h adds two tests for `p`-rows dedup:
//! - `grant_role_is_idempotent_on_p_rows` — a repeated `grant_role` does not
//!   insert duplicate `p`-rows or `g`-rows (the `has_policy` /
//!   `has_grouping_policy` pre-check in `CasbinAuthz::grant_role`).
//! - `unique_index_rejects_duplicates` — the unique index
//!   `casbin_rule_unique_idx` (migration `20261110000001`) rejects a direct
//!   duplicate `INSERT`, as a safety net behind the pre-check.

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

#[sqlx::test(migrations = "../db/migrations")]
async fn has_role_reflects_g_rows(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain = "tenant:test-has";

    assert!(
        !authz
            .has_role(user_id, domain, "editor")
            .await
            .expect("has_role must not error"),
        "user must not hold a role before grant"
    );

    authz
        .grant_role(
            user_id,
            domain,
            "editor",
            &[("documents".to_string(), "read".to_string())],
        )
        .await
        .unwrap();

    assert!(
        authz.has_role(user_id, domain, "editor").await.unwrap(),
        "has_role must be true after grant"
    );
    assert!(
        !authz.has_role(user_id, domain, "viewer").await.unwrap(),
        "has_role must be false for a role the user does not hold"
    );

    let other_user = Uuid::new_v4();
    assert!(
        !authz.has_role(other_user, domain, "editor").await.unwrap(),
        "has_role must be per-user"
    );

    authz.revoke_role(user_id, domain, "editor").await.unwrap();
    assert!(
        !authz.has_role(user_id, domain, "editor").await.unwrap(),
        "has_role must be false after revoke"
    );
}

#[sqlx::test(migrations = "../db/migrations")]
async fn count_users_with_role_tracks_holders(pool: PgPool) {
    let authz = setup(&pool).await;
    let domain = "tenant:test-count";
    let perms = vec![("documents".to_string(), "read".to_string())];

    let c0 = authz
        .count_users_with_role(domain, "owner")
        .await
        .expect("count must succeed");
    assert_eq!(c0, 0, "no holders of an unused role");

    let u1 = Uuid::new_v4();
    let u2 = Uuid::new_v4();
    let u3 = Uuid::new_v4();

    authz.grant_role(u1, domain, "owner", &perms).await.unwrap();
    let c1 = authz.count_users_with_role(domain, "owner").await.unwrap();
    assert_eq!(c1, 1, "one holder after first grant");

    authz.grant_role(u2, domain, "owner", &perms).await.unwrap();
    let c2 = authz.count_users_with_role(domain, "owner").await.unwrap();
    assert_eq!(c2, 2, "two distinct holders");

    authz
        .grant_role(u3, domain, "editor", &perms)
        .await
        .unwrap();
    let c_owner = authz.count_users_with_role(domain, "owner").await.unwrap();
    assert_eq!(
        c_owner, 2,
        "count is per-role, editor does not affect owner"
    );

    authz.revoke_role(u2, domain, "owner").await.unwrap();
    let c_after = authz.count_users_with_role(domain, "owner").await.unwrap();
    assert_eq!(c_after, 1, "count decreases after revoke");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn purge_role_removes_g_and_p_rows_and_is_idempotent(pool: PgPool) {
    let authz = setup(&pool).await;
    let domain = "tenant:test-purge";
    let role_key = "auditor";

    let u1 = Uuid::new_v4();
    let u2 = Uuid::new_v4();
    let permissions = vec![
        ("documents".to_string(), "read".to_string()),
        ("members".to_string(), "list".to_string()),
    ];

    authz
        .grant_role(u1, domain, role_key, &permissions)
        .await
        .unwrap();
    // Grant the same role to a second user without re-listing permissions.
    // `grant_role` always writes a g-row; p-rows are role-level and already
    // present from the first grant. Re-listing permissions here would rely
    // on casbin-rs's `add_policy` deduplicating (role, domain, resource,
    // action) — which it does not guarantee; see handoff §16.
    authz.grant_role(u2, domain, role_key, &[]).await.unwrap();

    let g_rows: i64 =
        sqlx::query_scalar("select count(*) from casbin_rule where ptype='g' and v1=$1 and v2=$2")
            .bind(role_key)
            .bind(domain)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(g_rows, 2, "two g-rows (one per user)");

    let p_rows: i64 =
        sqlx::query_scalar("select count(*) from casbin_rule where ptype='p' and v0=$1 and v1=$2")
            .bind(role_key)
            .bind(domain)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(p_rows, 2, "one p-row per permission");

    let deleted = authz
        .purge_role(domain, role_key)
        .await
        .expect("purge_role must succeed");
    assert_eq!(deleted, 4, "purge must remove 2 g-rows + 2 p-rows");

    let remaining: i64 = sqlx::query_scalar(
        r#"
        select count(*) from casbin_rule
        where (ptype='g' and v1=$1 and v2=$2)
           or (ptype='p' and v0=$1 and v1=$2)
        "#,
    )
    .bind(role_key)
    .bind(domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 0, "no rows must remain after purge");

    assert!(
        !authz.can(u1, domain, "documents", "read").await.unwrap(),
        "in-memory model must not grant permission after purge"
    );
    assert!(
        !authz.has_role(u1, domain, role_key).await.unwrap(),
        "has_role must be false after purge"
    );

    let deleted_again = authz
        .purge_role(domain, role_key)
        .await
        .expect("second purge must not fail");
    assert_eq!(deleted_again, 0, "purge must be idempotent");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn purge_role_leaves_other_roles_and_domains_intact(pool: PgPool) {
    let authz = setup(&pool).await;
    let domain_a = "tenant:test-purge-scope-a";
    let domain_b = "tenant:test-purge-scope-b";

    let perms = vec![("documents".to_string(), "read".to_string())];
    let u = Uuid::new_v4();

    authz
        .grant_role(u, domain_a, "target", &perms)
        .await
        .unwrap();
    authz.grant_role(u, domain_a, "keep", &perms).await.unwrap();
    authz
        .grant_role(u, domain_b, "target", &perms)
        .await
        .unwrap();

    let deleted = authz.purge_role(domain_a, "target").await.unwrap();
    assert_eq!(deleted, 2, "one g-row + one p-row in domain_a");

    assert!(
        authz.can(u, domain_a, "documents", "read").await.unwrap(),
        "other role 'keep' must still grant permission in domain_a"
    );
    assert!(
        authz.can(u, domain_b, "documents", "read").await.unwrap(),
        "same role_key 'target' in domain_b must not be purged"
    );
    assert!(
        !authz.has_role(u, domain_a, "target").await.unwrap(),
        "target must be gone from domain_a"
    );
}

// ============================================================================
// Stage 3h: Idempotency and Unique Index Tests
// ============================================================================

/// Stage 3h: repeated `grant_role` must not insert duplicate `p`-rows (nor
/// duplicate `g`-rows). Checks `casbin_rule` directly, not just the in-memory
/// `can` result — the latter was already covered by `grant_role_is_idempotent`.
#[sqlx::test(migrations = "../db/migrations")]
async fn grant_role_is_idempotent_on_p_rows(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain = "tenant:test-idempotent-p-rows";
    let role_key = "editor";

    let permissions = vec![
        ("documents".to_string(), "read".to_string()),
        ("documents".to_string(), "write".to_string()),
        ("members".to_string(), "list".to_string()),
    ];

    authz
        .grant_role(user_id, domain, role_key, &permissions)
        .await
        .expect("first grant_role");

    let p_rows_first: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype = 'p' and v0 = $1 and v1 = $2",
    )
    .bind(role_key)
    .bind(domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        p_rows_first, 3,
        "first grant_role must insert exactly one p-row per permission"
    );

    let g_rows_first: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype = 'g' and v1 = $1 and v2 = $2",
    )
    .bind(role_key)
    .bind(domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        g_rows_first, 1,
        "first grant_role must insert exactly one g-row"
    );

    // Repeat with the same (user, domain, role, permissions).
    authz
        .grant_role(user_id, domain, role_key, &permissions)
        .await
        .expect("second grant_role must succeed");

    let p_rows_second: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype = 'p' and v0 = $1 and v1 = $2",
    )
    .bind(role_key)
    .bind(domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        p_rows_second, p_rows_first,
        "second grant_role must not add p-row duplicates (has_policy pre-check)"
    );

    let g_rows_second: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype = 'g' and v1 = $1 and v2 = $2",
    )
    .bind(role_key)
    .bind(domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        g_rows_second, g_rows_first,
        "second grant_role must not add g-row duplicates"
    );
}

/// Stage 3h: the unique index `casbin_rule_unique_idx` (migration
/// `20261110000001`) rejects a direct duplicate `INSERT`. This is a
/// belt-and-suspenders safety net behind `grant_role`'s `has_policy`
/// pre-check — it must survive even if a future code path forgets the
/// pre-check.
#[sqlx::test(migrations = "../db/migrations")]
async fn unique_index_rejects_duplicates(pool: PgPool) {
    // First row: succeed.
    sqlx::query(
        r#"
        insert into casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
        values ('p', 'editor', 'tenant:idx-test', 'documents', 'read', '', '')
        "#,
    )
    .execute(&pool)
    .await
    .expect("first insert must succeed");

    // Identical row: must violate the unique index.
    let err = sqlx::query(
        r#"
        insert into casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
        values ('p', 'editor', 'tenant:idx-test', 'documents', 'read', '', '')
        "#,
    )
    .execute(&pool)
    .await
    .expect_err("duplicate insert must fail the unique index");

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique") || msg.contains("duplicate"),
        "expected unique-violation, got: {msg}"
    );

    // Only one row exists.
    let count: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype = 'p' and v1 = 'tenant:idx-test'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "duplicate insert must not add a row");

    // A different `(ptype, v0, v1, v2, v3)` is allowed.
    sqlx::query(
        r#"
        insert into casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
        values ('p', 'editor', 'tenant:idx-test', 'documents', 'write', '', '')
        "#,
    )
    .execute(&pool)
    .await
    .expect("distinct row must succeed");
}

// ─── Stage 4.5b: cross-process race on `grant_role` ────────────────────────

/// Stage 4.5b: a cross-process unique violation on `casbin_rule_unique_idx`
/// must be treated as an idempotent success, and the in-memory enforcer
/// must be reloaded so this replica agrees with the database.
///
/// The test simulates "another replica already inserted this row" by
/// writing **directly** to `casbin_rule` (bypassing the in-memory
/// enforcer — exactly the state this replica would be in if a different
/// process had won the race). `grant_role` then runs with the same `p`-row
/// plus one non-racing `p`-row (`documents:write`) to also verify that the
/// coalesced `load_policy` does not clobber rows the same call just wrote.
///
/// Regressions this catches:
/// - without the 4.5b fix, `grant_role` returns `AuthzError::Internal`
///   (HTTP 500 in a multi-replica consumer),
/// - without the `load_policy()` after the violation, this replica's
///   `can` / `require` would disagree with the database (they would still
///   miss the racing row),
/// - without the `has_policy` pre-check from Stage 3h, this call would
///   double-insert the racing `p`-row on the `documents:write` side too —
///   the final uniqueness assertions catch that.
#[sqlx::test(migrations = "../db/migrations")]
async fn grant_role_survives_unique_violation(pool: PgPool) {
    let authz = setup(&pool).await;
    let user_id = Uuid::new_v4();
    let domain = "tenant:test-race";
    let role_key = "editor";

    // Simulate a `p`-row written by *another process*: go straight to
    // `casbin_rule`, not through `add_policy`. The in-memory enforcer of
    // *this* replica does not know about it — same state as after a
    // cross-process race.
    sqlx::query(
        r#"
        insert into casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
        values ('p', $1, $2, 'documents', 'read', '', '')
        "#,
    )
    .bind(role_key)
    .bind(domain)
    .execute(&pool)
    .await
    .expect("direct p-row insert simulating another process must succeed");

    // Same for the `g`-row: another replica granted the role first.
    sqlx::query(
        r#"
        insert into casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
        values ('g', $1, $2, $3, '', '', '')
        "#,
    )
    .bind(user_id.to_string())
    .bind(role_key)
    .bind(domain)
    .execute(&pool)
    .await
    .expect("direct g-row insert simulating another process must succeed");

    // This replica's in-memory enforcer knows neither row. `grant_role`
    // must:
    //   1. hit `casbin_rule_unique_idx` on `add_grouping_policy`,
    //   2. hit `casbin_rule_unique_idx` on `add_policy` (documents:read),
    //   3. successfully insert `documents:write` (no race on that one),
    //   4. reload once at the end (`needs_reload` coalesces 1–3),
    //   5. return `Ok(())`.
    authz
        .grant_role(
            user_id,
            domain,
            role_key,
            &[
                ("documents".to_string(), "read".to_string()),
                ("documents".to_string(), "write".to_string()),
            ],
        )
        .await
        .expect("grant_role must tolerate cross-process unique violation (Stage 4.5b)");

    // (a) In-memory model now agrees with DB: the racing row is visible.
    //     This is the load-bearing assertion — without `load_policy()` after
    //     the violation, `can` would return `false` here.
    assert!(
        authz.can(user_id, domain, "documents", "read").await.unwrap(),
        "replica must see the row another process wrote (load_policy after violation)"
    );

    // (b) The non-racing permission this call inserted also works: the
    //     coalesced reload must not clobber rows this call wrote itself.
    assert!(
        authz.can(user_id, domain, "documents", "write").await.unwrap(),
        "non-racing add_policy must still insert and survive the coalesced reload"
    );

    // (c) `has_role` (raw SQL against `casbin_rule`) sees the g-row. This
    //     is the DB side of the same check as (a) for the grouping row.
    assert!(
        authz.has_role(user_id, domain, role_key).await.unwrap(),
        "g-row must exist after race"
    );

    // (d) The unique index held: exactly one row per (ptype, v0..v3).
    let p_read_rows: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule \
         where ptype='p' and v0=$1 and v1=$2 and v2='documents' and v3='read'",
    )
    .bind(role_key)
    .bind(domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        p_read_rows, 1,
        "exactly one p-row for `documents:read` — unique index held across the race"
    );

    let g_rows: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule \
         where ptype='g' and v0=$1 and v1=$2 and v2=$3",
    )
    .bind(user_id.to_string())
    .bind(role_key)
    .bind(domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        g_rows, 1,
        "exactly one g-row for `(user, editor, domain)` — unique index held across the race"
    );
}
