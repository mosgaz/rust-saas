//! SQL-level tests for the Resource Registry (Stage 5.0-A1.3).
//!
//! These tests pin the *database* invariants introduced by migrations
//! A1.1 (`resource_types` + 8 core kinds), A1.2 (trigger writes
//! `casbin_rule.p`), and A1.3 (`resource:manage` + FK
//! `permissions.resource → resource_types.name`). The Rust API
//! (`bootstrap_resource_type`, `add_action`, …) is Stage 5.0-A1.5 and
//! tested separately in `registry_api.rs`.
//!
//! All tests here go straight to SQL — no `CasbinAuthz`, no `AccessState`.
//! That keeps them focused on the schema, and independent of any
//! application-level reload/in-memory concerns (covered by A1.4's
//! `reload_in_memory_picks_up_external_p_row`).

use sqlx::PgPool;

/// A1.1: the 8 core resource types are bootstrapped by the first
/// migration; their names are already singular and match
/// `permissions.resource` exactly. If a future migration adds more core
/// types, update this list — the test is the contract.
#[sqlx::test(migrations = "../db/migrations")]
async fn resource_types_has_8_core(pool: PgPool) {
    let names: Vec<String> =
        sqlx::query_scalar("select name from resource_types order by name")
            .fetch_all(&pool)
            .await
            .expect("query resource_types");

    assert_eq!(
        names,
        vec![
            "audit".to_string(),
            "document".to_string(),
            "invitation".to_string(),
            "member".to_string(),
            "resource".to_string(),
            "role".to_string(),
            "tenant".to_string(),
            "workspace".to_string(),
        ],
        "A1.1 must bootstrap exactly these 8 core resource types"
    );

    // Every core type has at least one declared action. `default_actions`
    // is advisory; the point is "it's not empty".
    let empty: i64 = sqlx::query_scalar(
        "select count(*) from resource_types where cardinality(default_actions) = 0",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(empty, 0, "every core type must declare at least one action");
}

/// A1.3 step 2+3: `('resource', 'manage')` is added to `permissions`,
/// propagated to `role_permissions` for the platform owner, and (via the
/// A1.2 trigger) written to `casbin_rule.p`.
#[sqlx::test(migrations = "../db/migrations")]
async fn resource_manage_permission_added(pool: PgPool) {
    let perm_exists: bool = sqlx::query_scalar(
        "select exists(select 1 from permissions \
         where resource = 'resource' and action = 'manage')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(perm_exists, "A1.3 must add ('resource', 'manage')");

    let owner_has_rp: bool = sqlx::query_scalar(
        "select exists(select 1 from role_permissions rp \
         join roles r on r.id = rp.role_id \
         where r.key = 'owner' and r.domain = 'platform' \
           and rp.resource = 'resource' and rp.action = 'manage')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        owner_has_rp,
        "platform owner must hold ('resource', 'manage') in role_permissions"
    );

    let owner_has_p: bool = sqlx::query_scalar(
        "select exists(select 1 from casbin_rule \
         where ptype = 'p' and v0 = 'owner' and v1 = 'platform' \
           and v2 = 'resource' and v3 = 'manage')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        owner_has_p,
        "platform owner must hold ('resource', 'manage') in casbin_rule.p \
         (A1.2 trigger propagates it)"
    );
}

/// A1.3 step 4: FK `permissions.resource → resource_types.name` forbids
/// inserting a permission for an undeclared resource.
#[sqlx::test(migrations = "../db/migrations")]
async fn fk_permissions_resource_type_enforced(pool: PgPool) {
    let err = sqlx::query(
        "insert into permissions (resource, action, description) \
         values ('nonexistent_resource', 'read', 'should fail FK')",
    )
    .execute(&pool)
    .await
    .expect_err("FK must reject undeclared resource");

    let msg = err.to_string();
    assert!(
        msg.contains("fk_permissions_resource_type"),
        "expected FK violation on `fk_permissions_resource_type`, got: {msg}"
    );
}

/// A1.3 step 4: `ON DELETE RESTRICT` — a resource type that still has
/// permissions cannot be deleted. `(document, read)` and `(document,
/// write)` exist since the A1.1 bootstrap; `DELETE FROM resource_types
/// WHERE name = 'document'` must fail.
#[sqlx::test(migrations = "../db/migrations")]
async fn fk_permissions_resource_type_prevents_delete(pool: PgPool) {
    let err = sqlx::query("delete from resource_types where name = 'document'")
        .execute(&pool)
        .await
        .expect_err("ON DELETE RESTRICT must reject deleting a used resource type");

    let msg = err.to_string();
    assert!(
        msg.contains("fk_permissions_resource_type"),
        "expected FK violation on `fk_permissions_resource_type`, got: {msg}"
    );

    // Sanity: the row is still there.
    let exists: bool =
        sqlx::query_scalar("select exists(select 1 from resource_types where name = 'document')")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(exists, "document resource type must survive the rejected delete");
}

/// A1.3 step 1: legacy import. Simulates a consumer database that
/// predates A1.3 — custom permissions (`course`, `deal`) without a
/// `resource_types` row. We drop the FK, insert the "legacy"
/// permissions, replay the legacy-import SQL from the migration, and
/// assert the result. Restores the FK at the end so `#[sqlx::test]`'s
/// teardown sees a clean schema (the test DB is dropped anyway, but the
/// restore keeps the test self-explanatory).
#[sqlx::test(migrations = "../db/migrations")]
async fn legacy_custom_permissions_imported_before_fk(pool: PgPool) -> anyhow::Result<()> {
    // Simulate "before A1.3": drop the FK, then insert custom
    // permissions that would violate it.
    sqlx::query("alter table permissions drop constraint fk_permissions_resource_type")
        .execute(&pool)
        .await?;

    sqlx::query(
        "insert into permissions (resource, action, description) values \
         ('course', 'read', ''), \
         ('course', 'write', ''), \
         ('deal', 'read', ''), \
         ('deal', 'close', '')",
    )
    .execute(&pool)
    .await?;

    // Replay the legacy-import SQL exactly as the migration runs it.
    // Keeping the SQL here (instead of calling a Rust helper) is
    // deliberate: it tests the SQL that ships, not a wrapper that might
    // diverge.
    const LEGACY_IMPORT_SQL: &str = r#"
        INSERT INTO resource_types (name, scope, default_actions, description, metadata)
        SELECT
            p.resource,
            'custom:legacy',
            array_agg(DISTINCT p.action ORDER BY p.action),
            'Imported from permissions before Stage 5',
            '{"source": "legacy_import"}'::jsonb
        FROM permissions p
        WHERE p.resource NOT IN (SELECT name FROM resource_types)
        GROUP BY p.resource
        ON CONFLICT (name) DO NOTHING;
    "#;
    sqlx::raw_sql(LEGACY_IMPORT_SQL).execute(&pool).await?;

    // `course` and `deal` are now declared as `custom:legacy` with the
    // observed actions, sorted.
    let (scope, actions, meta): (String, Vec<String>, serde_json::Value) = sqlx::query_as(
        "select scope, default_actions, metadata from resource_types where name = 'course'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(scope, "custom:legacy");
    assert_eq!(actions, vec!["read".to_string(), "write".to_string()]);
    assert_eq!(meta["source"], "legacy_import");

    let (scope, actions, _meta): (String, Vec<String>, serde_json::Value) = sqlx::query_as(
        "select scope, default_actions, metadata from resource_types where name = 'deal'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(scope, "custom:legacy");
    assert_eq!(actions, vec!["close".to_string(), "read".to_string()]);

    // Restore the FK — every `permissions.resource` is now declared.
    sqlx::query(
        "alter table permissions add constraint fk_permissions_resource_type \
         foreign key (resource) references resource_types(name) \
         on update restrict on delete restrict",
    )
    .execute(&pool)
    .await?;

    Ok(())
}
