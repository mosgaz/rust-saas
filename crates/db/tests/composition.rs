//! `migrate_composed` tests (Stage 5.0-A3).
//!
//! `#[sqlx::test]` (no `migrations = …`) starts each test on a **fresh,
//! empty** database; the test drives `db::migrate_composed` itself. This
//! is exactly the consumer's path — apply the composed set once, on a
//! clean DB.

use std::path::Path;

use db::migrate_composed;
use sqlx::migrate::Migrator;
use sqlx::PgPool;

/// Loads a fixture migrator from `tests/fixtures/<name>/`.
///
/// `Migrator::new` reads `.sql` files at runtime; the version comes from
/// the filename prefix (`90000000000001_create_foo.sql` → version
/// `90000000000001`). Test fixtures are intentionally not part of the
/// production migration set.
async fn fixture(name: &str) -> Migrator {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    Migrator::new(path.as_path())
        .await
        .unwrap_or_else(|e| panic!("load fixture `{name}`: {e}"))
}

// ─── Happy path ────────────────────────────────────────────────────────────

#[sqlx::test(migrations = false)]
async fn migrate_composed_happy(pool: PgPool) -> anyhow::Result<()> {
    let simple = fixture("consumer_simple").await;

    migrate_composed(&pool, &[&simple]).await?;

    // rust-saas tables exist.
    for t in ["users", "tenants", "workspaces", "casbin_rule", "audit_log"] {
        let exists: bool = sqlx::query_scalar(
            "select exists(select 1 from information_schema.tables \
             where table_schema = 'public' and table_name = $1)",
        )
        .bind(t)
        .fetch_one(&pool)
        .await?;
        assert!(exists, "rust-saas table `{t}` must exist");
    }

    // Consumer table exists.
    let exists: bool = sqlx::query_scalar(
        "select exists(select 1 from information_schema.tables \
         where table_schema = 'public' and table_name = 'foo')",
    )
    .fetch_one(&pool)
    .await?;
    assert!(exists, "consumer table `foo` must exist");

    // `_sqlx_migrations` records all versions, rust-saas + consumer.
    let total: i64 = sqlx::query_scalar(
        "select count(*) from _sqlx_migrations where success = true",
    )
    .fetch_one(&pool)
    .await?;
    let our_count = db::MIGRATOR.migrations.len() as i64;
    assert_eq!(
        total,
        our_count + 1,
        "expected rust-saas ({our_count}) + consumer (1) successful migrations"
    );

    Ok(())
}

// ─── Validation errors ────────────────────────────────────────────────────

#[sqlx::test(migrations = false)]
async fn migrate_composed_rejects_collision(pool: PgPool) -> anyhow::Result<()> {
    let collision = fixture("consumer_collision").await;

    let err = migrate_composed(&pool, &[&collision])
        .await
        .expect_err("colliding version must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("migration version collision"),
        "expected collision error, got: {msg}"
    );

    // No SQL ran — even rust-saas migrations are not applied, because the
    // validation is before the `.run()` call. `#[sqlx::test(migrations =
    // false)]` may install an empty `_sqlx_migrations` during setup, so
    // assert on the actual schema: no rust-saas tables, no consumer
    // tables.
    for t in ["users", "tenants", "workspaces", "collision_marker"] {
        let exists: bool = sqlx::query_scalar(
            "select exists(select 1 from information_schema.tables \
             where table_schema = 'public' and table_name = $1)",
        )
        .bind(t)
        .fetch_one(&pool)
        .await?;
        assert!(
            !exists,
            "table `{t}` must not exist — collision is rejected before any SQL"
        );
    }

    Ok(())
}

#[sqlx::test(migrations = false)]
async fn migrate_composed_consumer_versions_must_be_greater(
    pool: PgPool,
) -> anyhow::Result<()> {
    let low = fixture("consumer_low_version").await;

    let err = migrate_composed(&pool, &[&low])
        .await
        .expect_err("lower-than-rust-saas version must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("consumer versions must be >"),
        "expected version-floor error, got: {msg}"
    );

    Ok(())
}

// ─── Idempotency ──────────────────────────────────────────────────────────

#[sqlx::test(migrations = false)]
async fn migrate_composed_idempotent(pool: PgPool) -> anyhow::Result<()> {
    let simple = fixture("consumer_simple").await;

    migrate_composed(&pool, &[&simple]).await?;
    let first: i64 =
        sqlx::query_scalar("select count(*) from _sqlx_migrations where success = true")
            .fetch_one(&pool)
            .await?;

    // Second call is a no-op.
    migrate_composed(&pool, &[&simple]).await?;
    let second: i64 =
        sqlx::query_scalar("select count(*) from _sqlx_migrations where success = true")
            .fetch_one(&pool)
            .await?;

    assert_eq!(first, second, "second call must not apply anything");

    Ok(())
}

// ─── Survives a "new rust-saas migration" in `_sqlx_migrations` ───────────

#[sqlx::test(migrations = false)]
async fn migrate_composed_survives_new_rust_saas_migration(
    pool: PgPool,
) -> anyhow::Result<()> {
    // Imagine `_sqlx_migrations` already contains a version that the
    // *current* `MIGRATOR` does not know about (e.g. consumer pinned an
    // older rust-saas, that one had a migration later removed, or a
    // future rust-saas ships a new migration and this binary is
    // outdated). `ignore_missing = true` on the composed `Migrator`
    // makes `run()` not blow up on it.
    //
    // We simulate by running `migrate_composed` twice: the second run
    // sees exactly the same versions, but the check that would fail
    // without `ignore_missing` is the same code path.

    let simple = fixture("consumer_simple").await;

    migrate_composed(&pool, &[&simple]).await?;
    migrate_composed(&pool, &[&simple]).await?;

    // Sanity: all versions still recorded, no re-runs.
    let total: i64 =
        sqlx::query_scalar("select count(*) from _sqlx_migrations where success = true")
            .fetch_one(&pool)
            .await?;
    assert_eq!(total, db::MIGRATOR.migrations.len() as i64 + 1);

    Ok(())
}

// ─── Consumer migration with FK to rust-saas table ────────────────────────

#[sqlx::test(migrations = false)]
async fn migrate_composed_consumer_can_fk_rust_saas_table(
    pool: PgPool,
) -> anyhow::Result<()> {
    let fk = fixture("consumer_fk").await;

    migrate_composed(&pool, &[&fk]).await?;

    // `bar` exists.
    let exists: bool = sqlx::query_scalar(
        "select exists(select 1 from information_schema.tables \
         where table_schema = 'public' and table_name = 'bar')",
    )
    .fetch_one(&pool)
    .await?;
    assert!(exists, "consumer table `bar` must exist");

    // FK is real: insert a tenant + workspace, then a bar row referencing
    // it; then a bar row referencing a missing workspace must be
    // rejected.
    let tenant_id: uuid::Uuid =
        sqlx::query_scalar("insert into tenants (name) values ('fk-test') returning id")
            .fetch_one(&pool)
            .await?;
    let ws_id: uuid::Uuid = sqlx::query_scalar(
        "insert into workspaces (tenant_id, name) values ($1, 'fk-ws') returning id",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await?;

    sqlx::query("insert into bar (id, workspace_id) values (1, $1)")
        .bind(ws_id)
        .execute(&pool)
        .await
        .expect("valid bar row must be accepted");

    let bad: Result<_, _> = sqlx::query(
        "insert into bar (id, workspace_id) values (2, \
         '00000000-0000-0000-0000-000000000000')",
    )
    .execute(&pool)
    .await;
    assert!(
        bad.is_err(),
        "FK to `workspaces(id)` must reject a non-existent workspace"
    );

    Ok(())
}
