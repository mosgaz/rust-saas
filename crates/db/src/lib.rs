use sqlx::PgPool;

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Runs one or more `sqlx::Migrator` sets against `pool` in order.
///
/// **Composition with [`migrate`] is not supported.** sqlx verifies
/// `_sqlx_migrations` against the current `Migrator`: any applied version
/// that the migrator does not know about yields `VersionMissing`. So a
/// consumer must pick **one** path per database:
///
/// - **Full schema** — [`migrate`] (the workspace-wide set in
///   `crates/db/migrations/`). All `rust-saas` crates share the same
///   database.
/// - **Partial schema** — `migrate_with(&[audit_pg::MIGRATOR])` (or a
///   slice of per-crate migrators) against a **fresh** database. Only the
///   chosen tables are created. Each per-crate migrator is responsible for
///   the FK targets it needs (e.g. `audit-pg` ships a minimal
///   `000_users_bootstrap.sql`).
///
/// Consumers that need *both* the workspace set and a subset of it
/// (e.g. add `audit_log` to an already-migrated DB) should **not** call
/// `migrate_with`: the workspace set already contains those migrations.
/// A consumer with its own migrations beyond the workspace set composes
/// them into its own `Migrator` and runs it against a fresh DB.
///
/// Each per-crate `Migrator` uses its own version namespace
/// (`000_…`, `001_…`) to avoid colliding with the workspace set
/// (`YYYYMMDD…`) — but, again, mixing them on one DB is not supported.
///
/// Additive: a consumer that does not call `migrate_with` is unchanged.
pub async fn migrate_with(
    pool: &PgPool,
    migrators: &[&sqlx::migrate::Migrator],
) -> anyhow::Result<()> {
    for m in migrators {
        m.run(pool).await?;
    }
    Ok(())
}

