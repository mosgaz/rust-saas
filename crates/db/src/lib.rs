//! PostgreSQL connection helper and migrations runner.
//!
//! Three entry points:
//!
//! - [`connect`] — opens a `PgPool` from a URL. Thin wrapper; no pool
//!   tuning (a consumer that needs `PgPoolOptions` builds its own).
//! - [`migrate`] — applies the **workspace-wide** migration set
//!   (`crates/db/migrations/`, embedded via `sqlx::migrate!`). All
//!   `rust-saas` crates share one database; this is the standard path.
//! - [`migrate_composed`] — applies the workspace set **plus** one or
//!   more consumer-supplied `Migrator`s, in one run. This is how an
//!   external consumer keeps their own `courses`/`files`/… tables in the
//!   same database without forking `crates/db/migrations`.
//!
//! `migrate_composed` is the evolution of the Stage 4.3c `migrate_with`
//! helper, which could only run per-crate sets against a **fresh**
//! database (composition with `migrate` was unsupported: sqlx's
//! `_sqlx_migrations` verification yields `VersionMissing` for any
//! applied version the running `Migrator` does not know about).
//! `migrate_composed` sidesteps that by building a single `Migrator`
//! that contains the union of all versions and runs it with
//! `ignore_missing = true`.

use std::borrow::Cow;
use std::collections::HashSet;

use sqlx::migrate::{Migration, Migrator};
use sqlx::PgPool;

/// The workspace-wide migration set (`crates/db/migrations/`), embedded
/// at compile time. Version namespace: `YYYYMMDDNNNNNNNN` (14+ digits).
///
/// Public so `migrate_composed` (and external tooling) can inspect the
/// version numbers without re-running the macro.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Recommended version prefix for consumer-owned migrations:
/// `90000000000000` and up. `migrate_composed` enforces
/// `consumer_version > max(rust_saas_version)`; the convention makes
/// the intent obvious and leaves room for future rust-saas migrations
/// below the prefix.
pub const CONSUMER_VERSION_FLOOR: i64 = 90_000_000_000_000;

/// Opens a `PgPool` from a connection URL. See module docs.
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    Ok(pool)
}

/// Applies the workspace-wide migration set. See module docs.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}

/// Applies the workspace-wide set **plus** every `consumers` migrator,
/// in one run.
///
/// # Validation (before any SQL runs)
///
/// 1. **No version collision.** A consumer version that already exists
///    in [`MIGRATOR`] is a hard error — the consumer would be re-running
///    a rust-saas migration under a different description.
/// 2. **Consumer versions are above `max(rust-saas versions)`.** sqlx
///    sorts by `version`; a consumer migration with a lower version
///    would run **before** rust-saas, and its SQL may reference tables
///    that do not exist yet. Use [`CONSUMER_VERSION_FLOOR`] (or higher).
///
/// # Execution
///
/// Builds one `Migrator` from the union of versions, sets
/// `ignore_missing = true` (so `_sqlx_migrations` may contain versions
/// this run does not know about — the normal case for a consumer that
/// already applied an older `rust-saas` set), and runs it. Idempotent:
/// a second call is a no-op.
///
/// # Errors
///
/// - `MigrateError::VersionCollision` (wrapped) — if a consumer version
///   equals a rust-saas version.
/// - `MigrateError::VersionNotGreater` (wrapped) — if a consumer version
///   is not greater than `max(rust-saas version)`.
/// - Any `sqlx::Error` from the underlying `run`.
pub async fn migrate_composed(
    pool: &PgPool,
    consumers: &[&Migrator],
) -> anyhow::Result<()> {
    // 1. Collect rust-saas versions and their maximum.
    let ours: HashSet<i64> = MIGRATOR.migrations.iter().map(|m| m.version).collect();
    let our_max = ours.iter().copied().max().unwrap_or(0);

    // 2. Validate each consumer migration.
    for consumer in consumers {
        for m in consumer.migrations.iter() {
            if ours.contains(&m.version) {
                anyhow::bail!(
                    "migration version collision: {} (\"{}\") already used by \
                     rust-saas; consumer versions must be distinct",
                    m.version,
                    m.description
                );
            }
            if our_max > 0 && m.version < our_max {
                anyhow::bail!(
                    "migration version {} (\"{}\") < rust-saas max {}; \
                     consumer versions must be > {} (use {} or higher)",
                    m.version,
                    m.description,
                    our_max,
                    our_max,
                    CONSUMER_VERSION_FLOOR
                );
            }
        }
    }

    // 3. Compose: MIGRATOR ∪ consumers, sorted by version. `Migrator`
    //    does not implement `Clone` in sqlx 0.8, but its four fields are
    //    `pub`, so we build a fresh one from the union.
    let mut all: Vec<Migration> = MIGRATOR.migrations.iter().cloned().collect();
    for consumer in consumers {
        all.extend(consumer.migrations.iter().cloned());
    }
    all.sort_by_key(|m| m.version);

    let composed = Migrator {
        migrations: Cow::Owned(all),
        ignore_missing: true,
        // sqlx defaults: `locking = true` serialises concurrent
        // migrators; `no_tx = false` gives each migration its own
        // transaction (PostgreSQL DDL is transactional).
        locking: true,
        no_tx: false,
    };

    composed.run(pool).await?;
    Ok(())
}

/// Runs one or more `sqlx::Migrator` sets against `pool` in order,
/// **without** composing with [`MIGRATOR`].
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
/// **Superseded by [`migrate_composed`] for the "rust-saas + my own
/// tables" case.** `migrate_composed` runs the union of versions in one
/// shot, so it does not hit `VersionMissing`; `migrate_with` remains for
/// per-crate sets that do not need `rust-saas`'s schema at all.
///
/// Each per-crate `Migrator` uses its own version namespace
/// (`000_…`, `001_…`) to avoid colliding with the workspace set
/// (`YYYYMMDD…`) — but, again, mixing them on one DB with [`migrate`] is
/// not supported.
#[deprecated(
    note = "use `migrate_composed` for the `rust-saas + consumer migrations` case; \
            `migrate_with` remains only for per-crate sets that need no rust-saas schema"
)]
pub async fn migrate_with(
    pool: &PgPool,
    migrators: &[&Migrator],
) -> anyhow::Result<()> {
    for m in migrators {
        m.run(pool).await?;
    }
    Ok(())
}

