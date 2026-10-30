//! PostgreSQL implementation of the `audit::AuditLogger` trait (ADR-0004).
//!
//! Owns the `audit_log` table (sole writer). Symmetric to `authz-casbin`:
//! trait lives in `audit`, SQL implementation lives here.
//!
//! Invariants (ADR-0004 §2.3–§2.4):
//! - `audit_log` is written in its **own** transaction, after the business
//!   mutation commits. There is no attempt to make this transactional with
//!   the caller's mutation (that would extend ADR-0003's A-lite to audit).
//! - `occurred_at` and `id` are set by the database (`DEFAULT now()` /
//!   `DEFAULT gen_random_uuid()`), not by this crate; the DTO does not
//!   carry them.
//! - `actor_id` uses `ON DELETE SET NULL`; `actor_email` denormalized so
//!   the audit row survives `users` row deletion (§2.3).
//! - Failures are surfaced as [`audit::AuditError::Internal`]; the caller
//!   (`authn`/`access`/`saas`) logs them via `tracing::warn!` and does
//!   **not** fail the business operation.
//!
//! Indexes on `occurred_at`, `(actor_id, occurred_at)`, `(event_type,
//! occurred_at)`, and `(target_type, target_id, occurred_at)` live in
//! `crates/db/migrations/`.

use audit::{AuditError, AuditEvent, AuditLogger};
use sqlx::PgPool;

/// PostgreSQL-backed [`AuditLogger`].
///
/// Stores only a `PgPool` — the same pool that `saas`/`access`/`authn` use
/// (Stage 2d: one connection pool per process). No separate pool.
#[derive(Clone)]
pub struct PgAuditLogger {
    pool: PgPool,
}

impl PgAuditLogger {
    /// Builds a logger over an existing pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Borrowed view of the underlying pool (for tests / health checks).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait::async_trait]
impl AuditLogger for PgAuditLogger {
    async fn log(&self, event: &AuditEvent) -> Result<(), AuditError> {
        sqlx::query(
            r#"
            insert into audit_log
                (event_type, actor_id, actor_email, target_type, target_id, metadata)
            values ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&event.event_type)
        .bind(event.actor_id)
        .bind(event.actor_email.as_deref())
        .bind(event.target_type.as_deref())
        .bind(event.target_id)
        .bind(&event.metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| AuditError::Internal(e.to_string()))?;
        Ok(())
    }
}
