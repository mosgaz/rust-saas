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
//!
//! Stage 3f adds [`AuditRow`] and [`PgAuditLogger::list`] for the
//! platform-admin audit view (`/platform/audit`). `list` is a read-only
//! helper — it does **not** participate in the write path and is not part
//! of the [`audit::AuditLogger`] trait (the trait is intentionally a
//! single-method write interface; reads are implementation-specific so
//! consumers can pick pagination/filtering for their own storage).

use audit::{AuditError, AuditEvent, AuditLogger};
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

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

    /// Lists the most recent audit rows, newest first.
    ///
    /// Read-only helper for the platform-admin audit view (Stage 3f); not
    /// part of the [`AuditLogger`] trait. `limit` is passed through to SQL
    /// as `LIMIT $1` — callers should clamp it to a sane upper bound (the
    /// example uses `LIMIT_MAX = 200`). Rows are ordered by
    /// `(occurred_at DESC, id DESC)` so that ties (same-microsecond rows,
    /// e.g. `change_role`'s three events) are stable across calls.
    pub async fn list(&self, limit: i64) -> Result<Vec<AuditRow>, AuditError> {
        sqlx::query_as::<_, AuditRow>(
            r#"
            select
                id,
                occurred_at,
                actor_id,
                actor_email,
                event_type,
                target_type,
                target_id,
                metadata
            from audit_log
            order by occurred_at desc, id desc
            limit $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuditError::Internal(e.to_string()))
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

/// A row from the `audit_log` table, as read by [`PgAuditLogger::list`].
///
/// Read-side mirror of [`audit::AuditEvent`]: it carries the DB-generated
/// `id` and `occurred_at` (the DTO does not) and its shape matches the
/// columns in `crates/db/migrations/20261107000001_audit_log.sql`.
/// `metadata` is a free-form `serde_json::Value` (JSONB). `actor_email`
/// may survive `users` row deletion — `actor_id` becomes `NULL` via
/// `ON DELETE SET NULL` (ADR-0004 §2.3).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditRow {
    pub id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub event_type: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub metadata: serde_json::Value,
}