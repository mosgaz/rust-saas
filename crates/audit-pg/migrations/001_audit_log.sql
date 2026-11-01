-- Per-crate migration set for `audit-pg` (Stage 4.3c).
--
-- Idempotent: a consumer may run `db::migrate` (workspace-wide set, which
-- also creates `audit_log`) *and* `db::migrate_with(&[audit_pg::MIGRATOR])`
-- on the same database — `IF NOT EXISTS` makes the second pass a no-op.
--
-- Version namespace `001_…` is deliberately different from the workspace
-- set (`YYYYMMDD…`), so the two `Migrator`s never collide on
-- `_sqlx_migrations.version`.
--
-- See `crates/db/migrations/20261107000001_audit_log.sql` for the full
-- commentary (indexes, `ON DELETE SET NULL`, retention, immutability).

CREATE TABLE IF NOT EXISTS audit_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_email text NULL,
    event_type text NOT NULL,
    target_type text NULL,
    target_id uuid NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS audit_log_occurred_idx
    ON audit_log (occurred_at DESC);

CREATE INDEX IF NOT EXISTS audit_log_actor_idx
    ON audit_log (actor_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS audit_log_event_idx
    ON audit_log (event_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS audit_log_target_idx
    ON audit_log (target_type, target_id, occurred_at DESC);
