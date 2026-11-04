-- Audit log (owner: `audit-pg`; ADR-0004, Stage 3e).
--
-- Single table for audit events, written synchronously by `PgAuditLogger`
-- **after** the business transaction commits, in its own transaction
-- (ADR-0004 §2.4). Audit is not part of the caller's transaction; there is
-- no cross-table tx between `saas`/`access`/`authn` and `audit_log`
-- (ADR-0003 A-lite is unchanged).
--
-- Invariants (§2.3):
--   - `id` and `occurred_at` are DB-generated (`gen_random_uuid()`,
--     `now()`); the `audit::AuditEvent` DTO does not carry them.
--   - `actor_id` is `NULL` for anonymous / system events. `ON DELETE SET
--     NULL` so deleting a user does not break the FK and does not delete
--     the audit row.
--   - `actor_email` is denormalized: after `users` row deletion, `actor_id`
--     becomes `NULL` but the email remains, so the audit row can still
--     answer "who did it?".
--   - `event_type` is free-form `text` (not an enum): new events are
--     constants in `audit::events`, no migration needed (§3.8).
--   - `target_type` + `target_id` are nullable (`user.login_*` has no
--     target). `target_type` is `'tenant' | 'workspace' | 'user' | 'role' |
--     'invitation'`.
--   - `metadata` is free-form `jsonb` with default `{}`; per-event shape is
--     documented in Appendix B, not enforced by the schema.
--
-- What is **not** in the schema (Stage 4+):
--   - `ip_address`, `user_agent` — the library does not know HTTP;
--     consumer `AuditLogger` implementations can store them in `metadata`
--     without a migration (§2.6).
--   - immutability enforcement (`REVOKE UPDATE, DELETE`) — deployment
--     responsibility.
--   - retention / partitioning (`pg_partman`) — Stage 4 (§2.3).
--
-- Indexes cover the four query shapes from the ADR §2.3:
--   - chronological scan (`occurred_at desc`);
--   - "what did this actor do?" (`actor_id, occurred_at desc`);
--   - "who triggered this event?" (`event_type, occurred_at desc`);
--   - "history of this target" (`target_type, target_id, occurred_at desc`).

create table audit_log (
    id uuid primary key default gen_random_uuid(),
    occurred_at timestamptz not null default now(),
    actor_id uuid null references users(id) on delete set null,
    actor_email text null,
    event_type text not null,
    target_type text null,
    target_id uuid null,
    metadata jsonb not null default '{}'::jsonb
);

create index audit_log_occurred_idx
on audit_log (occurred_at desc);

create index audit_log_actor_idx
on audit_log (actor_id, occurred_at desc);

create index audit_log_event_idx
on audit_log (event_type, occurred_at desc);

create index audit_log_target_idx
on audit_log (target_type, target_id, occurred_at desc);