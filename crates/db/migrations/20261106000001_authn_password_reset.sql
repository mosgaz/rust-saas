-- Password reset + password-change timestamp (owner: `authn`; see handoff
-- §18 / saas-14 §27, Stage 3d).
--
-- `users.password_changed_at` is the source of truth for "when was the
-- password last set". It is `NOT NULL` and defaults to `now()` for new rows;
-- for existing rows it is backfilled from `created_at` (see the multi-step
-- `ADD NULL` → `UPDATE` → `SET NOT NULL` → `SET DEFAULT` below). Stage 3d
-- uses it only as bookkeeping; Stage 4 will compare it against JWT `iat` to
-- invalidate access tokens issued before a password change.
--
-- `password_reset_tokens` holds short-lived one-shot tokens used by
-- `authn::{request_password_reset, reset_password}`:
--
--   - `token_hash` = SHA-256(raw_token) in hex; the raw token is returned
--     to the caller once (`Authn::request_password_reset`) and is never
--     persisted.
--   - Single-active invariant: at most one row per user with
--     `used_at IS NULL` (partial unique index). `request_password_reset`
--     deletes any existing unused row before inserting; the index is a
--     belt-and-suspenders DB-level guarantee.
--   - TTL: 1 hour (`PASSWORD_RESET_TTL_HOURS`), enforced in
--     `reset_password` via `expires_at >= now()`.
--   - One-shot: `reset_password` marks the row used and additionally
--     expires **all** outstanding reset tokens for the same user, so a
--     second link from an earlier request cannot be replayed against the
--     freshly rotated password. Unlike `verify_email`, this method is not
--     idempotent — a replay of the same raw token returns
--     `AuthnError::TokenInvalid`.
--
-- `password_reset_tokens` is owned by `authn` (§5 p.3 single writer); no
-- other crate reads or writes it. No backfill is needed for this table: it
-- is empty on introduction.

-- 1. `users.password_changed_at` — multi-step so the `NOT NULL` constraint
--    can be added safely to a table with existing rows.
alter table users
add column password_changed_at timestamptz null;

update users
set password_changed_at = created_at
where password_changed_at is null;

alter table users
alter column password_changed_at set not null;

alter table users
alter column password_changed_at set default now();

-- 2. `password_reset_tokens` (owner: `authn`).
create table password_reset_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    token_hash text not null unique,
    expires_at timestamptz not null,
    used_at timestamptz null,
    created_at timestamptz not null default now()
);

-- Single-active invariant: at most one unused reset token per user.
create unique index password_reset_tokens_one_active_idx
on password_reset_tokens (user_id)
where used_at is null;

-- Lookup for `request_password_reset` (delete-unused step) and for
-- auditing.
create index password_reset_tokens_user_idx on password_reset_tokens (user_id);