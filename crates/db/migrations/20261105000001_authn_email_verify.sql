-- Email verification + refresh revocation reasons (owner: `authn`; see
-- handoff §18 / saas-11 §27, Stage 3b).
--
-- `users.email_verified_at` is the source of truth: NULL = unverified,
-- NOT NULL = verified at that timestamp. `domain::AuthUser.email_verified`
-- is a **derived** boolean (`email_verified_at IS NOT NULL`), computed in
-- every SELECT by `identity`; the column itself is a timestamp, not a bool.
--
-- `email_verifications` holds short-lived one-shot tokens used by
-- `authn::{create_email_verification, verify_email}`:
--
--   - `token_hash` = SHA-256(raw_token) in hex; the raw token is returned
--     to the caller once (`AuthUser, raw_token`) and is never persisted.
--   - Single-active invariant: at most one row per user with `used_at IS
--     NULL` (partial unique index). `create_email_verification` deletes any
--     existing unused row before inserting; the index is a belt-and-
--     suspenders DB-level guarantee.
--   - TTL: 24h (`EMAIL_VERIFICATION_TTL_HOURS`), enforced in
--     `verify_email` via `expires_at >= now()`.
--   - `verify_email` is idempotent: it marks the row used and writes
--     `users.email_verified_at = COALESCE(existing, now())` — an already-
--     verified user keeps their original timestamp.
--
-- `refresh_tokens.revoked_reason` records **why** a family was revoked.
-- The column is `text` (not an enum) so new reasons can be added without a
-- migration; `authn::RevokeReason` in Rust holds the constants
-- (`"logout"`, `"reuse_detected"`, `"password_reset"`). `password_reset`
-- is reserved for Stage 3d and is not written by any code path in Stage 3b.

alter table users
add column email_verified_at timestamptz null;

create table email_verifications (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    token_hash text not null unique,
    expires_at timestamptz not null,
    used_at timestamptz null,
    created_at timestamptz not null default now()
);

-- Single-active invariant: at most one unused verification token per user.
create unique index email_verifications_one_active_idx
on email_verifications (user_id)
where used_at is null;

-- Lookup for `create_email_verification` (delete-unused step) and for
-- auditing.
create index email_verifications_user_idx on email_verifications (user_id);

alter table refresh_tokens
add column revoked_reason text null;