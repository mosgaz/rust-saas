-- Refresh tokens (owner: `authn`, Stage 2b; see handoff §8 and Appendix B §2.4).
--
-- Opaque refresh tokens: the raw token is returned to the caller once
-- (`issue_refresh_token`) and is never persisted; `refresh_tokens.token_hash`
-- stores SHA-256(raw_token) in hex. The unique constraint on `token_hash`
-- also serves as the lookup index on rotation.
--
-- Rotation with `family_id`: when a refresh token is used, the old row is
-- marked with `used_at` and a new row is inserted in the same `family_id`.
-- Presenting an already-used token revokes the whole family
-- (`revoked_at = now()` for all rows with that `family_id`); see handoff §22.6.
--
-- `expires_at` bounds the refresh lifetime; `revoked_at` marks explicit
-- revocation (logout, compromise, reuse detection).

create table refresh_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    token_hash text not null unique,
    family_id uuid not null,
    expires_at timestamptz not null,
    used_at timestamptz null,
    revoked_at timestamptz null,
    created_at timestamptz not null default now()
);

-- Mass-revoke by family on rotation reuse and logout.
create index refresh_tokens_family_idx on refresh_tokens (family_id);