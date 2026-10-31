-- Bootstrap for standalone `audit-pg` consumers (Stage 4.3c).
--
-- `audit_log.actor_id` has a foreign key to `users(id)`. A consumer that
-- depends only on `audit-pg` (without the full `rust-saas` workspace
-- migrations) still needs that table to exist. This bootstrap creates a
-- minimal `users` shape: `id` (the FK target) plus the columns every
-- real identity implementation has. A consumer that also uses
-- `identity`/`authn` will apply its own richer `users` migration first;
-- `IF NOT EXISTS` makes this a no-op in that case.
--
-- Version namespace `000_…` — same reasoning as `001_audit_log.sql`.
CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
