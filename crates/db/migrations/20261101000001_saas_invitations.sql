-- Invitations (owner: `saas`; see handoff §8 and Appendix B §2.2).
--
-- Exactly one of `tenant_id` / `workspace_id` is set: an invitation targets
-- either a tenant (for a tenant_owner) or a workspace (for a workspace role).
-- `email IS NULL` -> reusable link; `email IS NOT NULL` -> addressed (until
-- email verification, Stage 3, addressed invitations are effectively links;
-- see handoff §16).
--
-- `token_hash` stores SHA-256(raw_token); the raw token is returned to the
-- caller once (`InvitationCreated.token`) and is never persisted. The unique
-- constraint on `token_hash` also serves as the lookup index for `accept`.

create table invitations (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid null references tenants(id) on delete cascade,
    workspace_id uuid null references workspaces(id) on delete cascade,
    email text null,
    role text not null,
    token_hash text not null unique,
    created_by uuid not null references users(id) on delete cascade,
    expires_at timestamptz not null,
    max_uses int null,
    used_count int not null default 0,
    revoked_at timestamptz null,
    created_at timestamptz not null default now(),
    check ((tenant_id is null) <> (workspace_id is null))
);

-- Listing invitations by scope, newest first.
create index invitations_tenant_created_idx on invitations (tenant_id, created_at desc);
create index invitations_workspace_created_idx on invitations (workspace_id, created_at desc);