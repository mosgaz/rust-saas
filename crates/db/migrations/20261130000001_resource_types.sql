-- Resource types registry (Stage 5.0-A1.1; ADR-0009).
--
-- Reference table for resource kinds that can appear in `permissions.resource`.
-- Replaces the "insert into permissions" SQL-migration path with a runtime
-- Rust API (`saas::access::registry::bootstrap_resource_type`). See
-- `saas-external-02.md` §5.7(a) once written.
--
-- `scope` is DECLARED, not ENFORCED: `platform` / `tenant` / `workspace` /
-- `custom:*` describes the *usual* domain of the resource. Enforcement lives
-- in `casbin_rule.p.v1` (`platform` | `tenant:{uuid}` | `workspace:{uuid}`),
-- which is unchanged. `member`, `role`, and `invitation` legitimately appear
-- in both tenant- and workspace-domains; all three are declared `tenant`
-- (the "usual" case). Declared scope is a hint for consumer-side UI, not a
-- constraint on role definitions.
--
-- `custom:*` is reserved for Phase B (ABAC/ReBAC per-instance) and legacy
-- import (A1.3).
--
-- Table names stay plural (`tenants`, `workspaces`, `documents`); this table
-- names *resource kinds*, which are singular — matching the already-shipped
-- `permissions.resource` values (`document`, `member`, `role`, …).
--
-- 8 core types. Names match `permissions.resource` (already singular); A1.3
-- adds `resource:manage` for the registry itself and the FK
-- `permissions.resource → resource_types.name`.

create table resource_types (
    name text primary key,
    scope text not null check (
        scope in ('platform', 'tenant', 'workspace')
        or scope like 'custom:%'
    ),
    description text not null default '',
    default_actions text[] not null default '{}',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

-- `default_actions` is an advisory hint (useful for consumer-side UI):
-- "what actions does a resource of this kind typically support?". The
-- source of truth for whether a `(resource, action)` pair is *assignable*
-- to a role is `permissions` — `role_permissions` has a FK there. Adding an
-- action here without adding the corresponding `permissions` row is harmless
-- (no FK between the two tables); the reverse (adding an action to
-- `permissions` without declaring it here) is what A1.3's FK will forbid.
--
-- Arrays are sorted alphabetically to match what A1.5's upsert
-- (`array_agg(distinct x order by x)`) produces after any merge — keeps
-- idempotency tests deterministic.
--
-- `workspace:read` is aspirational: no code path currently checks it.
-- `resolve_active_tenant` uses `EXISTS tenant_members`, not
-- `authz.require(workspace, read)`. The slot is declared so a future
-- consumer can use it without re-touching `resource_types`.

insert into resource_types (name, scope, default_actions, description) values
    ('tenant',     'platform',  array['create','list','manage'],                  'Tenant containers'),
    ('workspace',  'tenant',    array['create','read'],                           'Workspaces inside a tenant'),
    ('document',   'workspace', array['read','write'],                            'Documents in a workspace'),
    ('member',     'tenant',    array['list','manage'],                           'Members (tenant/workspace domains)'),
    ('invitation', 'tenant',    array['create','list','revoke'],                  'Invitations (tenant/workspace domains)'),
    ('role',       'tenant',    array['create','delete','grant','list','manage'], 'Roles (tenant/workspace domains)'),
    ('audit',      'platform',  array['read'],                                    'Audit log'),
    ('resource',   'platform',  array['manage'],                                  'Resource registry itself');