-- RBAC initialization (owner: `access`; see ADR-0001, handoff §8 and Appendix B).
--
-- `permissions` is the reference table of `(resource, action)` pairs. It is
-- the natural key; FK from `role_permissions` enforces that no permission can
-- be assigned to a role unless it exists here.
--
-- `roles` are domain-scoped (`platform`, `tenant:{uuid}`, `workspace:{uuid}`).
-- `roles.key` is immutable: renaming requires delete + create, so that
-- `casbin_rule` g-rows `(user, role_key, domain)` remain valid forever.
--
-- `role_permissions` links roles to permissions with FK to both.
--
-- Bootstrap: the `platform` owner role is created here (protected, immutable)
-- and receives every permission from the reference table. Tenant and
-- workspace owner roles are created on the fly by `access::create_owner_role`
-- during provisioning (seed, provision_tenant, create_workspace).

create table permissions (
    resource text not null,
    action text not null,
    description text not null default '',
    primary key (resource, action)
);

create table roles (
    id uuid primary key default gen_random_uuid(),
    domain text not null,           -- 'platform' | 'tenant:{uuid}' | 'workspace:{uuid}'
    key text not null,
    name text not null,
    description text not null default '',
    protected boolean not null default false,
    immutable boolean not null default false,
    created_at timestamptz not null default now(),
    unique (domain, key)
);

create table role_permissions (
    role_id uuid not null references roles(id) on delete cascade,
    resource text not null,
    action text not null,
    primary key (role_id, resource, action),
    foreign key (resource, action) references permissions(resource, action) on delete cascade
);

-- Populate the reference table.
insert into permissions (resource, action, description) values
    ('tenants', 'create', 'Create tenants (platform domain)'),
    ('workspaces', 'create', 'Create workspaces (tenant domain)'),
    ('documents', 'read', 'Read documents (workspace domain)'),
    ('documents', 'write', 'Create or modify documents (workspace domain)'),
    ('members', 'manage', 'Manage members (workspace domain)'),
    ('invitations', 'create', 'Create invitations (tenant/workspace domain)'),
    ('invitations', 'revoke', 'Revoke invitations'),
    ('invitations', 'list', 'List invitations'),
    ('roles', 'create', 'Create roles in domain'),
    ('roles', 'manage', 'Modify roles'),
    ('roles', 'delete', 'Delete roles'),
    ('roles', 'list', 'List roles'),
    ('roles', 'grant', 'Assign or revoke roles');

-- Bootstrap the platform owner role.
insert into roles (domain, key, name, description, protected, immutable)
values ('platform', 'owner', 'Owner', 'Platform owner: all permissions', true, true);

-- Grant all permissions to the platform owner role.
insert into role_permissions (role_id, resource, action)
select r.id, p.resource, p.action
from roles r
cross join permissions p
where r.domain = 'platform' and r.key = 'owner';