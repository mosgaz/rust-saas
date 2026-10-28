-- Add `(members, list)` to the permission reference table and grant it to
-- every existing `owner` role across all domains (ADR-0001 §3.2).
--
-- `create_owner_role` copies the whole reference table at role-creation time,
-- so owner roles created after this migration receive the new permission
-- automatically. Owner roles that already existed before this migration
-- (`platform` owner from the bootstrap in `20261103000001_access_rbac_init.sql`,
-- and any tenant/workspace owner created by `seed` / `provision_tenant` /
-- `create_workspace`) need an explicit top-up — hence the second `insert`.
--
-- The top-up is targeted: only the new `(members, list)` pair is inserted for
-- `roles.key = 'owner'`. `on conflict do nothing` keeps it idempotent if the
-- migration ever runs against a partially-synced database.

insert into permissions (resource, action, description) values
    ('members', 'list', 'List members (tenant/workspace domain)');

insert into role_permissions (role_id, resource, action)
select r.id, 'members', 'list'
from roles r
where r.key = 'owner'
on conflict do nothing;