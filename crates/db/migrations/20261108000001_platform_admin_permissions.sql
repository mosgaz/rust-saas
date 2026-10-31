-- Platform admin permissions (Stage 3f; ADR-0002 rev.2, handoff §7).
--
-- Adds three `(resource, action)` pairs to the global `permissions`
-- reference table and grants them to the existing `platform` owner role.
--
-- `permissions` has no domain column: the same `(resource, action)` may be
-- referenced by roles in any domain. `(tenants, list)` and `(tenants,
-- manage)` are checked against `PLATFORM_DOMAIN`; `(audit, read)` gates the
-- platform audit view (`/platform/audit`). All three are platform-scoped
-- in practice, but the reference table does not encode domain ownership.
--
-- Top-up targets only `roles.domain = 'platform' AND roles.key = 'owner'`.
-- Owner roles created after this migration receive the new pairs
-- automatically because `access::create_owner_role` copies the whole
-- reference table at creation time. `on conflict do nothing` keeps both
-- inserts idempotent.

insert into permissions (resource, action, description) values
    ('tenants', 'list',   'List tenants (platform domain)'),
    ('tenants', 'manage', 'Suspend or activate tenants (platform domain)'),
    ('audit',   'read',   'Read the platform audit log (platform domain)')
on conflict do nothing;

insert into role_permissions (role_id, resource, action)
select r.id, p.resource, p.action
from roles r
cross join (values
    ('tenants', 'list'),
    ('tenants', 'manage'),
    ('audit', 'read')
) as p(resource, action)
where r.domain = 'platform' and r.key = 'owner'
on conflict do nothing;