-- Stage 5.0-A1.3 (Resource Registry; ADR-0009).
--
-- Order matters. Four steps:
--
--   1. Legacy import. Consumer databases created before Stage 5 may
--      contain `permissions.resource` values (`course`, `deal`, `invoice`)
--      that are not declared in `resource_types` (A1.1). Insert them as
--      `custom:legacy`, preserving observed actions in `default_actions`.
--      `on conflict (name) do nothing` — if a consumer already declared
--      the resource via `with_resource_types`, keep their scope/metadata.
--
--   2. `resource:manage` — the permission that gates the registry itself
--      (`saas::access::registry::{register_resource_type, add_action}`,
--      A1.5). `resource` is already a core type (A1.1); only the
--      `(resource, manage)` permission pair is missing.
--
--   3. Defensive top-up for `platform` owner. The A1.2 trigger already
--      writes `role_permissions` + `casbin_rule.p` for `owner` on
--      `INSERT INTO permissions`, so this is a no-op on a fresh DB and
--      idempotent on an existing one. Kept explicit for readers who scan
--      migrations for "who gets the new permission?".
--
--   4. FK `permissions.resource → resource_types.name`. Fires AFTER the
--      import, so every existing `permissions.resource` is now declared.
--      `on delete restrict` — a resource type that still has permissions
--      cannot be deleted. `on update restrict` — `resource_types.name`
--      is a PK that never changes (no rename API in A1.5).
--
-- Legacy rows land in `custom:legacy`, which Phase B (ABAC) treats as
-- "no structured scope" — a consumer that wants per-instance ABAC must
-- re-register under `custom:<name>` explicitly. Documented in
-- `saas-external-02.md` §5.7(f) once written.

-- 1. Legacy import: permissions whose resource is not yet declared.
INSERT INTO resource_types (name, scope, default_actions, description, metadata)
SELECT
    p.resource,
    'custom:legacy',
    array_agg(DISTINCT p.action ORDER BY p.action),
    'Imported from permissions before Stage 5',
    '{"source": "legacy_import"}'::jsonb
FROM permissions p
WHERE p.resource NOT IN (SELECT name FROM resource_types)
GROUP BY p.resource
ON CONFLICT (name) DO NOTHING;

-- 2. New permission for managing the registry.
INSERT INTO permissions (resource, action, description)
VALUES ('resource', 'manage', 'Register resource types and actions')
ON CONFLICT (resource, action) DO NOTHING;

-- 3. Defensive top-up for platform owner (A1.2 trigger does this too).
INSERT INTO role_permissions (role_id, resource, action)
SELECT r.id, 'resource', 'manage'
FROM roles r
WHERE r.domain = 'platform' AND r.key = 'owner'
ON CONFLICT DO NOTHING;

-- 4. FK. Every `permissions.resource` is now declared in `resource_types`.
ALTER TABLE permissions
    ADD CONSTRAINT fk_permissions_resource_type
    FOREIGN KEY (resource) REFERENCES resource_types(name)
    ON UPDATE RESTRICT ON DELETE RESTRICT;