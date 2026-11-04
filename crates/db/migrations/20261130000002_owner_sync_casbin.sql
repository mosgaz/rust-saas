-- Stage 5.0-A1.2 (Resource Registry; ADR-0009).
--
-- Problem (blocker B3, `saas-pluggability-04` §4.23):
--   `owner_sync_permission_after_insert` (from migration
--   `20261110000002_owner_sync_trigger.sql`) writes a new
--   `(resource, action)` to `role_permissions` only. It does NOT write to
--   `casbin_rule.p` — the source of truth for `authz.can` /
--   `authz.require`. Consequence: a new permission is invisible to owner
--   roles in a running replica until the process restarts (or someone
--   calls `authz.reload_in_memory()`, Stage 5.0-A1.4).
--
--   The AFTER DELETE side was already fixed in Stage 4.5c
--   (`20261111000001_owner_sync_delete_trigger.sql`); this migration
--   closes the symmetric INSERT side.
--
-- This migration does two things:
--
--   1. `CREATE OR REPLACE FUNCTION owner_sync_permission()` — the body
--      additionally inserts the `p`-row into `casbin_rule`. The trigger
--      binding (`AFTER INSERT ON permissions FOR EACH ROW`) is unchanged;
--      `CREATE OR REPLACE` updates the body in place.
--
--   2. Backfill — for every existing `owner` role (across all domains),
--      insert `casbin_rule.p` for every existing `(resource, action)` in
--      `permissions`. This makes the DB consistent with what the fixed
--      trigger would have produced. A running replica still needs
--      `authz.reload_in_memory()` to see it; the standard dev/CI practice
--      is `migrate_composed` before process start (`saas-external-02.md`
--      §5.7(e) once written).
--
-- Idempotency:
--   `casbin_rule_unique_idx` (migration `20261110000001`) is a unique
--   index on `(ptype, v0, v1, v2, v3, v4, v5)`, which is exactly what
--   `ON CONFLICT DO NOTHING` (no target) needs. A trigger that fires on a
--   replayed migration, or a backfill on a database where owners already
--   have p-rows (e.g. from `authz.grant_role`), is a no-op.
--
-- Not a cross-table transaction: the trigger runs in the same transaction
-- as the `INSERT INTO permissions`, and the backfill runs in the
-- migration's own transaction. ADR-0003 A-lite concerns
-- `saas` + `access` + `authz-casbin` boundaries, not intra-database SQL —
-- unchanged.

-- 1. Trigger function (body extended; binding unchanged).
CREATE OR REPLACE FUNCTION owner_sync_permission()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO role_permissions (role_id, resource, action)
    SELECT r.id, NEW.resource, NEW.action
    FROM roles r
    WHERE r.key = 'owner'
    ON CONFLICT DO NOTHING;

    INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
    SELECT 'p', r.key, r.domain, NEW.resource, NEW.action, '', ''
    FROM roles r
    WHERE r.key = 'owner'
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 2. Backfill: existing owner roles get p-rows for all existing
--    permissions. See the header comment for idempotency.
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
SELECT 'p', r.key, r.domain, p.resource, p.action, '', ''
FROM roles r
CROSS JOIN permissions p
WHERE r.key = 'owner'
ON CONFLICT DO NOTHING;