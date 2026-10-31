-- Stage 3h (optional): owner-sync trigger.
--
-- Purpose: when a new permission is added to the `permissions` reference
-- table, automatically grant it to every `owner` role across all domains
-- (platform, tenant:{id}, workspace:{id}). This replaces the manual
-- top-up migrations from Stage 3b (`20261105000001_authn_email_verify.sql`)
-- and Stage 3f (`20261108000001_platform_admin_permissions.sql`).
--
-- Why `ON CONFLICT DO NOTHING`: `role_permissions` has a unique constraint
-- on `(role_id, resource, action)`. The trigger must be idempotent — if
-- a future migration inserts the same `(resource, action)` twice, or if
-- the trigger fires on a replayed migration, the duplicate must not fail.
--
-- Why `FOR EACH ROW`: each inserted permission must be propagated to all
-- owner roles. A statement-level trigger would need a self-join against
-- `permissions` and would not know which row was just inserted.
--
-- Why not `AFTER UPDATE`: `permissions.resource` and `permissions.action`
-- are immutable (no UPDATE path in `access::*`). If a rename is ever
-- needed, it is done via DELETE + INSERT (ADR-0001), so the INSERT
-- trigger fires and the new permission is granted to owners.
--
-- Why not `AFTER DELETE`: removing a permission from the reference table
-- does not automatically revoke it from existing owner roles — that is
-- a destructive operation and must be explicit. The trigger only handles
-- the additive case.
--
-- Not a cross-table transaction: the trigger runs in the same transaction
-- as the INSERT into `permissions`. If the INSERT is rolled back, the
-- `role_permissions` inserts are rolled back too. This is the standard
-- PostgreSQL trigger behaviour and does not violate ADR-0003 A-lite
-- (which concerns `saas` + `access` + `authz-casbin` boundaries, not
-- intra-database triggers).

-- 1. Trigger function.
CREATE OR REPLACE FUNCTION owner_sync_permission()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO role_permissions (role_id, resource, action)
    SELECT r.id, NEW.resource, NEW.action
    FROM roles r
    WHERE r.key = 'owner'
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 2. Trigger binding.
DROP TRIGGER IF EXISTS owner_sync_permission_after_insert ON permissions;
CREATE TRIGGER owner_sync_permission_after_insert
AFTER INSERT ON permissions
FOR EACH ROW
EXECUTE FUNCTION owner_sync_permission();