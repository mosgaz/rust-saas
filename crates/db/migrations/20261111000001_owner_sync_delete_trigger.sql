-- Stage 4.5c: owner-unsync trigger (AFTER DELETE).
--
-- Complements `20261110000002_owner_sync_trigger.sql` (AFTER INSERT). The
-- INSERT trigger keeps every `owner` role's `role_permissions` in sync with
-- the reference table by adding new `(resource, action)` pairs. It does not
-- handle deletion: removing a `(resource, action)` row from `permissions`
-- cascades into `role_permissions` (FK `on delete cascade`), but the
-- **effective grants** in `casbin_rule.p` — written by
-- `authz.grant_role` at role-assignment time — are not touched. The result
-- was orphaned `p`-rows for `owner` in every domain where the role had been
-- granted, i.e. `enforce` kept returning `allow` for a permission the
-- reference table no longer knew about (`saas-pluggability-04 §4.23`).
--
-- This migration closes the gap for **owner roles only**:
--
--   - Owner roles are special: by definition they hold every permission in
--     the reference table (`protected=true, immutable=true`,
--     `create_owner_role` copies the whole reference at creation time).
--     If a permission leaves the reference, owner must stop allowing it,
--     or the invariant "owner = all permissions" is silently violated.
--   - Custom roles are deliberately **not** unsynced here. Deleting a
--     permission from the reference table is a deployment-level destructive
--     operation; whether existing custom-role holders should lose the
--     effective grant automatically (surprising) or retain it until the
--     role is next updated (predictable) is a policy decision that belongs
--     to the consumer, not to this reference trigger. Consumers who want
--     "delete reference row ⇒ revoke everywhere" can extend this trigger
--     or call `authz.purge_role` + re-`grant_role` explicitly.
--   - This is the mirror of the INSERT trigger's scope (which also only
--     touches `owner` roles). Symmetric and documented.
--
-- Why not `ON CONFLICT DO NOTHING` / `IF EXISTS`: the `DELETE` is already
-- idempotent — deleting zero rows is a no-op. `ON CONFLICT` applies to
-- INSERT, not DELETE. `IF EXISTS` is for DROP.
--
-- Why `RETURN OLD` (not `RETURN NEW`): symmetric to the INSERT trigger's
-- `RETURN NEW`. For `AFTER` row triggers the return value is ignored, but
-- the convention keeps the two functions readable side-by-side. `OLD` is
-- the deleted row, which is what the DELETE predicate reads.
--
-- `casbin_rule` is not owned by `access` — it is the `authz-casbin`
-- backend. But triggers are SQL-level, and this migration lives in
-- `crates/db/migrations/` like every other schema change. The forbidden
-- edge from ADR-0001 §4 ("`access` does not know about `casbin_rule`") is
-- an application-crate boundary, not a database one: no Rust crate reads
-- this function; it lives only in the schema.
--
-- Not a cross-table transaction: the trigger runs in the same transaction
-- as the DELETE from `permissions`. If the DELETE rolls back, the
-- `casbin_rule` deletes roll back too. Standard PostgreSQL trigger
-- behaviour; does not touch ADR-0003 A-lite (which concerns
-- `saas` + `access` + `authz-casbin` application-level writes, not
-- intra-database triggers).

-- 1. Trigger function.
CREATE OR REPLACE FUNCTION owner_unsync_permission()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM casbin_rule
    WHERE ptype = 'p'
      AND v0 = 'owner'
      AND v2 = OLD.resource
      AND v3 = OLD.action;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- 2. Trigger binding.
DROP TRIGGER IF EXISTS owner_unsync_permission_after_delete ON permissions;
CREATE TRIGGER owner_unsync_permission_after_delete
AFTER DELETE ON permissions
FOR EACH ROW
EXECUTE FUNCTION owner_unsync_permission();
