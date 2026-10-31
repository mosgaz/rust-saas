-- Deduplicate `casbin_rule` and enforce uniqueness (Stage 3h; ADR-0003 §2.2).
--
-- `casbin-rs` 2.x `add_policy` does not guarantee deduplication of `p`-rows:
-- repeated `grant_role` calls for the same `(role, domain, resource, action)`
-- can insert duplicate rows. `g`-rows are normally deduplicated by
-- `add_grouping_policy`, but this migration checks both `ptype` values so the
-- unique index cannot fail on pre-existing duplicates of either kind.
--
-- Steps:
-- 1. Delete duplicate rows, keeping the oldest row per duplicate group
--    (`a.id > b.id` keeps the smallest `id`; `casbin_rule.id` is `serial`).
-- 2. Create a unique index covering all `casbin_rule` value columns.
--
-- `DELETE ... USING` is PostgreSQL self-join syntax and works on an existing
-- database with duplicates.

-- 1. Deduplicate existing rows (both `p` and `g`).
delete from casbin_rule a
using casbin_rule b
where a.id > b.id
  and a.ptype = b.ptype
  and a.v0 = b.v0
  and a.v1 = b.v1
  and a.v2 = b.v2
  and a.v3 = b.v3
  and a.v4 = b.v4
  and a.v5 = b.v5;

-- 2. Unique index for `ON CONFLICT` / adapter safety.
create unique index casbin_rule_unique_idx
on casbin_rule (ptype, v0, v1, v2, v3, v4, v5);