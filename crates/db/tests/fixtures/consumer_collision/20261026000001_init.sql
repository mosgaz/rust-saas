-- Deliberately collides with rust-saas's `20261026000001_init`.
-- `migrate_composed` must reject this before running any SQL.
create table collision_marker (id int);
