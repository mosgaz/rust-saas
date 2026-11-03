-- Deliberately less than rust-saas's max version.
-- `migrate_composed` must reject this before running any SQL (a lower
-- version would sort before rust-saas and might reference missing
-- tables).
create table early_marker (id int);
