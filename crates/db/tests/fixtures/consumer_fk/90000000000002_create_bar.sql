-- Consumer migration with a FK to a rust-saas table (`workspaces`).
-- `migrate_composed` must run the rust-saas set first (by version order)
-- so the FK target exists.
create table bar (
    id int primary key,
    workspace_id uuid not null references workspaces(id) on delete cascade
);
