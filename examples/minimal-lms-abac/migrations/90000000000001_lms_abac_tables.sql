-- Phase B' B3': LMS tables for minimal-lms-abac example.
--
-- Version 90000000000001 > db::CONSUMER_VERSION_FLOOR (90_000_000_000_000)
-- so it composes cleanly with the workspace migration set via
-- db::migrate_composed.
--
-- Schema mirrors minimal-lms (A5), but `courses.status` is the ABAC hook:
-- the "status-gated write" scenario reads it as `resource.attrs.status`.

create table courses (
    id           uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references workspaces(id) on delete cascade,
    title        text not null,
    status       text not null default 'draft'
                 check (status in ('draft', 'published', 'archived')),
    owner_id     uuid not null,
    created_at   timestamptz not null default now()
);

create index courses_workspace_idx on courses (workspace_id);
create index courses_owner_idx on courses (owner_id);

create table assignments (
    id         uuid primary key default gen_random_uuid(),
    course_id  uuid not null references courses(id) on delete cascade,
    title      text not null,
    due_at     timestamptz,
    created_at timestamptz not null default now()
);

create index assignments_course_idx on assignments (course_id);
