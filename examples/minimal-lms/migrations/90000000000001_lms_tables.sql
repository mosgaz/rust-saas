-- LMS business tables (minimal-lms consumer migration, A5).
-- FK targets: workspaces(id), tenants(id), courses(id) -- plural names, as in rust-saas.

create table courses (
    id uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references workspaces(id) on delete cascade,
    title text not null,
    status text not null default $$draft$$,
    created_at timestamptz not null default now()
);

create index courses_workspace_idx on courses (workspace_id);

create table assignments (
    id uuid primary key default gen_random_uuid(),
    course_id uuid not null references courses(id) on delete cascade,
    title text not null,
    due_at timestamptz null,
    created_at timestamptz not null default now()
);

create index assignments_course_idx on assignments (course_id);

create table batches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name text not null,
    starts_at timestamptz null,
    created_at timestamptz not null default now()
);

create index batches_tenant_idx on batches (tenant_id);

create table files (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name text not null,
    size_bytes bigint not null default 0,
    created_at timestamptz not null default now()
);

create index files_tenant_idx on files (tenant_id);
