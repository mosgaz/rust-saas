create extension if not exists "pgcrypto";

create table users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    password_hash text not null,
    created_at timestamptz not null default now()
);

create table tenants (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    status text not null default 'active',
    created_at timestamptz not null default now()
);

create table workspaces (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name text not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, name)
);

create table tenant_members (
    tenant_id uuid not null references tenants(id) on delete cascade,
    user_id uuid not null references users(id) on delete cascade,
    role text not null,
    primary key (tenant_id, user_id)
);

create table workspace_members (
    workspace_id uuid not null references workspaces(id) on delete cascade,
    user_id uuid not null references users(id) on delete cascade,
    role text not null,
    primary key (workspace_id, user_id)
);

create table documents (
    id uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references workspaces(id) on delete cascade,
    title text not null,
    body text not null default '',
    created_at timestamptz not null default now()
);

create table casbin_rule (
    id serial primary key,
    ptype varchar(100) not null,
    v0 varchar(100) not null default '',
    v1 varchar(100) not null default '',
    v2 varchar(100) not null default '',
    v3 varchar(100) not null default '',
    v4 varchar(100) not null default '',
    v5 varchar(100) not null default ''
);

create index casbin_rule_idx on casbin_rule (ptype, v0, v1);