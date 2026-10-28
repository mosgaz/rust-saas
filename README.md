# Rust SAAS

**rust-saas** is a Rust library and reference application for building multi-tenant SaaS.

The library crates live in `crates/` (a Cargo workspace) and separate business logic, identity, authentication, and authorization from each other, so they can be reused in other applications through git dependencies. The `examples/saas-leptos` directory contains a reference consumer that combines them with an isomorphic Leptos frontend and an Axum-based backend.

## Features

- Multi-tenant architecture with tenants and workspaces
- Identity-first user model
- Email and password authentication
- Argon2 password hashing
- **JWT access tokens (short-lived) and opaque refresh tokens (rotation with family revocation)**
- **Auto-refresh middleware (transparent token rotation)**
- **Server-side logout (revokes refresh token family)**
- **Domain-ownership RBAC (ADR-0001): roles are data, owner of a domain has all permissions**
- **Tenant and workspace member management (list, assign/remove role, permission-gated UI)**
- **UI gating by effective permissions (`my_permissions`, batched per domain)**
- Platform, tenant, and workspace authorization domains
- Invitations (reusable links and addressed) with `token_hash` (SHA-256), `expires_at`, `max_uses`, `revoked_at`
- Document pages (view and create inside workspaces)
- Tenant, workspace, and document navigation (`/tenants`, `/workspaces`, `/workspaces/:id/documents/:id`)
- Leptos server-side rendering and client hydration
- Server functions for frontend-to-backend communication
- PostgreSQL migrations with SQLx
- Reproducible local development with Docker Compose
- Database seed command for bootstrap data
- Tailwind CSS v4 styling

## Architecture

The repository is split into two layers:

```text
crates/                  (library — the Cargo workspace)
├── domain/             Shared DTOs (Tenant, Workspace, Document, AuthUser, Invitation, Member),
│                       InvitationTarget, domain helpers, PLATFORM_DOMAIN
├── authz/              AuthorizationEngine trait (can/require/grant_role/revoke_role) + AuthzError
├── authz-casbin/       CasbinAuthz: canonical trait implementation
├── access/             Sole owner of `permissions`, `roles`, `role_permissions`:
│                       Role, Permission, RoleKey, AccessState, AccessError, role CRUD,
│                       create_owner_role, list_permissions, get_permissions_for_role
├── identity/           Sole owner of `users`: AuthUser, UserRecord, validation, CRUD
├── authn/              Argon2, JWT access tokens, opaque refresh tokens, rotation
├── saas/               Business logic: platform, tenant, workspace, invitation, member,
│                       access (wrappers, incl. my_permissions)
├── db/                 PostgreSQL connection and migrations
└── seed/               Bootstrap data and demo accounts

examples/                (reference consumers — outside the workspace)
└── saas-leptos/        Leptos SSR + Axum + #[server] + middleware + cookies
```

`examples/*` is listed in `workspace.exclude`; each example has its own `Cargo.toml` and `Cargo.lock`, and depends on the library crates via path dependencies pointing at `../../crates/*`.

The application separates five concerns:

| Concern | Responsibility | Crate |
|---|---|---|
| Identity | Who you are as an entity (`users` table, `AuthUser`) | `identity` |
| Authentication | How you proved you are who you are (Argon2, JWT, refresh tokens) | `authn` |
| Authorization | What you are allowed to do (`AuthorizationEngine`) | `authz` / `authz-casbin` |
| Roles & permissions | Who has which rights (`roles`, `permissions`, `role_permissions`) | `access` |
| Data isolation | Which rows you can see (SQL filters by tenant/workspace) | `saas` |

`Casbin does not replace SQL isolation. JWT does not replace Casbin. UI does not replace backend authorization. Roles are data, not code.`

### Crate dependency graph

```text
saas-leptos  -> domain, authz, authz-casbin, access, identity, authn, saas, db   (example)
seed         -> authz, authz-casbin, access, authn, identity, db, domain, saas
saas         -> authz (trait), access, identity, domain, sqlx, sha2
access       -> authz (trait), domain, sqlx, uuid, serde, thiserror
authn        -> identity, domain, sqlx, argon2, jsonwebtoken, sha2
identity     -> domain, sqlx
authz-casbin -> authz (trait), casbin, sqlx, sqlx-adapter
authz        -> uuid, thiserror, async-trait
db           -> sqlx, anyhow
domain       -> serde, uuid, chrono; sqlx (optional, ssr only)
```

Forbidden edges:

- `saas` does not depend on Leptos, Axum, `casbin::Enforcer`, JWT, or Argon2. `sha2` is used only for `invitation::hash_token`.
- `access` does not depend on business tables (`tenants`, `workspaces`, `documents`, `invitations`, `*_members`), HTTP, UI, JWT, or Argon2.
- `authn` does not depend on `authz`. `sha2` is used only for `refresh_tokens.token_hash`.
- `identity` does not depend on `authn` or `authz`.
- `authz` does not depend on Casbin, SQL, HTTP, Leptos, or JWT. It does not know about specific roles.
- `authz-casbin` does not depend on business tables (`users`, `tenants`, `invitations`, `refresh_tokens`, `roles`, `permissions`).
- The example (`examples/saas-leptos`) does not call `casbin_rule` directly and does not call `authz.require` — only `saas::*`, `saas::access::*`, `saas::member::*`, and `authn::*`.
- Library crates do not depend on `examples/*`.

### Multi-tenancy model

```text
platform
└── tenant
    ├── workspace
    └── workspace
```

- A **tenant** represents a customer organization.
- A **workspace** represents a working area inside a tenant, such as a team, department, or project.
- A **user** is a global identity and can participate in multiple tenants or workspaces.
- A **workspace** contains business resources such as documents.
- An **invitation** targets exactly one tenant or one workspace (`CHECK ((tenant_id IS NULL) <> (workspace_id IS NULL))`).

### Authorization domains

Casbin policies are scoped by domain:

| Domain | Purpose |
|---|---|
| `platform` | Platform-level administration |
| `tenant:{tenant_id}` | Tenant-level operations |
| `workspace:{workspace_id}` | Workspace-level operations |

### Domain-ownership RBAC (ADR-0001)

- A **role** is a named set of permissions in a **domain** (not in a tenant).
- A **permission** is a `(resource, action)` pair from the `permissions` reference table.
- The **owner** role in a domain has **all permissions** from the reference table, is `protected=true` and `immutable=true`. It is created by `access::create_owner_role(domain)` (idempotent) from `saas::platform::provision_tenant` and `saas::tenant::create_workspace`, and via the bootstrap SQL migration for the `platform` domain.
- The owner of a domain creates custom roles and assigns them to users of that domain (`saas::access::create_role` / `saas::access::assign_role`).
- Users can hold **multiple roles** in the same domain. `tenant_members` and `workspace_members` use `PRIMARY KEY (scope_id, user_id, role)`.

Example permissions and demo roles:

| Role | Domain | Permissions |
|---|---|---|
| `owner` | `platform` | all from `permissions` (bootstrap) |
| `owner` | `tenant:{id}` | all from `permissions` |
| `owner` | `workspace:{id}` | all from `permissions` |
| `editor` | `workspace:{id}` | `documents:read/write` (demo, created by seed) |
| `viewer` | `workspace:{id}` | `documents:read` (demo, created by seed) |

## Technology stack

| Layer | Technology |
|---|---|
| Language | Rust |
| UI | Leptos (in the reference example) |
| Backend | Axum (in the reference example) |
| Database | PostgreSQL 16 |
| Database access | SQLx |
| Authorization | Casbin (via `authz-casbin`) |
| Authentication | Argon2, JSON Web Tokens (access), opaque tokens (refresh) |
| Invitation tokens | SHA-256 (`sha2`) over a random raw token; raw token not persisted |
| Refresh tokens | SHA-256 (`sha2`) over a random raw token; raw token not persisted |
| Styling | Tailwind CSS v4 |
| Local infrastructure | Docker Compose (v1) |
| Logging | `tracing` + `tracing-subscriber` (`RUST_LOG` env-filter) |
| Testing | `cargo test`; `#[sqlx::test]` for per-test isolated databases |

## Getting started

### Prerequisites

- Rust
- `wasm32-unknown-unknown` target
- `cargo-leptos`
- Docker and Docker Compose (v1)

Install the WebAssembly target and Leptos CLI:

```bash
rustup target add wasm32-unknown-unknown
cargo install --locked cargo-leptos
```

### Start PostgreSQL

Run from the repository root:

```bash
docker-compose up -d
docker-compose ps   # STATUS = Up (healthy)
```

### Configure environment

Copy the example environment file at the repository root:

```bash
cp .env.example .env
```

## Generating `JWT_SECRET`

For local development:

```bash
openssl rand -base64 48
```

Or on Windows PowerShell:

```powershell
[Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))
```

Put the result into `.env`:

```env
JWT_SECRET=your-generated-random-secret
```

Keep `.env.example` on the placeholder (`replace-with-a-long-random-secret`); do not commit real secrets.

Then adjust the values if needed:

```env
# Read by the application, the seed binary, and `cargo test` (`#[sqlx::test]`)
DATABASE_URL=postgres://postgres:postgres@localhost:5430/rust_saas
JWT_SECRET=replace-with-a-long-random-secret
ACCESS_TOKEN_TTL_MINUTES=15
REFRESH_TOKEN_TTL_DAYS=30
BIND_ADDR=127.0.0.1:3395

# Read by docker-compose.yml (defaults are used if unset)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=rust_saas

# tracing-subscriber env-filter (e.g. info, debug)
RUST_LOG=info
```

Notes:

- `.env` lives in the **repository root** and is discovered by the seed binary, the example, and `#[sqlx::test]`.
- `.env` must be LF, not CRLF.
- Do not put `LEPTOS_*` variables into `.env`.
- `DATABASE_URL` is used in three places: by the running application, by `seed`, and by `cargo test`. The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege for `#[sqlx::test]`.

### Apply migrations and seed data

Run from the repository root:

```bash
cargo run -p seed
```

Demo users created by seed:

| Role | Email | Password |
|---|---|---|
| Platform owner | `platform-admin@example.test` | `PlatformAdmin123!` |
| Tenant owner | `owner@acme.test` | `Owner123!` |
| Workspace editor (role `editor`) | `editor@acme.test` | `Editor123!` |
| Workspace viewer (role `viewer`) | `viewer@acme.test` | `Viewer123!` |

The command applies database migrations (including `20261103000001_access_rbac_init.sql`, `20261103000002_saas_members_multi_role.sql`, and `20261104000001_access_members_list_permission.sql`) and creates initial platform, tenant, workspace, user, role, and authorization data. It is idempotent: re-running it re-hashes passwords and re-applies roles/policies without creating duplicate rows.

Seed flow (ADR-0001):

1. Grants `platform` `owner` role to the platform admin via `authz.grant_role` (permissions from `access::get_permissions_for_role`).
2. Provisions the tenant via `saas::platform::provision_tenant(..., &RoleKey::parse("owner")?)`.
3. Creates the workspace via `saas::tenant::create_workspace(..., &RoleKey::parse("owner")?)`.
4. Creates demo roles `editor`/`viewer` via `saas::access::create_role`, then assigns them via `saas::access::assign_role`.

**Existing database.** `members_multi_role.sql` changes the primary keys on `tenant_members` and `workspace_members`. If your DB has older rows, re-run seed after `docker-compose down -v` (recommended) or apply a manual data migration.

Seed prints `tenant id:` and `workspace id:`; use them in the UI as shown below.

### Run the reference application

The example is outside the workspace and has its own manifest, so it is run from its directory:

```bash
cd examples/saas-leptos
cargo leptos watch
```

Open:

```text
http://127.0.0.1:3395
```

The live-reload port is `3396` (`[package.metadata.leptos] reload-port` in `examples/saas-leptos/Cargo.toml`).

Then in the browser:

1. `/register` or `/login` with one of the demo accounts.
2. `/platform` — as platform owner, create a tenant (the creator becomes its `owner` via `provision_tenant`).
3. `/tenants` — list of tenants you're a member of; click **Open**.
4. `/tenants/<tenant_id>` — as tenant owner, create a workspace; the creator becomes its `owner`.
5. `/tenants/<tenant_id>/members` — as tenant owner, see members and assign or remove roles.
6. `/tenants/<tenant_id>/roles` — as tenant owner, list and create custom roles.
7. `/workspaces` — list of workspaces you're a member of.
8. `/workspaces/<workspace_id>` — as editor, create documents; click a document title to view it on its dedicated page.
9. `/workspaces/<workspace_id>/members` — as workspace owner, see members and assign or remove roles.
10. `/workspaces/<workspace_id>/roles` — as workspace owner, list and create custom roles.
11. `/tenants/<tenant_id>/invitations` — as tenant owner, create a tenant invitation (link, copied once); `/workspaces/<workspace_id>/invitations` — as workspace owner, create a workspace invitation.
12. Paste `/invitations/<64 hex>` into another browser/session (after logging in as someone else) — accept-flow writes `tenant_members` / `workspace_members` (multi-role PK) and grants the corresponding role via `authz.grant_role`.
13. **Wait 15+ minutes** — the auto-refresh middleware transparently rotates the refresh token; UI continues to work.

### Checking the build

From the repository root:

```bash
clear && cargo test && cargo check && cargo check -p seed && cargo check --manifest-path examples/saas-leptos/Cargo.toml --features ssr && cargo check --manifest-path examples/saas-leptos/Cargo.toml
```

### Running tests

From the repository root:

```bash
cargo test
```

67 tests, all green (23 unit + 13 `authn` integration + 20 `saas` integration + 6 `access` integration + 5 `authz-casbin` integration).

Unit tests live inline (`#[cfg(test)] mod tests`) in `crates/authn`, `crates/access`, and `crates/saas`. Integration tests live in `crates/*/tests/` and use `#[sqlx::test]`:

- Each test gets its own isolated database on the server pointed to by `DATABASE_URL`; `crates/db/migrations` are applied automatically; the database is dropped when the test finishes.
- No manual `createdb` is required.
- The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege.
- Tests can run in parallel; isolation is per-database.

`accept_invitation`, `*::list_memberships`, and `check_invitation` have no unit tests: they do not call `authz.require` and go straight to SQL, which a lazy `PgPool` cannot serve; they are covered by integration tests.

## Project layout

```text
.
├── Cargo.toml
├── docker-compose.yml
├── .env.example
├── crates/
│   ├── domain/
│   ├── authz/
│   ├── authz-casbin/
│   ├── access/
│   ├── identity/
│   ├── authn/
│   ├── saas/
│   ├── db/
│   │   └── migrations/
│   │       ├── 20261026000001_init.sql
│   │       ├── 20261101000001_saas_invitations.sql
│   │       ├── 20261102000001_authn_refresh_tokens.sql
│   │       ├── 20261103000001_access_rbac_init.sql
│   │       ├── 20261103000002_saas_members_multi_role.sql
│   │       └── 20261104000001_access_members_list_permission.sql
│   └── seed/
└── examples/
    └── saas-leptos/
```

### domain

Shared DTOs (`Tenant`, `Workspace`, `Document`, `AuthUser`, `Invitation`, `Member`), the `InvitationTarget` enum (`Tenant(Uuid) | Workspace(Uuid)`), and authorization domain helpers (`PLATFORM_DOMAIN`, `tenant_domain`, `workspace_domain`). No SQL queries, no logic — just types. `sqlx::FromRow` / `sqlx::Type` derives are gated behind the `ssr` feature.

### authz

The `AuthorizationEngine` trait — `can`, `require`, `grant_role`, `revoke_role` — and `AuthzError`. Trait-only: no Casbin, no SQL, no HTTP, no specific roles. `grant_role(user_id, domain, role_key, permissions)` writes one `g`-row (`user → role_key → domain`) and one `p`-row per `(resource, action)`. `revoke_role` removes the `g`-row (shared `p`-rows remain while the role exists).

### authz-casbin

`CasbinAuthz` — the canonical implementation of `AuthorizationEngine` on top of Casbin and `sqlx-adapter`. The `g`/`p` matcher and `grant_role`/`revoke_role` live here. Business code never talks to Casbin directly. Two constructors: `CasbinAuthz::new(&database_url)` (production, own pool) and `CasbinAuthz::from_pool(PgPool)` (consumers and tests, e.g. `#[sqlx::test]`). Does not know about `roles`/`permissions`/`users`/`tenants`; only `casbin_rule`.

### access

The sole owner of the `permissions`, `roles`, and `role_permissions` tables.

- DTOs: `Role`, `Permission` (`(resource, action)` + description), `RoleKey` (`[a-z0-9_]{1,64}`).
- `AccessState { pool, authz }`, `AccessError`.
- Services (all take `&AccessState`):
  - `create_role(actor, domain, key, name, description, permissions)` — requires `(roles, create)`.
  - `update_role(actor, role_id, name, description, permissions)` — requires `(roles, manage)`; rejects `protected`/`immutable`.
  - `delete_role(actor, role_id)` — requires `(roles, delete)`; rejects `protected`.
  - `list_roles(actor, domain)` — requires `(roles, list)`.
  - `get_role(domain, role_key)` — **no actor** (§5 p.5): helper.
  - `get_permissions_for_role(domain, role_key)` — **no actor**: helper for `saas::access::assign_role`.
  - `list_permissions()` — **no actor**: public reference.
  - `create_owner_role(domain)` — **no actor**: idempotent bootstrap; permissions = all from `permissions`.

Does not know about `tenants`, `workspaces`, `documents`, `invitations`, `*_members`, HTTP, UI, JWT, or Argon2.

### identity

The sole owner of the `users` table. Provides `AuthUser`, `UserRecord` (including `password_hash`, never leaves this crate's boundary), `validate_email`, `validate_password`, `find_by_id`, `find_by_email`, `create_user`, and idempotent `upsert_user`. Does **not** hash passwords (that is `authn`'s job) and does not know about JWT, cookies, or roles.

### authn

The authentication mechanism on top of `identity`. Provides `Authn::with_ttl`, `register`, `login`, `issue_access_token`, `issue_refresh_token`, `rotate_refresh_token`, `revoke_refresh_token`, `revoke_family`, `verify_token`, and `hash_password`. Uses Argon2, `jsonwebtoken`, and `sha2` for opaque refresh tokens. Does **not** know about HTTP, cookies, Leptos, or `AuthorizationEngine`.

### saas

Business logic, independent of UI framework. `SaasState { pool, authz, access }`, `SaasBuilder` (`with_authz`, `with_access`), `CoreError`, and services:

- `platform::create_tenant` — container only.
- `platform::provision_tenant(actor, name, owner, &owner_role_key)` — container + owner role creation (`access::create_owner_role`) + `grant_role` + `tenant_members` bookkeeping, in one transaction.
- `tenant::create_workspace(actor, tenant_id, name, owner, &owner_role_key)` — side effect preserved: the creator receives `owner_role_key` (usually `"owner"`).
- `tenant::list_memberships` / `workspace::list_memberships` — membership queries via `EXISTS` (multi-role).
- `workspace::create_document` / `list_documents` / `get_document`.
- `member::list(actor, MemberScope)`, `member::change_role`, `member::remove_role` — tenant/workspace member management (Stage 2c).
- `invitation::create_invitation` — validates `role` against `access::get_role(domain, &RoleKey)`.
- `invitation::accept_invitation` — by raw token; writes `*_members` (multi-role PK) and grants the role via `authz.grant_role`.
- `invitation::revoke_invitation` / `list_invitations`.
- `saas::access::{create_role, update_role, delete_role, list_roles, list_permissions, assign_role, revoke_role, my_permissions}` — wrappers over `access` + `authz` + `*_members`. `my_permissions` returns the actor's effective `(resource, action)` pairs in a domain (batched UX helper for the client; does not replace `authz.require`).

Every service calls `state.authz.require(...)` before touching the database, **except** the explicit exceptions in handoff §5 p.5:

- `invitation::accept_invitation` and `invitation::check_invitation` — authorized by the invitation token.
- `tenant::list_memberships` / `workspace::list_memberships` — membership queries.
- `access::get_permissions_for_role`, `access::create_owner_role`, `access::list_permissions`, `access::get_role` — helpers, called after `require` in a caller.
- `access::my_permissions` — read-only UX helper; any authenticated actor may discover their own effective permissions in a domain.

Does not know about Leptos, Axum, HTTP handlers, `casbin::Enforcer`, JWT, Argon2, or the `permissions`/`roles`/`role_permissions` tables (owned by `access`).

### db

PostgreSQL connection helper and migration runner. Migrations live in `crates/db/migrations/`:

- `20261026000001_init.sql` — `users`, `tenants`, `workspaces`, `tenant_members`, `workspace_members`, `documents`, `casbin_rule`.
- `20261101000001_saas_invitations.sql` — `invitations` (owner: `saas`).
- `20261102000001_authn_refresh_tokens.sql` — `refresh_tokens` (owner: `authn`).
- `20261103000001_access_rbac_init.sql` — `permissions`, `roles`, `role_permissions`; platform `owner` role with all permissions (owner: `access`).
- `20261103000002_saas_members_multi_role.sql` — `*_members` PK → `(scope_id, user_id, role)`.
- `20261104000001_access_members_list_permission.sql` — `(members, list)` reference row; top-up `roles.key='owner'` across all domains (owner: `access`).

Includes a `build.rs` with `cargo:rerun-if-changed=migrations` (and a `cargo:warning=` listing the migration set each time the build script runs).

### seed

Standalone binary for creating initial platform, tenant, workspace, user, role, and policy data. Bootstrap flow (ADR-0001):

1. Grants `platform` `owner` to the platform admin via `authz.grant_role` with permissions from `access::get_permissions_for_role`.
2. Provisions the tenant (`saas::platform::provision_tenant`) and workspace (`saas::tenant::create_workspace`) with `RoleKey::parse("owner")?`.
3. Creates demo roles `editor`/`viewer` via `saas::access::create_role` and assigns them via `saas::access::assign_role`.

Idempotent: re-runs re-hash passwords, skip existing tenant/workspace, and re-apply role assignments without duplicates.

### examples/saas-leptos

The reference consumer application: Leptos UI, Axum server, `#[server]` wrappers, and `AppState`. `#[server]` functions are thin: `extract::CurrentUser::from_request().await?.require()?` resolves the user (HTTP 401 when missing), then the call delegates to `saas::*`, `saas::access::*`, `saas::member::*`, or `authn::*`; errors go through `error::core_error_to_server_fn` / `error::authn_error_to_server_fn` / `error::access_error_to_server_fn`, which map to HTTP 400/401/403/409/500. `AppState` holds `authn`, `saas` (which contains `access`), and `leptos_options`. `src/extract.rs` holds `CurrentUser`; `src/error.rs` holds the error mapping; `src/middleware.rs` holds the auto-refresh middleware; `src/layout.rs` holds the global UI layout. `src/pages/{member,role}.rs` hold tenant/workspace member and role management. This crate is **not** part of the library workspace.

Routes:

| Route | Component | Purpose |
|---|---|---|
| `/` | `pages::home::HomePage` | landing page, links |
| `/login` | `pages::auth::LoginPage` | sign in |
| `/register` | `pages::auth::RegisterPage` | sign up |
| `/platform` | `pages::platform::PlatformPage` | create a tenant (as platform owner) |
| `/tenants` | `pages::tenant::TenantListPage` | list of my tenants |
| `/tenants/:tenant_id` | `pages::tenant::TenantPage` | single tenant (create workspace) |
| `/tenants/:tenant_id/invitations` | `pages::invitation::TenantInvitationListPage` | tenant invitations |
| `/tenants/:tenant_id/members` | `pages::member::TenantMemberListPage` | tenant members and role changes |
| `/tenants/:tenant_id/roles` | `pages::role::TenantRoleListPage` | tenant roles (list/create/delete) |
| `/workspaces` | `pages::workspace::WorkspaceListPage` | list of my workspaces |
| `/workspaces/:workspace_id` | `pages::workspace::WorkspacePage` | single workspace (documents) |
| `/workspaces/:workspace_id/documents/:document_id` | `pages::workspace::DocumentPage` | single document view |
| `/workspaces/:workspace_id/invitations` | `pages::invitation::WorkspaceInvitationListPage` | workspace invitations |
| `/workspaces/:workspace_id/members` | `pages::member::WorkspaceMemberListPage` | workspace members and role changes |
| `/workspaces/:workspace_id/roles` | `pages::role::WorkspaceRoleListPage` | workspace roles (list/create/delete) |
| `/invitations/:token` | `pages::invitation::InvitationAcceptPage` | accept-flow |

## Authorization model

A request is represented as:

```text
subject, domain, resource, action
```

Examples:

```text
user_id, platform, tenants, create
user_id, tenant:uuid, workspaces, create
user_id, tenant:uuid, invitations, create
user_id, tenant:uuid, members, list
user_id, tenant:uuid, members, manage
user_id, workspace:uuid, documents, write
user_id, workspace:uuid, roles, grant
```

Casbin model:

```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
```

Both `g` (user → role in domain) and `p` (role → resource, action in domain) are required; `grant_role` adds both.

Authorization is always checked on the server before business logic executes. Exceptions: `accept_invitation`/`check_invitation` (by token), `*::list_memberships` (membership queries), and `access` helpers (`get_role`, `get_permissions_for_role`, `list_permissions`, `create_owner_role`, `my_permissions`) — see handoff §5 p.5.

UI uses `saas::access::my_permissions` (batched per domain) to hide buttons and links; this is a UX convenience, not a security boundary — `authz.require` in `saas::*` remains authoritative.

## Development principles

- Keep authentication separate from authorization.
- Keep authorization separate from business logic.
- Never trust client-supplied tenant or workspace identifiers without server-side validation.
- Always scope database queries by tenant or workspace.
- Treat UI visibility as convenience, not as a security boundary.
- **Roles are data, not code.** No built-in role enums; `owner` is a row created by `access::create_owner_role`/the SQL migration; custom roles are created by the domain owner.
- `saas` and `authn` do not know about Leptos, Axum, or Casbin. `saas` does not know about `permissions`/`roles`/`role_permissions` — those belong to `access`.
- Library crates do not depend on `examples/*`; each example has its own `Cargo.toml` and `Cargo.lock`.
- Server functions resolve the actor through `extract::CurrentUser`; a missing actor is HTTP 401.
- Library errors (`CoreError`, `AuthnError`, `IdentityError`, `AccessError`) are mapped to HTTP status codes in the example (`src/error.rs`); keep new variants covered by that mapping.
- Invitation raw tokens are returned once from `saas::invitation::create_invitation` and are never persisted; only `invitations.token_hash` (SHA-256) is stored.
- Refresh raw tokens are returned once from `authn::issue_refresh_token` and are never persisted; only `refresh_tokens.token_hash` (SHA-256) is stored.
- `accept_invitation` does not compare `actor.email` to `invitation.email` until email verification (Stage 3).
- Auto-refresh middleware serializes refresh within a single HTTP request; parallel HTTP requests with the same refresh token are a known limitation (Stage 2d will add single-flight).
- `saas::member::change_role` is not atomic: it is `revoke_role` followed by `assign_role`. If `assign_role` fails after `revoke_role` commits, the user loses the old role. Stage 2d will unify the SQL connection (see handoff §16).

## Roadmap

- Stage 1 (done): typed error mapping to HTTP codes, `CurrentUser` extractor, mock `AuthorizationEngine` and `#[sqlx::test]` integration tests for `authn`, `saas`, and cross-tenant / cross-workspace access.
- Stage 1.5 (done): workspace `async-trait` dependency, cleanup, `.env.example` (EN), README `cargo test`.
- Stage 1.1 (done): `create_tenant` container only; `provision_tenant(actor, name, owner)` for explicit owner assignment; `create_workspace` side effect preserved.
- Stage 2a (done): invitations core.
- Stage 2b (done): refresh tokens with rotation + family revocation, auto-refresh middleware, logout with server-side invalidation, shorter access TTL, `access_token` + `refresh_token` cookies, global layout, document pages.
- Stage 2e (done): domain-ownership RBAC (ADR-0001), `access` crate, `grant_role`/`revoke_role`, `*_members` multi-role PK, `seed` bootstrap via `saas::*`.
- **Stage 2e.1 (done): cleanup — page naming convention (`EntityOperationPage`), EN comments, migration set sync, docs counters.**
- **Stage 2c (done): tenant and workspace member management, roles UI, UI gating via `saas::access::my_permissions`, Renew-demo removed.**
- Stage 2d (next): Casbin policy cleanup on delete, single Casbin/`saas` connection, single-flight refresh, atomic `change_role`.
- Stage 3: platform admin UI, tenant suspension, email verification, audit log, return-URL preservation for `/invitations/:token`.
- Stage 4: Dockerfile, CI (fmt/clippy/test/migration check), observability, backups, cookie `Secure`/`SameSite`, CSRF, rate limiting (incl. `/refresh`), optional RLS, E2E HTTP tests.

## License

See the `LICENSE` file in the root of the repository.
