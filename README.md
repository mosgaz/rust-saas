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
- Domain-scoped RBAC authorization with Casbin, behind an `AuthorizationEngine` trait
- Platform, tenant, and workspace authorization domains
- Invitations (reusable links and addressed) with `token_hash` (SHA-256), `expires_at`, `max_uses`, `revoked_at`
- **Document pages (view and create inside workspaces)**
- Tenant, workspace, and document navigation (`/tenants`, `/workspaces`, `/documents`)
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
├── domain/             Shared DTOs (Tenant, Workspace, Document, AuthUser, Invitation),
│                       InvitationTarget, domain helpers, PLATFORM_DOMAIN
├── authz/              AuthorizationEngine trait + AuthzError + WorkspaceRole
├── authz-casbin/       CasbinAuthz: canonical trait implementation
├── identity/           Sole owner of `users`: AuthUser, UserRecord, validation, CRUD
├── authn/              Argon2, JWT access tokens, opaque refresh tokens, rotation
├── saas/               Business logic: platform, tenant, workspace, invitation
├── db/                 PostgreSQL connection and migrations
└── seed/               Bootstrap data and demo accounts

examples/                (reference consumers — outside the workspace)
└── saas-leptos/        Leptos SSR + Axum + #[server] + middleware + cookies
```

`examples/*` is listed in `workspace.exclude`; each example has its own `Cargo.toml` and `Cargo.lock`, and depends on the library crates via path dependencies pointing at `../../crates/*`.

The application separates four concerns:

| Concern | Responsibility | Crate |
|---|---|---|
| Identity | Who you are as an entity (`users` table, `AuthUser`) | `identity` |
| Authentication | How you proved you are who you are (Argon2, JWT, refresh tokens) | `authn` |
| Authorization | What you are allowed to do (`AuthorizationEngine`) | `authz` / `authz-casbin` |
| Data isolation | Which rows you can see (SQL filters by tenant/workspace) | `saas` |

`Casbin does not replace SQL isolation. JWT does not replace Casbin. UI does not replace backend authorization.`

### Crate dependency graph

```text
saas-leptos  -> domain, authz, authz-casbin, identity, authn, saas, db   (example)
seed         -> authz, authn, identity, authz-casbin, db, domain
saas         -> authz (trait), identity, domain, sqlx, sha2
authn        -> identity, domain, sqlx, argon2, jsonwebtoken, sha2
identity     -> domain, sqlx
authz-casbin -> authz (trait), domain, casbin, sqlx, sqlx-adapter
authz        -> (trait only)
db           -> sqlx
domain       -> serde, uuid, chrono; sqlx (optional, ssr only)
```

Forbidden edges:

- `saas` does not depend on Leptos, Axum, `casbin::Enforcer`, JWT, or Argon2. `sha2` is used only for `invitation::hash_token`, never for passwords (passwords are Argon2 in `authn`).
- `authn` does not depend on `authz`. `sha2` is used only for `refresh_tokens.token_hash`.
- `identity` does not depend on `authn` or `authz`.
- `authz` does not depend on Casbin, SQL, HTTP, Leptos, or JWT.
- `authz-casbin` does not depend on business tables (`users`, `tenants`, `invitations`, `refresh_tokens`).
- The example (`examples/saas-leptos`) does not call `casbin_rule` directly and does not call `authz.require` — only `saas::*` and `authn::*`.
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

Example roles and permissions:

| Role | Domain | Permissions |
|---|---|---|
| `platform_admin` | `platform` | `tenants:create` |
| `tenant_owner` | `tenant:{id}` | `workspaces:create`, `invitations:create/revoke/list` |
| `workspace_admin` | `workspace:{id}` | `documents:read/write`, `members:manage`, `invitations:create/revoke/list` |
| `editor` | `workspace:{id}` | `documents:read/write` |
| `viewer` | `workspace:{id}` | `documents:read` |

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

- `.env` lives in the **repository root** and is discovered by the seed binary, the example, and `#[sqlx::test]` (which reads it via sqlx's built-in `dotenvy` support), so run the commands below from their documented locations.
- `.env` must be LF, not CRLF. If you ever ran `export $(grep -v '^#' .env | xargs)`, `unset BIND_ADDR JWT_SECRET DATABASE_URL` and reopen the shell.
- Do not put `LEPTOS_*` variables into `.env` — empty values break `get_configuration(None)`.
- `DATABASE_URL` is used in three places: by the running application, by `seed`, and by `cargo test`. The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege for `#[sqlx::test]`; the default `postgres` superuser from `docker-compose.yml` already does.

### Apply migrations and seed data

Run from the repository root:

```bash
cargo run -p seed
```

Demo users created by seed:

| Role | Email | Password |
|---|---|---|
| Platform admin | `platform-admin@example.test` | `PlatformAdmin123!` |
| Tenant owner | `owner@acme.test` | `Owner123!` |
| Workspace editor | `editor@acme.test` | `Editor123!` |
| Workspace viewer | `viewer@acme.test` | `Viewer123!` |

The command applies database migrations (including `20261102000001_authn_refresh_tokens.sql`) and creates initial platform, tenant, workspace, user, and authorization data. It is idempotent: re-running it re-hashes passwords and re-applies policies without creating duplicate rows.

**Policy regrant.** `seed` calls `grant_platform_admin`, `grant_tenant_owner`, and `grant_workspace_role` on every invocation. Casbin's `add_policy` deduplicates existing `p`-rows and adds new ones; this is how existing tenant/workspace policies pick up permissions introduced by later library versions (for example, `invitations:create/revoke/list` added in Stage 2a).

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

The live-reload port is `3396` (`[package.metadata.leptos] reload-port` in `examples/saas-leptos/Cargo.toml`); this avoids clashing with common dev-server ports such as `3000`/`3001`.

Then in the browser:

1. `/register` or `/login` with one of the demo accounts.
2. `/platform` — as platform admin, create a tenant.
3. `/tenants` — list of tenants you're a member of; click **Open**.
4. `/tenants/<tenant_id>` — as tenant owner, create a workspace.
5. `/workspaces` — list of workspaces you're a member of.
6. `/workspaces/<workspace_id>` — as editor, create documents; click a document title to view it on its dedicated page.
7. `/tenants/<tenant_id>/invitations` — as tenant owner, create a tenant invitation (link, copied once); `/workspaces/<workspace_id>/invitations` — as workspace owner, create a workspace invitation.
8. Paste `/invitations/<64 hex>` into another browser/session (after logging in as someone else) — accept-flow writes `tenant_members` / `workspace_members` and grants the corresponding role.
9. **Wait 15+ minutes** — the auto-refresh middleware transparently rotates the refresh token; UI continues to work. The **Renew (demo)** button in the header shows the current user is valid.

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

50 tests, all green (23 unit + 27 `#[sqlx::test]` integration).

Unit tests live inline (`#[cfg(test)] mod tests`) in `crates/authn` and `crates/saas`. Integration tests live in `crates/authn/tests/` and `crates/saas/tests/` and use `#[sqlx::test]`:

- Each test gets its own isolated database on the server pointed to by `DATABASE_URL`; `crates/db/migrations` are applied automatically; the database is dropped when the test finishes.
- No manual `createdb` is required.
- The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege (the default `postgres` superuser satisfies this).
- Tests can run in parallel; isolation is per-database.

`accept_invitation` and `*::list_memberships` have no unit tests: they do not call `authz.require` and go straight to SQL, which a lazy `PgPool` cannot serve; they are covered by integration tests.

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
│   ├── identity/
│   ├── authn/
│   ├── saas/
│   ├── db/
│   │   └── migrations/
│   │       ├── 20261026000001_init.sql
│   │       ├── 20261101000001_saas_invitations.sql
│   │       └── 20261102000001_authn_refresh_tokens.sql
│   └── seed/
└── examples/
    └── saas-leptos/
        ├── Cargo.toml
        ├── src/
        │   ├── layout.rs
        │   ├── middleware.rs
        │   ├── pages/
        │   │   ├── auth.rs
        │   │   ├── home.rs
        │   │   ├── invitation.rs
        │   │   ├── mod.rs
        │   │   ├── platform.rs
        │   │   ├── tenant.rs
        │   │   └── workspace.rs
        │   ├── error.rs
        │   ├── extract.rs
        │   ├── lib.rs
        │   ├── main.rs
        │   └── state.rs
        ├── style/
        └── public/
```

### domain

Shared DTOs (`Tenant`, `Workspace`, `Document`, `AuthUser`, `Invitation`), the `InvitationTarget` enum (`Tenant(Uuid) | Workspace(Uuid)`), and authorization domain helpers (`PLATFORM_DOMAIN`, `tenant_domain`, `workspace_domain`). No SQL queries, no logic — just types. `sqlx::FromRow` / `sqlx::Type` derives are gated behind the `ssr` feature.

### authz

The `AuthorizationEngine` trait, `AuthzError`, and `WorkspaceRole`. `WorkspaceRole::permissions()` is the **source of Casbin policies** for workspace-scoped roles (including `invitations:create/revoke/list` on `Admin`); it is not a UI list. No Casbin, no SQL, no HTTP. The trait is dyn-safe (`async-trait`); business code works with `Arc<dyn AuthorizationEngine>`.

### authz-casbin

`CasbinAuthz` — the canonical implementation of `AuthorizationEngine` on top of Casbin and `sqlx-adapter`. The `g`/`p` matcher and `grant_*` methods live here, driven by `WorkspaceRole::permissions()`. `grant_tenant_owner` writes `workspaces:create` plus `invitations:create/revoke/list` in the tenant domain. Business code never talks to Casbin directly. Two constructors: `CasbinAuthz::new(&database_url)` (production, own pool) and `CasbinAuthz::from_pool(PgPool)` (consumers and tests that already have a pool, e.g. `#[sqlx::test]`).

### identity

The sole owner of the `users` table. Provides `AuthUser`, `UserRecord` (including `password_hash`, never leaves this crate's boundary), `validate_email`, `validate_password`, `find_by_id`, `find_by_email`, `create_user`, and idempotent `upsert_user`. Does **not** hash passwords (that is `authn`'s job) and does not know about JWT, cookies, or roles.

### authn

The authentication mechanism on top of `identity`. Provides `Authn::with_ttl` (and `new`), `register`, `login`, `issue_access_token`, `issue_refresh_token`, `rotate_refresh_token`, `revoke_refresh_token`, `revoke_family`, `verify_token`, and `hash_password`. Uses Argon2 for passwords, `jsonwebtoken` for access tokens, and `sha2` for opaque refresh tokens (rotation with family revocation, stored in `refresh_tokens`). Talks to `users` through `identity`. Does **not** know about HTTP, cookies, Leptos, or `AuthorizationEngine`. `verify_token` returns `Ok(None)` for deleted users and invalid `sub`, `Err` for invalid signature or expiry. Covered by 13 unit tests and 13 `#[sqlx::test]` integration tests.

### saas

Business logic, independent of UI framework. `SaasState`, `SaasBuilder`, `CoreError`, and services:

- `platform::create_tenant` — container only (`INSERT tenants`, no membership, no grants).
- `platform::provision_tenant(actor, name, owner)` — creates a tenant and explicitly assigns `owner` in one transaction (`INSERT tenants` + `INSERT tenant_members(owner, 'owner')` + `grant_tenant_owner(owner)`).
- `tenant::create_workspace` — creates a workspace and assigns the creator `workspace_admin` (side effect preserved: a workspace is a working unit, and its creator is by definition its admin).
- `tenant::list_memberships` / `workspace::list_memberships` — membership queries (see below).
- `workspace::create_document` / `workspace::list_documents` / `workspace::get_document`.
- `invitation::create_invitation` — returns `(Invitation, raw_token)`; raw token is shown once and is not persisted (`invitations.token_hash` stores SHA-256).
- `invitation::accept_invitation` — by raw token; writes `*_members` and grants the role in one transaction.
- `invitation::revoke_invitation` / `invitation::list_invitations`.

Every service calls `state.authz.require(...)` before touching the database, **except** three explicit exceptions (see handoff §5 p.5):

- `invitation::accept_invitation` — authorized by the invitation token, not by `authz.require`.
- `tenant::list_memberships` / `workspace::list_memberships` — membership queries, not protected actions. There is no domain to `require` before knowing the result; `*_members` is the authoritative source for "which tenants/workspaces am I a member of". `casbin_rule` remains the authoritative source for actions **inside** a tenant or workspace. A platform admin who provisioned a tenant for someone else (actor ≠ owner) does not appear in these lists.

Depends on `authz` (trait), `identity` (`AuthUser`), `domain`, `sqlx`, and `sha2`. Construction goes through `SaasBuilder` only; `SaasState::new` is intentionally not exposed, so `authz` is always present. Covered by 11 unit tests (mock `AuthorizationEngine`) and 14 `#[sqlx::test]` integration tests.

### db

PostgreSQL connection helper and migration runner. Migrations live in `crates/db/migrations/`:

- `20261026000001_init.sql` — `users`, `tenants`, `workspaces`, `tenant_members`, `workspace_members`, `documents`, `casbin_rule`.
- `20261101000001_saas_invitations.sql` — `invitations` (owner: `saas`).
- `20261102000001_authn_refresh_tokens.sql` — `refresh_tokens` (owner: `authn`, Stage 2b).
Includes a `build.rs` with `cargo:rerun-if-changed=migrations` so that Cargo
recompiles `db` whenever a migration file changes (prevents stale
`sqlx::migrate!` caches across workspace targets).

### seed

Standalone binary for creating initial platform, tenant, workspace, user, and policy data. Uses `identity::upsert_user`, `authn::hash_password`, `authz::WorkspaceRole`, and `authz-casbin` grants; other bootstrap rows are written with inline SQL by design (§11 of the handoff). Re-runs re-grant policies, which is how existing seed tenants/workspaces pick up newly introduced permissions such as `invitations:*`.

### examples/saas-leptos

The reference consumer application: Leptos UI, Axum server, `#[server]` wrappers, and `AppState`. `#[server]` functions are thin: `extract::CurrentUser::from_request().await?.require()?` resolves the user (HTTP 401 when missing), then the call delegates to `saas::*` or `authn::*`; errors go through `error::core_error_to_server_fn` / `error::authn_error_to_server_fn`, which map to HTTP 400/401/403/404/409/500. `AppState` holds `authn`, `saas`, and `leptos_options`, and implements `FromRef<AppState> for LeptosOptions`. `src/extract.rs` holds `CurrentUser`; `src/error.rs` holds the error mapping; `src/middleware.rs` holds the auto-refresh middleware; `src/layout.rs` holds the global UI layout. This crate is **not** part of the library workspace; it is checked separately with `--manifest-path examples/saas-leptos/Cargo.toml`.

Routes (Stage 2b):

| Route | Component | Purpose |
|---|---|---|
| `/` | `pages::home::HomePage` | landing page, links |
| `/login` | `pages::auth::LoginPage` | sign in |
| `/register` | `pages::auth::RegisterPage` | sign up |
| `/platform` | `pages::platform::PlatformPage` | create a tenant (as platform admin) |
| `/tenants` | `pages::tenant::TenantsListPage` | list of my tenants |
| `/tenants/:tenant_id` | `pages::tenant::TenantPage` | single tenant (create workspace) |
| `/tenants/:tenant_id/invitations` | `pages::invitation::TenantInvitationsPage` | tenant invitations |
| `/workspaces` | `pages::workspace::WorkspacesListPage` | list of my workspaces |
| `/workspaces/:workspace_id` | `pages::workspace::WorkspacePage` | single workspace (documents) |
| `/workspaces/:workspace_id/documents/:document_id` | `pages::workspace::DocumentPage` | single document view |
| `/workspaces/:workspace_id/invitations` | `pages::invitation::WorkspaceInvitationsPage` | workspace invitations |
| `/invitations/:token` | `pages::invitation::AcceptInvitationPage` | accept-flow |

Plural URLs (`/tenants`, `/workspaces`) are intentional: list pages are first-class. `/invitations/:token` lives under a shared `/invitations` prefix.

## Authorization model

A request is represented as:

```text
subject, domain, object, action
```

Examples:

```text
user_id, platform, tenants, create
user_id, tenant:uuid, workspaces, create
user_id, tenant:uuid, invitations, create
user_id, workspace:uuid, documents, write
user_id, workspace:uuid, invitations, list
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

Both `g` (user → role in domain) and `p` (role → obj, act in domain) are required; `grant_*` methods add both.

Authorization is always checked on the server before business logic executes. Exceptions: `accept_invitation` (by token) and `*::list_memberships` (membership queries) — see handoff §5 p.5.

## Development principles

- Keep authentication separate from authorization.
- Keep authorization separate from business logic.
- Never trust client-supplied tenant or workspace identifiers without server-side validation.
- Always scope database queries by tenant or workspace.
- Treat UI visibility as convenience, not as a security boundary.
- Prefer explicit roles and permissions over unrestricted superuser access.
- `saas` and `authn` do not know about Leptos, Axum, or Casbin.
- Library crates do not depend on `examples/*`; each example has its own `Cargo.toml` and `Cargo.lock`.
- Server functions resolve the actor through `extract::CurrentUser`; a missing actor is HTTP 401, not a generic `ServerFnError`.
- Library errors (`CoreError`, `AuthnError`, `IdentityError`) are mapped to HTTP status codes in the example (`src/error.rs`); keep new variants covered by that mapping.
- Invitation raw tokens are returned once from `saas::invitation::create_invitation` and are never persisted; only `invitations.token_hash` (SHA-256) is stored.
- **Refresh raw tokens are returned once from `authn::issue_refresh_token` and are never persisted; only `refresh_tokens.token_hash` (SHA-256) is stored.**
- `accept_invitation` does not compare `actor.email` to `invitation.email` until email verification (Stage 3); addressed invitations are effectively links today — documented limitation, not a bug.
- **Auto-refresh middleware serializes refresh within a single HTTP request; parallel HTTP requests with the same refresh token are a known limitation (Stage 2c/2d will add single-flight).**

## Roadmap

- Stage 1 (done): typed error mapping to HTTP codes, `CurrentUser` extractor, mock `AuthorizationEngine` and `#[sqlx::test]` integration tests for `authn`, `saas`, and cross-tenant / cross-workspace access; `create_tenant` / `create_workspace` grant the creator a role
- Stage 1.5 (done): workspace `async-trait` dependency, removal of unused `tower-http` / `getrandom` / `serde_json` / `jsonwebtoken` / `argon2`, removal of dead `#[server] current_user`, `.env.example` (EN), README `cargo test`
- Stage 1.1 (done): `create_tenant` container only; `provision_tenant(actor, name, owner)` for explicit owner assignment; `create_workspace` side effect preserved
- Stage 2a (done): invitations core — `invitations` table, `saas::invitation::{create, accept, revoke, list}`, `invitations:*` permissions, `tenant::list_memberships` / `workspace::list_memberships`, plural URL scheme (`/tenants`, `/workspaces`, `/invitations/:token`)
- **Stage 2b (done): refresh tokens with rotation + family revocation, auto-refresh middleware, logout with server-side invalidation, shorter access TTL, `access_token` + `refresh_token` cookies, global layout, document pages**
- Stage 2e: domain-ownership RBAC (ADR-0001), `access` crate, `grant_role`/`revoke_role`, `*_members` multi-role PK, `seed` bootstrap updates
- Stage 2c: workspace member management (list/change_role/remove), UI hides/disables buttons based on `authz.can`, client-side auto-retry
- Stage 2d: Casbin policy cleanup on delete + single Casbin/`saas` connection + single-flight refresh
- Stage 3: platform admin UI, tenant suspension, email verification (makes addressed invitations effective), audit log, return-URL preservation for `/invitations/:token`
- Stage 4: Dockerfile, CI (fmt/clippy/test/migration check), observability, backups, cookie `Secure`/`SameSite`, CSRF, rate limiting (incl. `/refresh`), optional RLS, E2E HTTP tests

## License

See the `LICENSE` file in the root of the repository.
