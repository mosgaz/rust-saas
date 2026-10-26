# rust-saas

**rust-saas** is a full-stack Rust platform for building multi-tenant SaaS applications.

It combines an isomorphic Leptos frontend, an Axum-based backend, PostgreSQL persistence, and Casbin-powered authorization. The project is organized as a Cargo workspace with focused crates that separate business logic, identity, authentication, authorization, and transport from each other, so the core crates can be reused in other applications through git dependencies.

## Features

- Multi-tenant architecture with tenants and workspaces
- Identity-first user model
- Email and password authentication
- Argon2 password hashing
- JWT-based sessions stored in HTTP-only cookies
- Domain-scoped RBAC authorization with Casbin, behind an `AuthorizationEngine` trait
- Platform, tenant, and workspace authorization domains
- Leptos server-side rendering and client hydration
- Server functions for frontend-to-backend communication
- PostgreSQL migrations with SQLx
- Reproducible local development with Docker Compose
- Database seed command for bootstrap data
- Tailwind CSS v4 styling

## Architecture

The repository uses a Cargo workspace:

```text
crates/
├── domain/         Shared DTOs, domain helpers, PLATFORM_DOMAIN
├── authz/          AuthorizationEngine trait + AuthzError (no Casbin)
├── authz-casbin/   CasbinAuthz: canonical trait implementation
├── identity/       Sole owner of `users`: AuthUser, UserRecord, validation, CRUD
├── authn/          Argon2, JWT, register/login/verify_token/issue_token
├── saas/           Business logic: platform, tenant, workspace, documents
├── db/             PostgreSQL connection and migrations
├── seed/           Bootstrap data and demo accounts
└── app/            Leptos UI, Axum server, server functions
```

The application separates four concerns:

| Concern | Responsibility | Crate |
|---|---|---|
| Identity | Who you are as an entity (`users` table, `AuthUser`) | `identity` |
| Authentication | How you proved you are who you are (Argon2, JWT) | `authn` |
| Authorization | What you are allowed to do (`AuthorizationEngine`) | `authz` / `authz-casbin` |
| Data isolation | Which rows you can see (SQL filters by tenant/workspace) | `saas` |

`Casbin does not replace SQL isolation. JWT does not replace Casbin.
UI does not replace backend authorization.`

### Crate dependency graph

```text
app          -> saas, authn, identity, authz-casbin, db, domain
seed         -> authn, identity, authz-casbin, db, domain
saas         -> authz (trait), identity, db, domain
authn        -> identity, db, domain
identity     -> domain, sqlx
authz-casbin -> authz (trait), casbin, sqlx-adapter
authz        -> (trait only)
db           -> sqlx
domain       -> serde, uuid, chrono; sqlx (optional, ssr only)
```

Forbidden edges:

- `saas` does not depend on Leptos, Axum, `casbin::Enforcer`, JWT, or Argon2.
- `authn` does not depend on `authz`.
- `identity` does not depend on `authn` or `authz`.
- `authz` does not depend on Casbin, SQL, HTTP, Leptos, or JWT.
- `authz-casbin` does not depend on business tables (`users`, `tenants`).
- `app` does not call `casbin_rule` directly and does not call `authz.require` — only `saas::*` and `authn::*`.

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

### Authorization domains

Casbin policies are scoped by domain:

| Domain | Purpose |
|---|---|
| `platform` | Platform-level administration |
| `tenant:{tenant_id}` | Tenant-level operations |
| `workspace:{workspace_id}` | Workspace-level operations |

Example roles:

- `platform_admin`
- `tenant_owner`
- `workspace_admin`
- `editor`
- `viewer`

## Technology stack

| Layer | Technology |
|---|---|
| Language | Rust |
| UI | Leptos |
| Backend | Axum |
| Database | PostgreSQL 16 |
| Database access | SQLx |
| Authorization | Casbin (via `authz-casbin`) |
| Authentication | Argon2, JSON Web Tokens |
| Styling | Tailwind CSS v4 |
| Local infrastructure | Docker Compose (v1) |

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

```bash
docker-compose up -d
docker-compose ps   # STATUS = Up (healthy)
```

### Configure environment

Copy the example environment file:

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
DATABASE_URL=postgres://postgres:postgres@localhost:5430/rust_saas
JWT_SECRET=replace-with-a-long-random-secret
BIND_ADDR=127.0.0.1:3395
```

Notes:

- `.env` must be LF, not CRLF. If you ever ran `export $(grep -v '^#' .env | xargs)`, `unset BIND_ADDR JWT_SECRET DATABASE_URL` and reopen the shell.
- Do not put `LEPTOS_*` variables into `.env` — empty values break `get_configuration(None)`.

### Apply migrations and seed data

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

The command applies database migrations and creates initial platform, tenant, workspace, user, and authorization data. It is idempotent: re-running it re-hashes passwords and re-applies policies without creating duplicate rows.

Seed prints `tenant id:` and `workspace id:`; use them in the UI as shown below.

### Run the application

```bash
cargo leptos watch
```

Open:

```text
http://127.0.0.1:3395
```

Then in the browser:

1. `/register` or `/login` with one of the demo accounts.
2. `/platform` — as platform admin, create a tenant.
3. `/tenant/<tenant_id>` — as tenant owner, create a workspace.
4. `/workspace/<workspace_id>` — as editor, create documents; as viewer, list only.

## Project layout

```text
.
├── Cargo.toml
├── docker-compose.yml
├── .env.example
└── crates/
    ├── domain/
    ├── authz/
    ├── authz-casbin/
    ├── identity/
    ├── authn/
    ├── saas/
    ├── db/
    ├── seed/
    └── app/
```

### domain

Shared DTOs (`User`, `Tenant`, `Workspace`, `Document`, `AuthUser`), authorization domain helpers (`PLATFORM_DOMAIN`, `tenant_domain`, `workspace_domain`). No SQL queries, no logic — just types. `sqlx::FromRow` derives are gated behind the `ssr` feature.

### authz

The `AuthorizationEngine` trait and `AuthzError`. No Casbin, no SQL, no HTTP. Consumers depend on this crate only; the trait is dyn-safe (`async-trait`), so business code works with `Arc<dyn AuthorizationEngine>`.

### authz-casbin

`CasbinAuthz` — the canonical implementation of `AuthorizationEngine` on top of Casbin and `sqlx-adapter`. The `g`/`p` matcher, `grant_*` methods, and `WorkspaceRole` permissions live here. Business code never talks to Casbin directly.

### identity

The sole owner of the `users` table. Provides `AuthUser`, `UserRecord` (including `password_hash`, never leaves this crate's boundary), `validate_email`, `validate_password`, `find_by_id`, `find_by_email`, `create_user`, and idempotent `upsert_user`. Does **not** hash passwords (that is `authn`'s job) and does not know about JWT, cookies, or roles.

### authn

The authentication mechanism on top of `identity`. Provides `Authn::register`, `Authn::login`, `Authn::issue_token`, `Authn::verify_token`, and `hash_password`. Uses Argon2 and `jsonwebtoken`. Does **not** know about HTTP, cookies, Leptos, or `AuthorizationEngine`. `verify_token` returns `Ok(None)` for deleted users and invalid `sub`, `Err` for invalid signature or expiry.

### saas

Business logic, independent of UI framework. `SaasState`, `SaasBuilder`, `CoreError`, and services: `platform::create_tenant`, `tenant::create_workspace`, `workspace::create_document`, `workspace::list_documents`. Every service checks authorization via `state.authz.require(...)` before touching the database. Depends only on `authz` (trait), `identity` (`AuthUser`), `db`, and `domain`.

### db

PostgreSQL connection helper and migration runner. Migrations live in `crates/db/migrations/`.

### seed

Standalone binary for creating initial platform, tenant, workspace, user, and policy data. Uses `identity::upsert_user`, `authn::hash_password`, and `authz-casbin` grants; other bootstrap rows are written with inline SQL by design (§10 of the handoff).

### app

The application crate: Leptos UI, Axum server, `#[server]` wrappers, and `AppState`. `#[server]` functions are thin: they resolve `current_user` through `authn`, then delegate to `saas::*`. `AppState` holds `pool`, `authz`, `authn`, `saas`, and `leptos_options`, and implements `FromRef<AppState> for LeptosOptions`.

## Authorization model

A request is represented as:

```text
subject, domain, object, action
```

Examples:

```text
user_id, platform, tenants, create
user_id, tenant:uuid, workspaces, create
user_id, workspace:uuid, documents, write
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

Authorization is always checked on the server before business logic executes.

## Development principles

- Keep authentication separate from authorization.
- Keep authorization separate from business logic.
- Never trust client-supplied tenant or workspace identifiers without server-side validation.
- Always scope database queries by tenant or workspace.
- Treat UI visibility as convenience, not as a security boundary.
- Prefer explicit roles and permissions over unrestricted superuser access.
- `saas` and `authn` do not know about Leptos, Axum, or Casbin.

## Roadmap

- Stage 1: typed errors, `CurrentUser` extractor, integration tests for `authn` and cross-tenant access, mock `AuthorizationEngine` in `saas` tests
- Stage 2: invitation-based workspace membership, role management UI, Casbin policy cleanup on delete
- Stage 3: platform admin UI, tenant suspension, audit log
- Stage 4: Dockerfile, CI (fmt/clippy/test/migration check), observability, backups

## License

See the `LICENSE` file in the root of the repository.