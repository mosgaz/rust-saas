# Rust SAAS

**rust-saas** is a Rust library and reference application for building multi-tenant SaaS.

The library crates live in `crates/` (a Cargo workspace) and separate business logic, identity, authentication, authorization, and persistence from each other, so they can be reused in other applications through git dependencies. The `examples/saas-leptos` directory contains a reference consumer that combines them with an isomorphic Leptos frontend and an Axum-based backend.

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

The repository is split into two layers:

```text
crates/                  (library — the Cargo workspace)
├── domain/             Shared DTOs, domain helpers, PLATFORM_DOMAIN
├── authz/              AuthorizationEngine trait + AuthzError (no Casbin)
├── authz-casbin/       CasbinAuthz: canonical trait implementation
├── identity/           Sole owner of `users`: AuthUser, UserRecord, validation, CRUD
├── authn/              Argon2, JWT, register/login/verify_token/issue_token
├── saas/               Business logic: platform, tenant, workspace, documents
├── db/                 PostgreSQL connection and migrations
└── seed/               Bootstrap data and demo accounts

examples/                (reference consumers — outside the workspace)
└── saas-leptos/        Leptos SSR + Axum + #[server] + cookie
```

`examples/*` is listed in `workspace.exclude`; each example has its own `Cargo.toml` and `Cargo.lock`, and depends on the library crates via path dependencies pointing at `../../crates/*`.

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
saas-leptos  -> domain, authz, authz-casbin, identity, authn, saas, db   (example)
seed         -> authz, authn, identity, authz-casbin, db, domain
saas         -> authz (trait), identity, domain, sqlx
authn        -> identity, domain, sqlx, argon2, jsonwebtoken
identity     -> domain, sqlx
authz-casbin -> authz (trait), domain, casbin, sqlx, sqlx-adapter
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
| UI | Leptos (in the reference example) |
| Backend | Axum (in the reference example) |
| Database | PostgreSQL 16 |
| Database access | SQLx |
| Authorization | Casbin (via `authz-casbin`) |
| Authentication | Argon2, JSON Web Tokens |
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

The command applies database migrations and creates initial platform, tenant, workspace, user, and authorization data. It is idempotent: re-running it re-hashes passwords and re-applies policies without creating duplicate rows.

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

Then in the browser:

1. `/register` or `/login` with one of the demo accounts.
2. `/platform` — as platform admin, create a tenant.
3. `/tenant/<tenant_id>` — as tenant owner, create a workspace.
4. `/workspace/<workspace_id>` — as editor, create documents; as viewer, list only.

### Checking the build

From the repository root:

```bash
clear && cargo check && cargo check -p seed && cargo check --manifest-path examples/saas-leptos/Cargo.toml --features ssr && cargo check --manifest-path examples/saas-leptos/Cargo.toml
```

### Running tests

From the repository root:

```bash
cargo test
```

Unit tests live inline (`#[cfg(test)] mod tests`) in `crates/authn` and `crates/saas`. Integration tests live in `crates/authn/tests/` and `crates/saas/tests/` and use `#[sqlx::test]`:

- Each test gets its own isolated database on the server pointed to by `DATABASE_URL`; `crates/db/migrations` are applied automatically; the database is dropped when the test finishes.
- No manual `createdb` is required.
- The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege (the default `postgres` superuser satisfies this).
- Tests can run in parallel; isolation is per-database.

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
│   └── seed/
└── examples/
    └── saas-leptos/
        ├── Cargo.toml
        ├── src/
        ├── style/
        └── public/
```

### domain

Shared DTOs (`Tenant`, `Workspace`, `Document`, `AuthUser`), authorization domain helpers (`PLATFORM_DOMAIN`, `tenant_domain`, `workspace_domain`). No SQL queries, no logic — just types. `sqlx::FromRow` derives are gated behind the `ssr` feature.

### authz

The `AuthorizationEngine` trait, `AuthzError`, and `WorkspaceRole`. No Casbin, no SQL, no HTTP. Consumers depend on this crate only; the trait is dyn-safe (`async-trait`), so business code works with `Arc<dyn AuthorizationEngine>`.

### authz-casbin

`CasbinAuthz` — the canonical implementation of `AuthorizationEngine` on top of Casbin and `sqlx-adapter`. The `g`/`p` matcher and `grant_*` methods live here, driven by `WorkspaceRole::permissions()`. Business code never talks to Casbin directly. Two constructors: `CasbinAuthz::new(&database_url)` (production, own pool) and `CasbinAuthz::from_pool(PgPool)` (consumers and tests that already have a pool, e.g. `#[sqlx::test]`).

### identity

The sole owner of the `users` table. Provides `AuthUser`, `UserRecord` (including `password_hash`, never leaves this crate's boundary), `validate_email`, `validate_password`, `find_by_id`, `find_by_email`, `create_user`, and idempotent `upsert_user`. Does **not** hash passwords (that is `authn`'s job) and does not know about JWT, cookies, or roles.

### authn

The authentication mechanism on top of `identity`. Provides `Authn::register`, `Authn::login`, `Authn::issue_token`, `Authn::verify_token`, and `hash_password`. Uses Argon2 and `jsonwebtoken`, and talks to `users` through `identity` (via `sqlx`, not through `db`). Does **not** know about HTTP, cookies, Leptos, or `AuthorizationEngine`. `verify_token` returns `Ok(None)` for deleted users and invalid `sub`, `Err` for invalid signature or expiry. Covered by 10 unit tests and 6 `#[sqlx::test]` integration tests.

### saas

Business logic, independent of UI framework. `SaasState`, `SaasBuilder`, `CoreError`, and services: `platform::create_tenant`, `tenant::create_workspace`, `workspace::create_document`, `workspace::list_documents`. Every service checks authorization via `state.authz.require(...)` before touching the database. `create_tenant` and `create_workspace` grant the creator `tenant_owner` / `workspace_admin` respectively, inside the same transaction, then commit. Depends on `authz` (trait), `identity` (`AuthUser`), `domain`, and `sqlx`. Construction goes through `SaasBuilder` only; `SaasState::new` is intentionally not exposed, so `authz` is always present. Covered by 6 unit tests (mock `AuthorizationEngine`) and 4 `#[sqlx::test]` integration tests.

### db

PostgreSQL connection helper and migration runner. Migrations live in `crates/db/migrations/`.

### seed

Standalone binary for creating initial platform, tenant, workspace, user, and policy data. Uses `identity::upsert_user`, `authn::hash_password`, `authz::WorkspaceRole`, and `authz-casbin` grants; other bootstrap rows are written with inline SQL by design (§10 of the handoff).

### examples/saas-leptos

The reference consumer application: Leptos UI, Axum server, `#[server]` wrappers, and `AppState`. `#[server]` functions are thin: `extract::CurrentUser::from_request().await?.require()?` resolves the user (HTTP 401 when missing), then the call delegates to `saas::*` or `authn::*`; errors go through `error::core_error_to_server_fn` / `error::authn_error_to_server_fn`, which map to HTTP 400/401/403/404/409/500. `AppState` holds `authn`, `saas`, and `leptos_options`, and implements `FromRef<AppState> for LeptosOptions`. `src/extract.rs` holds `CurrentUser`; `src/error.rs` holds the error mapping. This crate is **not** part of the library workspace; it is checked separately with `--manifest-path examples/saas-leptos/Cargo.toml`.

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
- Library crates do not depend on `examples/*`; each example has its own `Cargo.toml` and `Cargo.lock`.
- Server functions resolve the actor through `extract::CurrentUser`; a missing actor is HTTP 401, not a generic `ServerFnError`.
- Library errors (`CoreError`, `AuthnError`, `IdentityError`) are mapped to HTTP status codes in the example (`src/error.rs`); keep new variants covered by that mapping.

## Roadmap

- Stage 1 (done): typed error mapping to HTTP codes, `CurrentUser` extractor, mock `AuthorizationEngine` and `#[sqlx::test]` integration tests for `authn`, `saas`, and cross-tenant / cross-workspace access; `create_tenant` / `create_workspace` grant the creator a role
- Stage 2: invitation-based workspace membership, refresh tokens with rotation, logout with session invalidation, role management UI, Casbin policy cleanup on delete
- Stage 3: platform admin UI, tenant suspension, email verification, audit log
- Stage 4: Dockerfile, CI (fmt/clippy/test/migration check), observability, backups, cookie `Secure`/`SameSite`, optional RLS

## License

See the `LICENSE` file in the root of the repository.
