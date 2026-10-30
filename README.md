# Шаг 6/10: `README.md`

**Изменения против Stage 3b:**
- Features: addressed invitations требуют `email_verified` + case-insensitive match; `EmailSender::send_invitation` + `Sent / Failed / Disabled` в UI; новый `CoreError::EmailNotVerified`.
- Architecture / `saas`: `accept_invitation` — verified-first, match, `*_members` и `casbin_rule` после проверок.
- Architecture / `saas-leptos`: `who_am_i` возвращает `SessionUser`; `create_invitation → (Invitation, String, Option<EmailResult>)`; `InvitationAcceptPage` — ветки unverified/mismatch/resend.
- Getting started: шаг про addressed invitation.
- Running tests: 83 → 90; разбивка обновлена.
- Development principles: новый bullet про addressed invitations.
- Roadmap: 3c (done), 3d (next).

```markdown
# Rust SAAS

**rust-saas** is a Rust library and reference application for building multi-tenant SaaS.

The library crates live in `crates/` (a Cargo workspace) and separate business logic, identity, authentication, and authorization from each other, so they can be reused in other applications through git dependencies. The `examples/saas-leptos` directory contains a reference consumer that combines them with an isomorphic Leptos frontend and an Axum-based backend.

## Features

- Multi-tenant architecture with tenants and workspaces
- Identity-first user model
- Email and password authentication
- Argon2 password hashing
- **JWT access tokens (short-lived) and opaque refresh tokens (rotation with family revocation)**
- **Refresh grace window: parallel-request race does not revoke the token family**
- **Auto-refresh middleware scoped to protected routes (SSR + server functions); static assets bypass it**
- **Server-side logout (revokes refresh token family, records `revoked_reason`)**
- **Access-token claims `{ sub, iat, exp }` (no `email`); user is resolved from `users` on every request**
- **Email verification: single-active 24-hour token, idempotent verification, `/verify/:token` page, per-email rate limit (3/hour)**
- **Addressed invitations (Stage 3c): `accept_invitation` requires a verified, matching email (`email_verified` first, then case-insensitive match); the invitation link is delivered via `EmailSender::send_invitation`, and the UI distinguishes `Sent` / `Failed` / `Disabled` (with a copy-link fallback). Link invitations (`email IS NULL`) keep Stage 2a behaviour.**
- **Domain-ownership RBAC: roles are data, owner of a domain has all permissions**
- **Owner guard: the last holder of a protected role cannot be removed**
- **Tenant and workspace member management (list; assign/remove role; permission-gated UI; role and member selects)**
- **Role management: list, create, edit (Stage 3a), delete; `key` is read-only after creation**
- **UI gating by effective permissions (`my_permissions`, batched per domain)**
- **Return-URL preservation across login/registration (anonymous visitor on `/invitations/:token` is redirected back after sign-in; open-redirect attempts rejected by `is_safe_return_url`)**
- Platform, tenant, and workspace authorization domains
- Invitations (reusable links and addressed) with `token_hash` (SHA-256), `expires_at`, `max_uses`, `revoked_at`
- Document pages (view and create inside workspaces)
- Tenant, workspace, and document navigation (`/tenants`, `/workspaces`, `/workspaces/:id/documents/:id`)
- Leptos server-side rendering and client hydration
- Server functions for frontend-to-backend communication
- PostgreSQL migrations with SQLx
- Reproducible local development with Docker Compose (PostgreSQL + Mailpit)
- Database seed command for bootstrap data
- Tailwind CSS v4 styling

## Architecture

The repository is split into two layers:

```text
crates/                  (library — the Cargo workspace)
├── domain/             Shared DTOs (Tenant, Workspace, Document, AuthUser, Invitation, Member),
│                       InvitationTarget, domain helpers, PLATFORM_DOMAIN;
│                       AuthUser.email_verified (derived from users.email_verified_at)
├── authz/              AuthorizationEngine trait
│                       (can / require / grant_role / revoke_role / has_role /
│                        count_users_with_role / purge_role) + AuthzError
├── authz-casbin/       CasbinAuthz: canonical trait implementation
├── access/             Sole owner of `permissions`, `roles`, `role_permissions`:
│                       Role, Permission, RoleKey, AccessState, AccessError, role CRUD,
│                       create_owner_role, get_role_by_id, delete_role_by_id,
│                       list_permissions, get_permissions_for_role
├── identity/           Sole owner of `users`: AuthUser, UserRecord, validation, CRUD;
│                       UserRecord.email_verified_at (source of truth for the derived flag)
├── authn/              Argon2, JWT access tokens, opaque refresh tokens, rotation
│                       with grace window; email verification (single-active, 24h);
│                       RevokeReason (logout / reuse_detected / password_reset)
├── saas/               Business logic: platform, tenant, workspace, invitation, member,
│                       access (wrappers, incl. my_permissions)
├── db/                 PostgreSQL connection and migrations
└── seed/               Bootstrap data and demo accounts (all email-verified)

examples/                (reference consumers — outside the workspace)
└── saas-leptos/        Leptos SSR + Axum + #[server] + middleware + cookies
                        + SMTP transport (lettre) + in-memory rate limiter
```

`examples/*` is listed in `workspace.exclude`; each example has its own `Cargo.toml` and `Cargo.lock`, and depends on the library crates via path dependencies pointing at `../../crates/*`.

The application separates five concerns:

| Concern | Responsibility | Crate |
|---|---|---|
| Identity | Who you are as an entity (`users` table, `AuthUser`) | `identity` |
| Authentication | How you proved you are who you are (Argon2, JWT, refresh tokens, email verification) | `authn` |
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
domain       -> serde, uuid, chrono; sqlx (optional, ssr only);
                `test-support` feature (test-only AuthUser constructors)
```

Forbidden edges:

- `saas` does not depend on Leptos, Axum, `casbin::Enforcer`, JWT, or Argon2. `sha2` is used only for `invitation::hash_token`.
- `access` does not depend on business tables (`tenants`, `workspaces`, `documents`, `invitations`, `*_members`), HTTP, UI, JWT, or Argon2.
- `authn` does not depend on `authz`. `sha2` is used only for refresh- and email-verification `token_hash`. `lettre` is **not** a dependency of `authn`; SMTP delivery lives in the example.
- `identity` does not depend on `authn` or `authz`.
- `authz` does not depend on Casbin, SQL, HTTP, Leptos, or JWT. It does not know about specific roles.
- `authz-casbin` does not depend on business tables (`users`, `tenants`, `invitations`, `refresh_tokens`, `roles`, `permissions`). It uses raw SQL only against its own `casbin_rule` table (`has_role`, `count_users_with_role`, `purge_role`).
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
- An **invitation** targets exactly one tenant or one workspace (`CHECK ((tenant_id IS NULL) <> (workspace_id IS NULL))`). `email IS NULL` is a reusable link; `email IS NOT NULL` is an addressed invitation (Stage 3c).

### Authorization domains

Casbin policies are scoped by domain:

| Domain | Purpose |
|---|---|
| `platform` | Platform-level administration |
| `tenant:{tenant_id}` | Tenant-level operations |
| `workspace:{workspace_id}` | Workspace-level operations |

### Domain-ownership RBAC

- A **role** is a named set of permissions in a **domain** (not in a tenant).
- A **permission** is a `(resource, action)` pair from the `permissions` reference table.
- The **owner** role in a domain has **all permissions** from the reference table, is `protected=true` and `immutable=true`. It is created by `access::create_owner_role(domain)` (idempotent) from `saas::platform::provision_tenant` and `saas::tenant::create_workspace`, and via the bootstrap SQL migration for the `platform` domain.
- The owner of a domain creates custom roles and assigns them to users of that domain (`saas::access::create_role` / `assign_role` / `update_role`). Roles can be edited (`name`, `description`, `permissions`) and deleted; `key` is immutable (`update_role` never changes it; rename = delete + create, ADR-0001).
- Users can hold **multiple roles** in the same domain. `tenant_members` and `workspace_members` use `PRIMARY KEY (scope_id, user_id, role)`.
- The **owner guard** prevents removing the last holder of a `protected` role from a domain (`saas::member::{change_role, remove_role}` return `Forbidden`). Non-protected roles have no last-holder guard. The guard reads `casbin_rule` (the source of truth for authorization), not `*_members`.

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
| Email verification | SHA-256 (`sha2`) over a random raw token; raw token not persisted; 24-hour TTL, single-active per user |
| Email delivery | `lettre` (async SMTP, tokio1-rustls) in the example; Mailpit for local dev |
| Rate limiting | In-memory sliding-window (`SimpleRateLimiter` in the example; not distributed) |
| Invitation tokens | SHA-256 (`sha2`) over a random raw token; raw token not persisted |
| Refresh tokens | SHA-256 (`sha2`) over a random raw token; raw token not persisted |
| Styling | Tailwind CSS v4 |
| Local infrastructure | Docker Compose (v1) — PostgreSQL + Mailpit |
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

### Start PostgreSQL and Mailpit

Run from the repository root:

```bash
docker-compose up -d
docker-compose ps   # both services: postgres Up (healthy); mailpit Up
```

Mailpit is only needed for the email-verification flow (Stage 3b) and addressed invitations (Stage 3c). Open `http://localhost:8025` to read the inbox. Without Mailpit, the app falls back to `NoopEmailSender`: registration still succeeds, but the UI reports "email delivery not configured", and no verification or invitation link is delivered.

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

# Stage 3b: SMTP for verification emails (points at Mailpit by default).
# When unset, the app uses NoopEmailSender (registration still succeeds).
SMTP_URL=smtp://localhost:1025
# SMTP_FROM=noreply@example.test      # optional, defaults to noreply@example.test
# BASE_URL=http://127.0.0.1:3395      # optional, defaults to http://{BIND_ADDR}

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
- `SMTP_URL` is read only by `examples/saas-leptos`. The library (`authn`) does not depend on `lettre`.

### Apply migrations and seed data

Run from the repository root:

```bash
cargo run -p seed
```

Demo users created by seed (all **email-verified** — Stage 3b):

| Role | Email | Password |
|---|---|---|
| Platform owner | `platform-admin@example.test` | `PlatformAdmin123!` |
| Tenant owner | `owner@acme.test` | `Owner123!` |
| Workspace editor (role `editor`) | `editor@acme.test` | `Editor123!` |
| Workspace viewer (role `viewer`) | `viewer@acme.test` | `Viewer123!` |

The command applies database migrations (including `20261105000001_authn_email_verify.sql` — `users.email_verified_at`, `email_verifications`, `refresh_tokens.revoked_reason`) and creates initial platform, tenant, workspace, user, role, and authorization data. It is idempotent: re-running it re-hashes passwords, re-applies roles/policies, and marks demo accounts verified without moving their original `email_verified_at`.

Seed flow:

1. Grants `platform` `owner` role to the platform admin via `authz.grant_role` (permissions from `access::get_permissions_for_role`).
2. Provisions the tenant via `saas::platform::provision_tenant(..., &RoleKey::parse("owner")?)`.
3. Creates the workspace via `saas::tenant::create_workspace(..., &RoleKey::parse("owner")?)`.
4. Creates demo roles `editor`/`viewer` via `saas::access::create_role`, then assigns them via `saas::access::assign_role`.
5. Marks every demo account verified (`users.email_verified_at = COALESCE(existing, now())`).

**Existing database.** `members_multi_role.sql` changes the primary keys on `tenant_members` and `workspace_members`, and `authn_email_verify.sql` adds new columns and a table. If your DB predates these migrations, `docker-compose down -v` + `cargo run -p seed` is the recommended path.

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

1. `/register` — create a new account. After submit, the page shows "Account created for …" plus the verification-email outcome:
   - **Sent** — an email has been delivered to Mailpit; open `http://localhost:8025` to read the link.
   - **Failed** — SMTP transport error; the page shows a **Resend** button.
   - **Disabled** — no `SMTP_URL`; the page shows "email delivery is not configured".
2. Open the verification link from Mailpit in the same or another browser → `/verify/:token` shows "Email verified: …" and a link to `/login`. Re-opening the same link is safe (idempotent).
3. `/login` with one of the demo accounts (or your freshly-verified one).
4. `/platform` — as platform owner, create a tenant (the creator becomes its `owner` via `provision_tenant`).
5. `/tenants` — list of tenants you're a member of; click **Open**.
6. `/tenants/<tenant_id>` — as tenant owner, create a workspace; the creator becomes its `owner`.
7. `/tenants/<tenant_id>/members` — as tenant owner, see members; assign or remove roles via member/role selects; "Invite instead" jumps to invitations.
8. `/tenants/<tenant_id>/roles` — as tenant owner, list, create, edit, and delete custom roles.
9. `/workspaces` — list of workspaces you're a member of.
10. `/workspaces/<workspace_id>` — as editor, create documents; click a document title to view it on its dedicated page.
11. `/workspaces/<workspace_id>/members` — as workspace owner, see members; assign or remove roles via member/role selects; "Invite instead" jumps to invitations.
12. `/workspaces/<workspace_id>/roles` — as workspace owner, list, create, edit, and delete custom roles.
13. `/tenants/<tenant_id>/invitations` — as tenant owner, create a tenant invitation. **Link invitation** (email empty) — raw token shown once; **addressed invitation** (email set) — the invitation link is sent to that address by email; the UI reports `Sent` / `Failed` (with a copy-link fallback) / `Disabled`. Same on `/workspaces/<workspace_id>/invitations`.
14. **Link invitation flow.** Paste `/invitations/<64 hex>` into another browser/session (not logged in) — the page stores the URL in the `return_url` cookie; click **Log in** or **Register**, sign in, and you are redirected back to the same invitation page, where you can accept it. Accept-flow writes `tenant_members` / `workspace_members` (multi-role PK) and grants the corresponding role via `authz.grant_role`. Link invitations do not require a verified email.
15. **Addressed invitation flow (Stage 3c).** As tenant owner, create an invitation with `email = viewer@acme.test` (or any user's address). Open the invitation link from Mailpit as that user. The server enforces:
    - `invitation.email IS NOT NULL` → `actor.email_verified == false` returns **`email not verified`** (HTTP 403, `CoreError::EmailNotVerified`); the accept page shows "verify your email first" and a **Resend verification email** button.
    - Verified actor whose address does not match (case-insensitively) returns **`forbidden`** (HTTP 403, `CoreError::Forbidden`); the accept page shows "invitation is for X, you are logged in as Y" and a link to `/login`.
    - Verified actor whose address matches → accept succeeds; `tenant_members` + `casbin_rule` are updated.
16. **Wait 15+ minutes** — the auto-refresh middleware transparently rotates the refresh token; UI continues to work.
17. Rate limit: on `RegisterPage` (or after login) press **Resend** four times within an hour — the 4th call returns 429 with "rate limited; try again in Ns".

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

**90 tests, all green** (24 unit + 66 integration: `authn` 13 unit + 22 integration = 35; `saas` 11 unit + 29 integration = 40; `access` 0 unit + 6 integration = 6; `authz-casbin` 0 unit + 9 integration = 9). The count is a plan-level estimate; if the actual run differs slightly, the code is the source of truth.

Unit tests live inline (`#[cfg(test)] mod tests`) in `crates/authn`, `crates/access`, and `crates/saas`. Integration tests live in `crates/*/tests/` and use `#[sqlx::test]`:

- Each test gets its own isolated database on the server pointed to by `DATABASE_URL`; `crates/db/migrations` are applied automatically; the database is dropped when the test finishes.
- No manual `createdb` is required.
- The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege.
- Tests can run in parallel; isolation is per-database.

The reference example has a small unit-test module too (`rate_limit.rs`); run it with `cargo test --manifest-path examples/saas-leptos/Cargo.toml --features ssr rate_limit`.

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
│   │       ├── 20261104000001_access_members_list_permission.sql
│   │       └── 20261105000001_authn_email_verify.sql
│   └── seed/
└── examples/
    └── saas-leptos/
        ├── Cargo.toml
        └── src/
            ├── auth.rs           # register / login / refresh / logout
            │                     # + set_return_url / take_return_url
            │                     # + request_email_verification / verify_email
            ├── email.rs          # EmailResult (hydration-visible);
            │                     # EmailSender / SmtpEmailSender / NoopEmailSender (ssr);
            │                     # send_verification + send_invitation (Stage 3c)
            ├── rate_limit.rs     # SimpleRateLimiter (ssr, in-memory)
            └── ...
```

### domain

Shared DTOs (`Tenant`, `Workspace`, `Document`, `AuthUser`, `Invitation`, `Member`), the `InvitationTarget` enum (`Tenant(Uuid) | Workspace(Uuid)`), and authorization domain helpers (`PLATFORM_DOMAIN`, `tenant_domain`, `workspace_domain`). No SQL queries, no logic — just types. `sqlx::FromRow` / `sqlx::Type` derives are gated behind the `ssr` feature.

`AuthUser.email_verified: bool` is a **derived** boolean (`users.email_verified_at IS NOT NULL`), computed in every SELECT by `identity`. The timestamp itself is internal to `identity`/`authn`.

The `test-support` feature exposes `AuthUser::test_verified()` / `AuthUser::test_unverified()`; enabled only from `[dev-dependencies]` of crates with tests, never in production builds.

### authz

The `AuthorizationEngine` trait — seven methods: `can`, `require`, `grant_role`, `revoke_role`, `has_role`, `count_users_with_role`, `purge_role` — and `AuthzError`. Trait-only: no Casbin, no SQL, no HTTP, no specific roles.

- `grant_role(user_id, domain, role_key, permissions)` writes one `g`-row (`user → role_key → domain`) and one `p`-row per `(resource, action)`.
- `revoke_role` removes the `g`-row (shared `p`-rows remain while the role exists).
- `has_role(user_id, domain, role_key)` returns `true` iff the `g`-row `(user_id, role_key, domain)` exists.
- `count_users_with_role(domain, role_key)` returns the number of distinct holders, counted from `casbin_rule` (not `*_members`).
- `purge_role(domain, role_key)` deletes every `g`-row and `p`-row for `(domain, role_key)`; returns the number of deleted rows. Idempotent.

`has_role`, `count_users_with_role`, and `purge_role` are non-transactional; they are safe to retry.

### authz-casbin

`CasbinAuthz` — the canonical implementation of `AuthorizationEngine` on top of Casbin and `sqlx-adapter`. The `g`/`p` matcher and all seven trait methods live here. Business code never talks to Casbin directly. Two constructors:

- `CasbinAuthz::new(&database_url)` — convenience wrapper that opens its own `PgPool` and delegates to `from_pool`.
- `CasbinAuthz::from_pool(PgPool)` — the recommended constructor. The same `PgPool` is used by `SqlxAdapter` (Casbin persistence) and by the raw-SQL helpers (`has_role`, `count_users_with_role`, `purge_role`). Consumers that already hold a `PgPool` should use this.

`has_role` and `count_users_with_role` query `casbin_rule` directly (the source of truth for authorization). `purge_role` uses a single raw `DELETE` for both `g`- and `p`-rows and then calls `enforcer.load_policy()` to sync the in-memory model. This is the only place where `authz-casbin` uses raw SQL; the table is its own.

Does not know about `roles`/`permissions`/`users`/`tenants`; only `casbin_rule`.

### access

The sole owner of the `permissions`, `roles`, and `role_permissions` tables.

- DTOs: `Role`, `Permission` (`(resource, action)` + description), `RoleKey` (`[a-z0-9_]{1,64}`).
- `AccessState { pool, authz }`, `AccessError`.
- Services (all take `&AccessState`):
  - `create_role(actor, domain, key, name, description, permissions)` — requires `(roles, create)`.
  - `update_role(actor, role_id, name, description, permissions)` — requires `(roles, manage)`; rejects `protected`/`immutable`.
  - `delete_role(actor, role_id)` — requires `(roles, delete)`; rejects `protected`. Does not cascade to `casbin_rule` or `*_members`; consumers that want the full cleanup should use `saas::access::delete_role`.
  - `list_roles(actor, domain)` — requires `(roles, list)`.
  - `get_role(domain, role_key)` — no actor: helper, called after `require` in a caller.
  - `get_role_by_id(role_id)` — no actor: helper, returns `Option<Role>`; used by `saas::access::delete_role` and by the example's role edit form.
  - `delete_role_by_id(role_id)` — no actor: low-level `DELETE` of the `roles` row; idempotent; no `require`, no `protected` check. Used by `saas::access::delete_role` after its own `require` and `protected` check.
  - `get_permissions_for_role(domain, role_key)` — no actor: helper for `saas::access::assign_role`.
  - `list_permissions()` — no actor: public reference.
  - `create_owner_role(domain)` — no actor: idempotent bootstrap; permissions = all from `permissions`.

Does not know about `tenants`, `workspaces`, `documents`, `invitations`, `*_members`, HTTP, UI, JWT, or Argon2.

### identity

The sole owner of the `users` table. Provides `AuthUser`, `UserRecord` (including `password_hash` and `email_verified_at`; never leaves this crate's boundary), `validate_email`, `validate_password`, `find_by_id`, `find_by_email`, `create_user`, and idempotent `upsert_user`. Every `SELECT` that returns `AuthUser` computes `(email_verified_at IS NOT NULL) AS email_verified`. Does **not** hash passwords (that is `authn`'s job) and does not know about JWT, cookies, or roles.

### authn

The authentication mechanism on top of `identity`. Provides `Authn::with_ttl`, `register`, `login`, `issue_access_token`, `issue_refresh_token`, `rotate_refresh_token`, `revoke_refresh_token`, `revoke_family(family_id, reason: Option<&str>)`, `verify_token`, and `hash_password`. Uses Argon2, `jsonwebtoken`, and `sha2` for opaque refresh- and email-verification tokens. Does **not** know about HTTP, cookies, Leptos, `lettre`, or `AuthorizationEngine`.

**Claims (Stage 3b).** Access JWTs carry `{ sub, iat, exp }` — no `email`. `verify_token` resolves the `AuthUser` (including the current `email_verified` flag and the current address) from `users` on every call, so verification state and email changes are immediately visible without waiting for the access token to expire.

**Refresh tokens (Stage 2b/2d).** `rotate_refresh_token` includes a **grace window** (`REFRESH_GRACE_SECONDS = 10`): an already-used token presented within the window returns `RefreshInvalid` and leaves the family intact (absorbs the parallel-request race); after the window it returns `RefreshReused` and revokes the family (`revoked_reason = "reuse_detected"`). Logout revokes the family with `revoked_reason = "logout"`. The `RevokeReason` enum (`Logout`, `ReuseDetected`, `PasswordReset`) mirrors the values; `PasswordReset` is reserved for Stage 3d.

**Email verification (Stage 3b).**

- `create_email_verification(user_id) -> Result<String, AuthnError>` — issues a fresh raw token (only `token_hash` is persisted) with `EMAIL_VERIFICATION_TTL_HOURS = 24`. Single-active: any unused token for the same user is deleted under a row lock; a partial unique index (`email_verifications_one_active_idx`) enforces the invariant at the DB level. Returns `AuthnError::AlreadyVerified` if `users.email_verified_at IS NOT NULL`.
- `verify_email(raw_token) -> Result<AuthUser, AuthnError>` — idempotent. Marks the token used, writes `users.email_verified_at = COALESCE(existing, now())` (preserves the original timestamp if already verified). Does **not** issue tokens or cookies; the caller may prompt the user to sign in.

### saas

Business logic, independent of UI framework. `SaasState { pool, authz, access }`, `SaasBuilder` (`with_authz`, `with_access`), `CoreError`, and services:

- `platform::create_tenant` — container only.
- `platform::provision_tenant(actor, name, owner, &owner_role_key)` — container + owner role creation (`access::create_owner_role`) + `grant_role` + `tenant_members` bookkeeping, in one transaction.
- `tenant::create_workspace(actor, tenant_id, name, owner, &owner_role_key)` — side effect preserved: the creator receives `owner_role_key` (usually `"owner"`).
- `tenant::list_memberships` / `workspace::list_memberships` — membership queries via `EXISTS` (multi-role).
- `workspace::create_document` / `list_documents` / `get_document`.
- `member::list(actor, MemberScope)`, `member::change_role`, `member::remove_role` — tenant/workspace member management.
  - `change_role` performs `assign(new)` before `revoke(old)`. On a partial failure (revoke fails after assign commits), the user is temporarily over-permissioned with both roles; this is recoverable idempotently by calling `change_role` again.
  - `change_role` and `remove_role` include an **owner guard**: removing the last holder of a `protected` role from a domain returns `Forbidden`. Non-protected roles have no last-holder guard. `assign_role` is never guarded.
- `invitation::create_invitation` — validates `role` against `access::get_role(domain, &RoleKey)`. For addressed invitations (`email IS NOT NULL`) the caller (e.g. `#[server] create_invitation` in the example) is responsible for delivering the link via `EmailSender::send_invitation` — `saas` does not know about SMTP.
- `invitation::accept_invitation` — by raw token. For **addressed** invitations (`invitation.email IS NOT NULL`):
  - `actor.email_verified == false` → `CoreError::EmailNotVerified` (verified-first: an unverified address is not proof of ownership).
  - Verified actor with a mismatched address → `CoreError::Forbidden` (case-insensitive comparison).
  - Both checks run after the `SELECT ... FOR UPDATE` lookup and before `used_count` is incremented; a rejected accept does not consume a use.
  - Link invitations (`email IS NULL`) skip both checks (Stage 2a behaviour). Accept writes `*_members` (multi-role PK) and grants the role via `authz.grant_role`.
- `invitation::revoke_invitation` / `list_invitations`.
- `saas::access::{create_role, update_role, delete_role, list_roles, list_permissions, assign_role, revoke_role, my_permissions}` — wrappers over `access` + `authz` + `*_members`.
  - `delete_role` performs the full cleanup in six retry-safe steps: `get_role_by_id` → `protected` check → `require` → `purge_role` (g+p) → `DELETE *_members` → `delete_role_by_id`. A partial failure at any step after `require` can be retried by calling `delete_role` again with the same `role_id`.
  - `my_permissions` returns the actor's effective `(resource, action)` pairs in a domain (batched UX helper for the client; does not replace `authz.require`).

Every service calls `state.authz.require(...)` before touching the database, **except** the following helpers (no `actor`, called after `require` in a caller):

- `invitation::accept_invitation` and `invitation::check_invitation` — authorized by the invitation token.
- `tenant::list_memberships` / `workspace::list_memberships` — membership queries.
- `access::get_role`, `access::get_role_by_id`, `access::delete_role_by_id`, `access::get_permissions_for_role`, `access::create_owner_role`, `access::list_permissions` — helpers, called after `require` in a caller.
- `saas::access::my_permissions` — read-only UX helper; any authenticated actor may discover their own effective permissions in a domain.

Does not know about Leptos, Axum, HTTP handlers, `casbin::Enforcer`, JWT, Argon2, `lettre`, or the `permissions`/`roles`/`role_permissions` tables (owned by `access`).

### db

PostgreSQL connection helper and migration runner. Migrations live in `crates/db/migrations/`:

- `20261026000001_init.sql` — `users`, `tenants`, `workspaces`, `tenant_members`, `workspace_members`, `documents`, `casbin_rule`.
- `20261101000001_saas_invitations.sql` — `invitations` (owner: `saas`).
- `20261102000001_authn_refresh_tokens.sql` — `refresh_tokens` (owner: `authn`).
- `20261103000001_access_rbac_init.sql` — `permissions`, `roles`, `role_permissions`; platform `owner` role with all permissions (owner: `access`).
- `20261103000002_saas_members_multi_role.sql` — `*_members` PK → `(scope_id, user_id, role)`.
- `20261104000001_access_members_list_permission.sql` — `(members, list)` reference row; top-up `roles.key='owner'` across all domains (owner: `access`).
- `20261105000001_authn_email_verify.sql` — `users.email_verified_at`; `email_verifications` table + single-active partial unique index; `refresh_tokens.revoked_reason` (owner: `authn`; Stage 3b).

Includes a `build.rs` with `cargo:rerun-if-changed=migrations` (and a `cargo:warning=` listing the migration set each time the build script runs).

### seed

Standalone binary for creating initial platform, tenant, workspace, user, role, and policy data. Bootstrap flow:

1. Grants `platform` `owner` to the platform admin via `authz.grant_role` with permissions from `access::get_permissions_for_role`.
2. Provisions the tenant (`saas::platform::provision_tenant`) and workspace (`saas::tenant::create_workspace`) with `RoleKey::parse("owner")?`.
3. Creates demo roles `editor`/`viewer` via `saas::access::create_role` and assigns them via `saas::access::assign_role`.
4. Marks each demo account verified (`users.email_verified_at = COALESCE(existing, now())`) — Stage 3b. Idempotent: the original timestamp is preserved on repeat runs.

Uses a single `PgPool` for `authz-casbin`, `access`, `saas`, and `authn` (`CasbinAuthz::from_pool`).

Idempotent: re-runs re-hash passwords, skip existing tenant/workspace, re-apply role assignments without duplicates, and do not move `email_verified_at`.

### examples/saas-leptos

The reference consumer application: Leptos UI, Axum server, `#[server]` wrappers, and `AppState`. `#[server]` functions are thin: `extract::CurrentUser::from_request().await?.require()?` resolves the user (HTTP 401 when missing), then the call delegates to `saas::*`, `saas::access::*`, `saas::member::*`, or `authn::*`; errors go through `error::core_error_to_server_fn` / `error::authn_error_to_server_fn` / `error::access_error_to_server_fn` / `error::rate_limited_error`, which map to HTTP 400/401/403/404/409/429/500. `AppState` holds `authn`, `saas` (which contains `access`), `leptos_options`, `email: Arc<dyn EmailSender>`, and `rate_limit: Arc<SimpleRateLimiter>`.

`src/extract.rs` holds `CurrentUser`; `src/error.rs` holds the error mapping; `src/middleware.rs` holds the auto-refresh middleware; `src/layout.rs` holds the global UI layout; `src/email.rs` holds `EmailResult` (visible in both `ssr` and `hydrate`), the SMTP transports (`SmtpEmailSender`, `NoopEmailSender` — `ssr` only), and the `EmailSender` trait with `send_verification` + `send_invitation` (Stage 3c); `src/rate_limit.rs` holds `SimpleRateLimiter` (in-memory, `ssr` only). `src/pages/{member,role,auth,invitation}.rs` hold the tenant/workspace member and role management, the auth + verification pages, and the invitation list / accept pages. This crate is **not** part of the library workspace.

`main.rs` builds two routers and merges them:

- `protected` — SSR pages (via `leptos_routes_with_context`) and Leptos `/_server/*` handlers; `auto_refresh` is attached via `.route_layer`.
- `public` — `file_and_error_handler` fallback (static files under `public/`, `/pkg/*`, `/assets/*`, and 404 responses); no middleware.

The split avoids running JWT verification, refresh-token rotation, and `Set-Cookie` on static assets.

`main.rs` also constructs the email transport from `SMTP_URL` (falls back to `NoopEmailSender` when unset) and an in-memory `SimpleRateLimiter` (3 per hour per email, enforced in `request_email_verification`). `BASE_URL` and `SMTP_FROM` have sensible defaults (`http://{BIND_ADDR}`, `noreply@example.test`).

Routes:

| Route | Component | Purpose |
|---|---|---|
| `/` | `pages::home::HomePage` | landing page, links |
| `/login` | `pages::auth::LoginPage` | sign in; consumes `return_url` after success (Stage 3a) |
| `/register` | `pages::auth::RegisterPage` | sign up; shows `EmailResult` (Sent / Failed+Resend / Disabled); consumes `return_url` |
| `/verify/:token` | `pages::auth::VerifyEmailPage` | email verification link target (Stage 3b); idempotent, no auto-login |
| `/platform` | `pages::platform::PlatformPage` | create a tenant (as platform owner) |
| `/tenants` | `pages::tenant::TenantListPage` | list of my tenants |
| `/tenants/:tenant_id` | `pages::tenant::TenantPage` | single tenant (create workspace) |
| `/tenants/:tenant_id/invitations` | `pages::invitation::TenantInvitationListPage` | tenant invitations (link + addressed) |
| `/tenants/:tenant_id/members` | `pages::member::TenantMemberListPage` | tenant members and role changes (selects, Stage 3a) |
| `/tenants/:tenant_id/roles` | `pages::role::TenantRoleListPage` | tenant roles (list/create/edit/delete) |
| `/tenants/:tenant_id/roles/:role_id` | `pages::role::TenantRoleFormPage` | edit tenant role (Stage 3a) |
| `/workspaces` | `pages::workspace::WorkspaceListPage` | list of my workspaces |
| `/workspaces/:workspace_id` | `pages::workspace::WorkspacePage` | single workspace (documents) |
| `/workspaces/:workspace_id/documents/:document_id` | `pages::workspace::DocumentPage` | single document view |
| `/workspaces/:workspace_id/invitations` | `pages::invitation::WorkspaceInvitationListPage` | workspace invitations (link + addressed) |
| `/workspaces/:workspace_id/members` | `pages::member::WorkspaceMemberListPage` | workspace members and role changes (selects, Stage 3a) |
| `/workspaces/:workspace_id/roles` | `pages::role::WorkspaceRoleListPage` | workspace roles (list/create/edit/delete) |
| `/workspaces/:workspace_id/roles/:role_id` | `pages::role::WorkspaceRoleFormPage` | edit workspace role (Stage 3a) |
| `/invitations/:token` | `pages::invitation::InvitationAcceptPage` | accept-flow; sets `return_url` for anonymous visitors (Stage 3a); verified-first + case-insensitive match for addressed invitations (Stage 3c) |

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

Authorization is always checked on the server before business logic executes. Exceptions: `accept_invitation`/`check_invitation` (by token — addressed invitations additionally enforce `email_verified` and a case-insensitive email match, Stage 3c), `*::list_memberships` (membership queries), and `access` helpers (`get_role`, `get_role_by_id`, `delete_role_by_id`, `get_permissions_for_role`, `list_permissions`, `create_owner_role`, `my_permissions`).

UI uses `saas::access::my_permissions` (batched per domain) to hide buttons and links; this is a UX convenience, not a security boundary — `authz.require` in `saas::*` remains authoritative.

## Development principles

- Keep authentication separate from authorization.
- Keep authorization separate from business logic.
- Never trust client-supplied tenant or workspace identifiers without server-side validation.
- Always scope database queries by tenant or workspace.
- Treat UI visibility as convenience, not as a security boundary.
- **Roles are data, not code.** No built-in role enums; `owner` is a row created by `access::create_owner_role`/the SQL migration; custom roles are created and edited by the domain owner.
- **Role edit is UI-editable for `name`, `description`, and `permissions`.** `key` is read-only after creation (ADR-0001: rename = delete + create). `protected`/`immutable` roles (`owner`) cannot be edited or deleted.
- `saas` and `authn` do not know about Leptos, Axum, or Casbin. `saas` does not know about `permissions`/`roles`/`role_permissions` — those belong to `access`. `authn` does not depend on `lettre` — SMTP transport lives in the example.
- Library crates do not depend on `examples/*`; each example has its own `Cargo.toml` and `Cargo.lock`.
- Server functions resolve the actor through `extract::CurrentUser`; a missing actor is HTTP 401.
- Library errors (`CoreError`, `AuthnError`, `IdentityError`, `AccessError`) are mapped to HTTP status codes in the example (`src/error.rs`); keep new variants covered by that mapping.
- Invitation raw tokens are returned once from `saas::invitation::create_invitation` and are never persisted; only `invitations.token_hash` (SHA-256) is stored. For **addressed** invitations the example immediately passes the raw token to `EmailSender::send_invitation`; for **link** invitations the raw token is shown once in the UI.
- Refresh raw tokens are returned once from `authn::issue_refresh_token` and are never persisted; only `refresh_tokens.token_hash` (SHA-256) is stored.
- **Email-verification raw tokens (Stage 3b)** are returned once from `authn::create_email_verification` and are never persisted; only `email_verifications.token_hash` (SHA-256) is stored. `NoopEmailSender` logs only the recipient and the fact of a skipped send — **never the token**.
- **Access JWT claims are `{ sub, iat, exp }` (Stage 3b).** The address and the `email_verified` flag are always resolved from `users` on `verify_token`.
- **Addressed invitations (Stage 3c).** `saas::invitation::accept_invitation` enforces verified-first (`CoreError::EmailNotVerified` if `!actor.email_verified`) then a case-insensitive email match (`CoreError::Forbidden` on mismatch) for `invitation.email IS NOT NULL`; link invitations (`email IS NULL`) skip both checks. Both checks run before any mutation (`used_count`, `*_members`, `casbin_rule`), so a rejected accept does not consume a use. `accept_invitation` is not a public bypass — it still authorizes by the invitation token, not by `authz.require`.
- **Email delivery failures are not registration failures.** `#[server] register` returns `(AuthUser, EmailResult)`; the account is created and cookies set regardless of the SMTP outcome. `RegisterPage` offers a **Resend** button when `Failed`.
- **`request_email_verification` is rate limited to 3/hour per email** via the process-local `SimpleRateLimiter`; the 4th call returns 429. Not distributed across instances (Stage 4+).
- **Post-auth return-URL preservation (Stage 3a):** anonymous visitors on `/invitations/:token` store the path in the `return_url` cookie (`auth::set_return_url`); `pages::auth::{LoginPage, RegisterPage}` call `auth::take_return_url` after successful sign-in and navigate there, falling back to `/` when the cookie is absent or unsafe. `is_safe_return_url` rejects `//`, `:` in the first segment, `;`/`,`/`"`/`\`/whitespace, and prefixes `/login`/`/register`. The cookie is `httpOnly`, `SameSite=Lax`, `Path=/`, session lifetime; `Secure` is deferred to Stage 4 (added to all auth cookies together).
- `authn::rotate_refresh_token` has a 10-second grace window for parallel refresh requests; a parallel request within the window returns `RefreshInvalid` and does not revoke the token family. Distributed single-flight for multi-instance deployments is not implemented.
- `saas::member::change_role` performs `assign` before `revoke`. A partial failure leaves the user over-permissioned with both roles (recoverable by retrying `change_role`); under-permissioning on partial failure is not possible.
- `saas::member::{change_role, remove_role}` include an owner guard: the last holder of a `protected` role cannot be removed from a domain. The guard reads `casbin_rule`, not `*_members`.
- `saas::access::delete_role` cleans up `casbin_rule` (g+p) and `*_members` in six retry-safe steps; a partial failure can be recovered by calling `delete_role` again.
- All library crates (`authz-casbin`, `access`, `saas`, `authn`) in the reference app and `seed` share a single `PgPool` (`CasbinAuthz::from_pool`).
- The reference app's `auto_refresh` middleware runs on the protected router (SSR + `/_server/*`); static files and 404 responses bypass it.
- **Hydrate host check.** `cargo check --features hydrate` runs on the host and catches type-level errors; it does **not** catch wasm-only errors. A full `cargo leptos watch` is part of the merge checklist (Stage 3a).

## Roadmap

- Stage 1 (done): typed error mapping to HTTP codes, `CurrentUser` extractor, mock `AuthorizationEngine` and `#[sqlx::test]` integration tests for `authn`, `saas`, and cross-tenant / cross-workspace access.
- Stage 1.5 (done): workspace `async-trait` dependency, cleanup, `.env.example` (EN), README `cargo test`.
- Stage 1.1 (done): `create_tenant` container only; `provision_tenant(actor, name, owner)` for explicit owner assignment; `create_workspace` side effect preserved.
- Stage 2a (done): invitations core.
- Stage 2b (done): refresh tokens with rotation + family revocation, auto-refresh middleware, logout with server-side invalidation, shorter access TTL, `access_token` + `refresh_token` cookies, global layout, document pages.
- Stage 2e (done): domain-ownership RBAC, `access` crate, `grant_role`/`revoke_role`, `*_members` multi-role PK, `seed` bootstrap via `saas::*`.
- Stage 2e.1 (done): cleanup — page naming convention (`EntityOperationPage`), EN comments, migration set sync, docs counters.
- Stage 2c (done): tenant and workspace member management, roles UI, UI gating via `saas::access::my_permissions`, Renew-demo removed.
- Stage 2d (done): casbin cleanup (`purge_role`, `delete_role_by_id`), single `PgPool` (`from_pool`), owner guard, refresh grace window, `.route_layer` split for auto-refresh.
- Stage 3.0 (done): ADRs 0002/0003/0004 (auth-scoping, cross-table transactions, audit log) — doc-only.
- Stage 3a (done): UX 2.5 — role edit (`RoleFormPage`, `update_role` UI, read-only `key`), member selects (`<select>` for user and role), "Invite instead" link, return-URL preservation across login/registration (`set_return_url` / `take_return_url` / `is_safe_return_url`).
- Stage 3b (done): email verification + claims cleanup. `users.email_verified_at`; `email_verifications` (single-active, 24h); `authn::{create_email_verification, verify_email}`; `AuthnError::AlreadyVerified`; `RevokeReason` (`logout`/`reuse_detected`/`password_reset`) + `refresh_tokens.revoked_reason`; claims cleanup (`-email, +iat`); `lettre` + Mailpit in the example; `SimpleRateLimiter` (3/hour per email); `EmailResult` on `RegisterPage`; `/verify/:token` page; demo accounts marked verified by `seed`.
- **Stage 3c (done): addressed invitations.** `saas::invitation::accept_invitation` enforces `actor.email_verified` (verified-first, `CoreError::EmailNotVerified`) then a case-insensitive email match (`CoreError::Forbidden`) for `invitation.email IS NOT NULL`; link invitations keep Stage 2a behaviour. `EmailSender::send_invitation` in the example; `who_am_i` returns `SessionUser { email, email_verified }`; `create_invitation` returns `(Invitation, String, Option<EmailResult>)` for addressed; UI branches for unverified (Resend) / mismatch (log in as) / match; `CoreError::EmailNotVerified` mapped to 403; 6 new `saas` integration tests (84 → 90).
- Stage 3d (next): password reset (`password_reset_tokens`, `users.password_changed_at`, `revoke_all_user_tokens("password_reset")` via `RevokeReason::PasswordReset` — already reserved; rate limit 5/hour per email).
- Stage 3e: audit log (`audit` + `audit-pg`, 21 events).
- Stage 3f: platform admin (`list_tenants`, `suspend_tenant`, `activate_tenant`, `resolve_active_tenant`, `ActiveTenant`, `TenantSuspended`); audit view.
- Stage 3g: `axum-minimal` (portability proof).
- Stage 3h: infra + minor (`has_policy` pre-check, `pg_advisory_xact_lock`, `my_permissions` cache, `casbin_rule` dedup).
- **Micro-PR (after 3d):** migrate from `docker-compose` (v1) to `docker compose` (v2 plugin) in README/`.env.example`/handoff; v2 does not emit the spurious `KeyError: 'id'` traceback from `log_printer` on `Ctrl+C` after `docker-compose up` in foreground.
- Stage 4: Dockerfile, CI (fmt/clippy/test/migration check), observability, backups, cookie `Secure`/`SameSite`, CSRF, rate limiting (incl. `/refresh`), optional RLS, E2E HTTP tests, iat-vs-`password_changed_at`, outbox, audit retention, distributed single-flight refresh, distributed rate limiter.

## License

See the `LICENSE` file in the root of the repository.
