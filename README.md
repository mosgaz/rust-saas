# Rust SAAS

**rust-saas** is a Rust library and reference application for building multi-tenant SaaS.

The library crates live in `crates/` (a Cargo workspace) and separate business logic, identity, authentication, and authorization from each other, so they can be reused in other applications through git dependencies. The `examples/saas-leptos` directory contains a reference consumer that combines them with an isomorphic Leptos frontend and an Axum-based backend. The `examples/axum-minimal` directory contains a second consumer on pure Axum, without Leptos — the portability proof from Stage 3g.

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
- **Password reset (Stage 3d): single-active 1-hour token, `authn::request_password_reset` returns `Ok(None)` for unknown emails (no enumeration signal), `authn::reset_password` is **one-shot** (a replayed token returns `TokenInvalid`). In one transaction it rewrites `password_hash` + bumps `password_changed_at`, expires every outstanding reset token for the user, and revokes **every** refresh-token family with `revoked_reason = "password_reset"`. `/forgot-password` (5/hour per email) and `/reset-password/:token` pages; no auto-login after reset.**
- **Addressed invitations (Stage 3c): `accept_invitation` requires a verified, matching email (`email_verified` first, then case-insensitive match); the invitation link is delivered via `EmailSender::send_invitation`, and the UI distinguishes `Sent` / `Failed` / `Disabled` (with a copy-link fallback). Link invitations (`email IS NULL`) keep Stage 2a behaviour.**
- **Audit log (Stage 3e): `audit` trait crate + `audit-pg` (`PgAuditLogger`); `Authn`/`AccessState`/`SaasState` inject `Arc<dyn AuditLogger>` via `with_audit`; 21 event types; sync after `COMMIT` in a separate transaction; `NoopAuditLogger` fallback for dev / tests / seed; failures are `tracing::warn!` and never fail the business operation.**
- **Platform admin (Stage 3f): `saas::platform::{list_tenants, suspend_tenant, activate_tenant}` gated by `(tenants, list)` / `(tenants, manage)` in `PLATFORM_DOMAIN`; `/platform` page creates tenants and toggles suspend/activate; `/platform/audit` renders the most recent `audit_log` rows (`(audit, read)`).**
- **Tenant suspension (Stage 3f): `saas::platform::resolve_active_tenant` + `ActiveTenant` + `CoreError::TenantSuspended`. Mutating `#[server]` calls (`create_workspace`, `create_document`, `create_role`, `update_role`, `delete_role`, `assign_member_role`, `remove_member_role`, `create_invitation`) resolve the tenant first; reads and cleanup (`list_*`, `get_*`, `my_permissions`, `revoke_invitation`) stay available on a suspended tenant. `suspend_tenant` / `activate_tenant` are idempotent and emit `tenant.suspended` / `tenant.activated` only on a transition.**
- **Client route guards (Stage 3f + follow-up): `examples/saas-leptos/src/guard.rs` — `RouteGuard` enum + monolithic `GuardRoute` + standalone `RequireAuth` / `RequirePermission` / `RequireAnyPermission`. UX-only, not a security boundary; the policy lives next to `<Route>` in `lib.rs`, pages do not know about guards. SSR-correct guard and server-side middleware — Stage 4.**
- **Second consumer (Stage 3g): `examples/axum-minimal` — pure Axum, no Leptos. Portability proof: the same `saas::*` / `authn::*` / `audit::*` public contracts and the same `resolve_active_tenant` calls in mutation handlers as `saas-leptos`. `CurrentUser` implemented as `axum::extract::FromRequestParts` — a deliberate deviation from ADR-0002 rev.2 §3.8, recorded in `handoff §16`. 11 endpoints (`/auth/{register,login,logout,refresh}`, `/tenants`, `/workspaces`, `/documents`, `/audit`); `NoopEmailSender` (no SMTP transport).**
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
- Reproducible local development with Docker Compose v2 (PostgreSQL + Mailpit)
- Database seed command for bootstrap data
- Tailwind CSS v4 styling

## Architecture

The repository is split into two layers:

```text
crates/                  (library — the Cargo workspace)
├── domain/             Shared DTOs (Tenant, Workspace, Document, AuthUser, Invitation, Member),
│                       InvitationTarget, domain helpers, PLATFORM_DOMAIN;
│                       AuthUser.email_verified (derived from users.email_verified_at);
│                       TenantStatus (Active / Suspended)
├── authz/              AuthorizationEngine trait
│                       (can / require / grant_role / revoke_role / has_role /
│                        count_users_with_role / purge_role) + AuthzError
├── authz-casbin/       CasbinAuthz: canonical trait implementation
├── audit/              AuditLogger trait, AuditEvent DTO, NoopAuditLogger, 21 event constants
├── audit-pg/           PgAuditLogger: PostgreSQL implementation (audit_log table)
├── access/             Sole owner of `permissions`, `roles`, `role_permissions`:
│                       Role, Permission, RoleKey, AccessState, AccessError, role CRUD,
│                       create_owner_role, get_role_by_id, delete_role_by_id,
│                       list_permissions, get_permissions_for_role
├── identity/           Sole owner of `users`: AuthUser, UserRecord, validation, CRUD;
│                       UserRecord.email_verified_at (source of truth for the derived flag);
│                       UserRecord.password_changed_at (Stage 3d);
│                       update_password_tx (Stage 3d)
├── authn/              Argon2, JWT access tokens, opaque refresh tokens, rotation
│                       with grace window; email verification (single-active, 24h);
│                       password reset (single-active, 1h, one-shot, revoke all families);
│                       RevokeReason (logout / reuse_detected / password_reset);
│                       audit emission (8 events)
├── saas/               Business logic: platform (incl. suspend/activate + resolve_active_tenant),
│                       tenant, workspace, invitation, member, access (wrappers, incl.
│                       my_permissions); audit emission
├── db/                 PostgreSQL connection and migrations
└── seed/               Bootstrap data and demo accounts (all email-verified)

examples/                (reference consumers — outside the workspace)
├── saas-leptos/        Leptos SSR + Axum + #[server] + middleware + cookies
│                       + SMTP transport (lettre, 10s timeout) + in-memory rate limiter
│                       + forgot-password / reset-password pages
│                       + /platform + /platform/audit (platform admin)
│                       + PgAuditLogger wired through Authn / AccessState / SaasBuilder
│                       + client route guards (Stage 3f + follow-up)
└── axum-minimal/       Stage 3g: pure Axum, no Leptos — portability proof
                        + CurrentUser via axum::extract::FromRequestParts
                        + 11 endpoints: /auth/{register,login,logout,refresh},
                          GET|POST /tenants, GET|POST /workspaces,
                          GET|POST /documents, GET /audit
                        + auto_refresh on the protected router (public routes bypass it)
                        + NoopEmailSender (no SMTP transport)
                        + same resolve_active_tenant in mutation handlers as saas-leptos
```

`examples/*` is listed in `workspace.exclude`; each example has its own `Cargo.toml` and `Cargo.lock`, and depends on the library crates via path dependencies pointing at `../../crates/*`.

The application separates five concerns:

| Concern | Responsibility | Crate |
|---|---|---|
| Identity | Who you are as an entity (`users` table, `AuthUser`) | `identity` |
| Authentication | How you proved you are who you are (Argon2, JWT, refresh tokens, email verification, password reset) | `authn` |
| Authorization | What you are allowed to do (`AuthorizationEngine`) | `authz` / `authz-casbin` |
| Roles & permissions | Who has which rights (`roles`, `permissions`, `role_permissions`) | `access` |
| Data isolation | Which rows you can see (SQL filters by tenant/workspace) | `saas` |

Plus a cross-cutting concern:

| Concern | Responsibility | Crate |
|---|---|---|
| Audit | Who did what, when (`audit_log`) | `audit` / `audit-pg` |

`Casbin does not replace SQL isolation. JWT does not replace Casbin. UI does not replace backend authorization. Roles are data, not code. Audit is best-effort, not a security boundary.`

### Crate dependency graph

```text
saas-leptos  -> domain, authz, authz-casbin, access, identity, authn, saas, db,
                audit, audit-pg                                              (example)
axum-minimal -> domain, authz, authz-casbin, access, identity, authn, saas, db,
                audit, audit-pg                                              (example)
seed         -> authz, authz-casbin, access, authn, identity, db, domain, saas,
                audit, audit-pg
saas         -> authz (trait), access, identity, domain, audit, sqlx, sha2
access       -> authz (trait), domain, audit, sqlx, uuid, serde, thiserror
authn        -> identity, domain, audit, sqlx, argon2, jsonwebtoken, sha2
identity     -> domain, sqlx
authz-casbin -> authz (trait), casbin, sqlx, sqlx-adapter
authz        -> uuid, thiserror, async-trait
audit        -> serde, uuid, thiserror, async-trait, chrono, serde_json
audit-pg     -> audit, sqlx, uuid, thiserror, async-trait
db           -> sqlx, anyhow
domain       -> serde, uuid, chrono; sqlx (optional, ssr only);
                `test-support` feature (test-only AuthUser constructors)
```

Forbidden edges:

- `saas` does not depend on Leptos, Axum, `casbin::Enforcer`, JWT, or Argon2. `sha2` is used only for `invitation::hash_token`.
- `access` does not depend on business tables (`tenants`, `workspaces`, `documents`, `invitations`, `*_members`), HTTP, UI, JWT, or Argon2.
- `authn` does not depend on `authz`. `sha2` is used only for refresh-, email-verification, and password-reset `token_hash`. `lettre` is **not** a dependency of `authn`; SMTP delivery lives in the example.
- `identity` does not depend on `authn` or `authz`.
- `authz` does not depend on Casbin, SQL, HTTP, Leptos, or JWT. It does not know about specific roles.
- `authz-casbin` does not depend on business tables (`users`, `tenants`, `invitations`, `refresh_tokens`, `password_reset_tokens`, `roles`, `permissions`). It uses raw SQL only against its own `casbin_rule` table (`has_role`, `count_users_with_role`, `purge_role`).
- **`audit` does not depend on `sqlx`, `SaasState`, `Authn`, `AccessState`, `identity`, or any business crate.** Trait-only, symmetric to `authz`. Only `serde`, `uuid`, `thiserror`, `async-trait`, `chrono`, `serde_json`.
- **`audit-pg` depends on `audit` and owns the `audit_log` table.** The only writer. Symmetric to `authz-casbin` / `casbin_rule`.
- The examples (`examples/saas-leptos`, `examples/axum-minimal`) do not call `casbin_rule` or `audit_log` directly and do not call `authz.require` — only `saas::*`, `saas::access::*`, `saas::member::*`, and `authn::*`. The `/platform/audit` read-only helper does not go through `saas::*` for historical reasons (the `AuditLogger` trait is a single-method write interface; `PgAuditLogger::list` is a per-implementation read helper), but it does enforce `(audit, read)` via `saas::access::my_permissions`.
- Library crates do not depend on `examples/*`.

### Multi-tenancy model

```text
platform
└── tenant
    ├── workspace
    └── workspace
```

- A **tenant** represents a customer organization. It has a `status` (`active` or `suspended`).
- A **workspace** represents a working area inside a tenant, such as a team, department, or project.
- A **user** is a global identity and can participate in multiple tenants or workspaces.
- A **workspace** contains business resources such as documents.
- An **invitation** targets exactly one tenant or one workspace (`CHECK ((tenant_id IS NULL) <> (workspace_id IS NULL))`). `email IS NULL` is a reusable link; `email IS NOT NULL` is an addressed invitation (Stage 3c).
- **Suspended tenants** (Stage 3f): mutating `#[server]` calls that go through `saas::platform::resolve_active_tenant` return `TenantSuspended` (HTTP 403); reads and cleanup (`list_*`, `get_*`, `my_permissions`, `revoke_invitation`) keep working. See the *Tenant lifecycle* section below.

### Authorization domains

Casbin policies are scoped by domain:

| Domain | Purpose |
|---|---|
| `platform` | Platform-level administration (list tenants, suspend/activate, read audit) |
| `tenant:{tenant_id}` | Tenant-level operations |
| `workspace:{workspace_id}` | Workspace-level operations |

### Domain-ownership RBAC

- A **role** is a named set of permissions in a **domain** (not in a tenant).
- A **permission** is a `(resource, action)` pair from the `permissions` reference table.
- The **owner** role in a domain has **all permissions** from the reference table, is `protected=true` and `immutable=true`. It is created by `access::create_owner_role(domain)` (idempotent) from `saas::platform::provision_tenant` and `saas::tenant::create_workspace`, and via the bootstrap SQL migration for the `platform` domain.
- The owner of a domain creates custom roles and assigns them to users of that domain (`saas::access::create_role` / `assign_role` / `update_role`). Roles can be edited (`name`, `description`, `permissions`) and deleted; `key` is immutable (`update_role` never changes it; rename = delete + create, ADR-0001).
- Users can hold **multiple roles** in the same domain. `tenant_members` and `workspace_members` use `PRIMARY KEY (scope_id, user_id, role)`.
- The **owner guard** prevents removing the last holder of a `protected` role from a domain (`saas::member::{change_role, remove_role}` return `Forbidden`). Non-protected roles have no last-holder guard. The guard reads `casbin_rule` (the source of truth for authorization), not `*_members`.
- **Platform admin** (Stage 3f) is a user holding `platform` `owner` (or any role that grants the platform-scoped permissions). It is **not** a superuser inside tenants/workspaces: it can list/suspend/activate tenants and read the platform audit log, but it does not gain any role in a target tenant.

Example permissions and demo roles:

| Permission `(resource, action)` | Domain | Used by |
|---|---|---|
| `(tenants, create)` | `platform` | `saas::platform::{create_tenant, provision_tenant}` |
| `(tenants, list)` | `platform` | `saas::platform::list_tenants` (Stage 3f) |
| `(tenants, manage)` | `platform` | `saas::platform::{suspend_tenant, activate_tenant}` (Stage 3f) |
| `(audit, read)` | `platform` | `/platform/audit` view (Stage 3f) |
| `(workspaces, create)` | `tenant:{id}` | `saas::tenant::create_workspace` |
| `(documents, read/write)` | `workspace:{id}` | `saas::workspace::*` |
| `(members, list/manage)` | `tenant:{id}`, `workspace:{id}` | `saas::member::*` |
| `(invitations, create/revoke/list)` | `tenant:{id}`, `workspace:{id}` | `saas::invitation::*` |
| `(roles, create/manage/delete/list/grant)` | `tenant:{id}`, `workspace:{id}` | `saas::access::*` |

| Role | Domain | Permissions |
|---|---|---|
| `owner` | `platform` | all from `permissions` (bootstrap) |
| `owner` | `tenant:{id}` | all from `permissions` |
| `owner` | `workspace:{id}` | all from `permissions` |
| `editor` | `workspace:{id}` | `documents:read/write` (demo, created by seed) |
| `viewer` | `workspace:{id}` | `documents:read` (demo, created by seed) |

### Tenant lifecycle

- `tenants.status` is `active` (default) or `suspended`.
- **Suspend/activate** are admin actions: `saas::platform::{suspend_tenant, activate_tenant}` require `(tenants, manage)` in `PLATFORM_DOMAIN`. Both are **idempotent**: `UPDATE … WHERE status = <expected> RETURNING *` emits `tenant.suspended` / `tenant.activated` only when the update actually matched a row. A second call returns the row unchanged with no audit emission.
- **Resolution.** `saas::platform::resolve_active_tenant(state, actor, tenant_id)` returns `ActiveTenant` only when (1) the actor is a member of the tenant (`EXISTS tenant_members`) and (2) `status = 'active'`. Non-member → `Forbidden`; suspended → `TenantSuspended`; missing → `NotFound`.
- **Mutation paths.** The example's `#[server]` mutation functions (and `axum-minimal`'s handler functions) call `resolve_active_tenant` **explicitly** before delegating to `saas::*` (`create_workspace`, `create_document`, `create_role`, `update_role`, `delete_role`, `assign_member_role`, `remove_member_role`, `create_invitation`). `saas::invitation::{create_invitation, accept_invitation}` also check the tenant status inside the service (defense in depth). Reads and cleanup (`list_*`, `get_*`, `my_permissions`, `revoke_invitation`, `check_invitation`) do **not** resolve.
- **Platform admin is not a bypass.** A platform admin who is not a member of the target tenant cannot resolve it — `resolve_active_tenant` returns `Forbidden`. An escape hatch (`_or_platform_admin`) is deliberately deferred to Stage 4.

## Technology stack

| Layer | Technology |
|---|---|
| Language | Rust |
| UI | Leptos (in the reference example) |
| Backend | Axum (in the reference example and in `axum-minimal`) |
| Database | PostgreSQL 16 |
| Database access | SQLx |
| Authorization | Casbin (via `authz-casbin`) |
| Authentication | Argon2, JSON Web Tokens (access), opaque tokens (refresh, email-verification, password-reset) |
| Audit | `audit` (trait-only) + `audit-pg` (`audit_log`) |
| Email verification | SHA-256 (`sha2`) over a random raw token; raw token not persisted; 24-hour TTL, single-active per user |
| Password reset | SHA-256 (`sha2`) over a random raw token; raw token not persisted; 1-hour TTL, single-active per user, one-shot |
| Email delivery | `lettre` (async SMTP, tokio1-rustls, 10s timeout) in `saas-leptos`; `NoopEmailSender` in `axum-minimal`; Mailpit for local dev |
| Rate limiting | In-memory sliding-window (`SimpleRateLimiter` in both examples; not distributed) |
| Invitation tokens | SHA-256 (`sha2`) over a random raw token; raw token not persisted |
| Refresh tokens | SHA-256 (`sha2`) over a random raw token; raw token not persisted |
| Styling | Tailwind CSS v4 (in `saas-leptos`) |
| Local infrastructure | Docker Compose v2 — PostgreSQL + Mailpit |
| Logging | `tracing` + `tracing-subscriber` (`RUST_LOG` env-filter) |
| Testing | `cargo test`; `#[sqlx::test]` for per-test isolated databases |

## Getting started

### Prerequisites

- Rust
- `wasm32-unknown-unknown` target
- `cargo-leptos`
- Docker with the Compose **v2** plugin (verify with `docker compose version` — it should print `Docker Compose version v2.x.y`; the legacy `docker-compose` v1 binary is not supported)

Install the WebAssembly target and Leptos CLI:

```bash
rustup target add wasm32-unknown-unknown
cargo install --locked cargo-leptos
```

### Start PostgreSQL and Mailpit

Run from the repository root:

```bash
docker compose up -d
docker compose ps   # both services: postgres Up (healthy); mailpit Up
```

Mailpit is only needed for the email-verification flow (Stage 3b), addressed invitations (Stage 3c), and password reset (Stage 3d). Open `http://localhost:8025` to read the inbox. Without Mailpit, the app falls back to `NoopEmailSender`: registration still succeeds, but the UI reports "email delivery not configured", and no verification, invitation, or reset link is delivered.

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

- `.env` lives in the **repository root** and is discovered by the seed binary, both examples, and `#[sqlx::test]`.
- `.env` must be LF, not CRLF.
- Do not put `LEPTOS_*` variables into `.env`.
- `DATABASE_URL` is used in three places: by the running application, by `seed`, and by `cargo test`. The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege for `#[sqlx::test]`.
- `SMTP_URL` is read only by `examples/saas-leptos`. `axum-minimal` uses `NoopEmailSender` unconditionally. The library (`authn`) does not depend on `lettre`.

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

The command applies database migrations (including `20261107000001_audit_log.sql` and `20261108000001_platform_admin_permissions.sql`) and creates initial platform, tenant, workspace, user, role, authorization, and audit data. It is idempotent: re-running it re-hashes passwords, re-applies roles/policies, and marks demo accounts verified without moving their original `email_verified_at`. Seed does not touch `password_changed_at`.

Seed flow:

1. Grants `platform` `owner` role to the platform admin via `authz.grant_role` (permissions from `access::get_permissions_for_role`). Bootstrap-only: no `member.role_assigned` audit event.
2. Provisions the tenant via `saas::platform::provision_tenant(..., &RoleKey::parse("owner")?)` — emits `tenant.created`.
3. Creates the workspace via `saas::tenant::create_workspace(..., &RoleKey::parse("owner")?)` — emits `workspace.created`.
4. Creates demo roles `editor`/`viewer` via `saas::access::create_role` — each emits `role.created`; then assigns them via `saas::access::assign_role` — each emits `member.role_assigned`.
5. Marks every demo account verified (`users.email_verified_at = COALESCE(existing, now())`).

Bootstrap audit events (visible in `audit_log` after seed): `tenant.created`, `workspace.created`, `role.created` × 2, `member.role_assigned` × 2.

**Existing database.** `20261107000001_audit_log.sql` adds a new table (`audit_log`), `20261108000001_platform_admin_permissions.sql` adds new `(resource, action)` rows and top-ups the platform owner — no backfill. If your DB predates the earlier migrations, `docker compose down -v` + `cargo run -p seed` is the recommended path.

### Run the reference application (`saas-leptos`)

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

1. `/register` — create a new account. After submit, the page shows "Account created for …" plus the verification-email outcome.
2. Open the verification link from Mailpit → `/verify/:token` shows "Email verified: …". Re-opening the same link is safe (idempotent).
3. `/login` with one of the demo accounts (or your freshly-verified one).
4. `/platform` — as platform owner, create a tenant and see the list of every tenant.
5. **Platform admin + tenant suspension (Stage 3f).**
   - As `platform-admin@example.test`, on `/platform` click **Suspend** next to Acme.
   - **In a second browser profile / incognito window** sign in as `owner@acme.test`. `/tenants` still lists Acme (with `status: Suspended`); `/tenants/<acme_id>` renders, but "Create workspace" (and any other mutation) returns HTTP 403 `tenant is suspended`. Same for `/tenants/<id>/roles`, `/tenants/<id>/members`, `/workspaces/<id>` (create document), and `/tenants/<id>/invitations` (create invitation). **Reads keep working.**
   - Back as platform admin, click **Activate** on `/platform`. `owner@acme.test` can mutate again.
   - Inspect `audit_log` (`psql … -c "select event_type, actor_email from audit_log where target_type = 'tenant' order by occurred_at"`) — you should see exactly one `tenant.suspended` and one `tenant.activated` per toggle (no duplicates on a re-click of an already-suspended / already-active tenant).
6. `/platform/audit` — as platform admin, lists the most recent audit rows (default limit 100, clamped server-side to 200). Non-platform-admins get HTTP 403.
7. `/tenants` — list of tenants you're a member of.
8. `/tenants/<tenant_id>` — as tenant owner, create a workspace.
9. `/tenants/<tenant_id>/members` — see members; assign/remove roles via selects.
10. `/tenants/<tenant_id>/roles` — list, create, edit, delete custom roles.
11. `/workspaces` — list of workspaces you're a member of.
12. `/workspaces/<workspace_id>` — as editor, create documents.
13. `/workspaces/<workspace_id>/members` — workspace member list.
14. `/workspaces/<workspace_id>/roles` — workspace roles.
15. `/tenants/<tenant_id>/invitations` — create a tenant invitation (link or addressed).
16. Link invitation flow: paste `/invitations/<64 hex>` in another session → `return_url` cookie → login → accept.
17. Addressed invitation flow (Stage 3c): verified-first + case-insensitive match; `EmailNotVerified` / `Forbidden`.
18. **Forgot password (Stage 3d).** `/login` → "Forgot password?" → `/forgot-password`. Generic confirmation for known/unknown emails; rate-limited 5/hour.
19. **Reset password (Stage 3d).** `/reset-password/:token` → new password. All existing refresh tokens are revoked; one-shot (replay → `invalid or expired`).
20. **Audit log.** After any of the flows above (register, login, logout, verify, password reset, invite, accept, role change, tenant/workspace provisioning, tenant suspend/activate), the corresponding `audit_log` rows are visible via `psql ... -c "select event_type, actor_email, target_type from audit_log order by occurred_at"` or via `/platform/audit`.
21. **Wait 15+ minutes** — auto-refresh rotates the refresh token.
22. Rate limits: `request_email_verification` — 3/hour per email; `request_password_reset` — 5/hour per email.

### Run the `axum-minimal` example (Stage 3g)

The second example is also outside the workspace and has its own manifest. It uses the same database and seed data as `saas-leptos`, so run `cargo run -p seed` once (from the repository root) before starting it.

```bash
cargo run --manifest-path examples/axum-minimal/Cargo.toml
```

It listens on `BIND_ADDR` (default `127.0.0.1:3395`). If `saas-leptos` is already using that port, set `BIND_ADDR=127.0.0.1:3397` (or similar) in `.env`.

Smoke checklist (curl, from the repository root). The example returns JSON, not HTML, so it is easy to script:

```bash
# register (rate-limited 3/h per email; use a fresh address each time)
curl -X POST http://127.0.0.1:3395/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke-1@example.test","password":"Smoke123!"}' \
  -c /tmp/axum-minimal-cookies.txt

# login as a seed demo account
curl -X POST http://127.0.0.1:3395/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"platform-admin@example.test","password":"PlatformAdmin123!"}' \
  -c /tmp/axum-minimal-cookies.txt

# list tenants (empty for platform admin — not a tenant member)
curl -X GET http://127.0.0.1:3395/tenants -b /tmp/axum-minimal-cookies.txt

# create a tenant (the caller becomes its owner)
curl -X POST http://127.0.0.1:3395/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"Axum Smoketest"}' \
  -b /tmp/axum-minimal-cookies.txt

# list workspaces, audit
curl -X GET http://127.0.0.1:3395/workspaces -b /tmp/axum-minimal-cookies.txt
curl -X GET 'http://127.0.0.1:3395/audit?limit=10' -b /tmp/axum-minimal-cookies.txt

# negative checks:
# - POST /workspaces on a suspended tenant → 403 {"error":"tenant is suspended"}
# - GET /audit as a non-platform-admin → 403 {"error":"forbidden"}
# - GET /tenants anonymously → 401 {"error":"unauthorized"}
```

Expected behaviours:

- Anonymous `GET /tenants` → `401 {"error":"unauthorized"}` (from `CurrentUser::require`).
- `platform-admin@example.test` `POST /workspaces` on a suspended tenant → `403 {"error":"tenant is suspended"}` (from `resolve_active_tenant`).
- `platform-admin@example.test` `GET /audit` → `200` + up to 10 rows (the platform owner has `(audit, read)`).
- `owner@acme.test` `GET /audit` → `403 {"error":"forbidden"}` (no `(audit, read)`).
- Anonymous `POST /auth/register` four times in an hour with the same email → the 4th call is `429`, with `Retry-After` header and `{"error":"rate limited; try again in <n>s","retry_after_secs":<n>}`.

The `axum-minimal` cookie flow (`access_token` / `refresh_token`) and the auto-refresh behaviour are identical to `saas-leptos` (same library calls, same middleware contract); only the transport (JSON vs `#[server]` RPC) and the absence of Leptos differ.

### Checking the build

From the repository root:

```bash
clear && cargo test && cargo check && cargo check -p seed && cargo check --manifest-path examples/saas-leptos/Cargo.toml --features ssr && cargo check --manifest-path examples/saas-leptos/Cargo.toml && cargo check --manifest-path examples/axum-minimal/Cargo.toml
```

### Running tests

From the repository root:

```bash
cargo test
```

**124 tests, all green** (code — source of truth; `cargo test` output wins over this estimate if they differ). Distribution (rough): `authn` 13+37 = 50; `saas` 11+41 = 52; `access` 0+6 = 6; `authz-casbin` 0+9 = 9; `audit` 3+0 = 3; `audit-pg` 0+4 = 4. Stage 3f added 8 integration tests in `saas::tests::integration` (resolve_active_tenant × 3, list_tenants, suspend_tenant, activate_tenant, accept_invitation_on_suspended, create_invitation_on_suspended).

Stage 3g (`axum-minimal`) does **not** change the library test counter — `crates/*` is untouched (0 migrations, 0 breaking changes, 0 new library tests). The example ships no `tests/` directory (binary-only crate; the plan marks example smoke tests optional). Its smoke coverage is the curl checklist above, which exercises the same `saas::*` / `authn::*` calls as `saas-leptos`.

Unit tests live inline (`#[cfg(test)] mod tests`) in `crates/authn`, `crates/access`, `crates/saas`, and `crates/audit`. Integration tests live in `crates/*/tests/` and use `#[sqlx::test]`:

- Each test gets its own isolated database on the server pointed to by `DATABASE_URL`; `crates/db/migrations` are applied automatically; the database is dropped when the test finishes.
- No manual `createdb` is required.
- The user in `DATABASE_URL` must have the `CREATE DATABASE` privilege.
- Tests can run in parallel; isolation is per-database.

The reference examples have small unit-test modules too (`rate_limit.rs` in both; run with `cargo test --manifest-path examples/saas-leptos/Cargo.toml --features ssr rate_limit` or `cargo test --manifest-path examples/axum-minimal/Cargo.toml rate_limit`).

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
│   ├── audit/
│   ├── audit-pg/
│   ├── access/
│   ├── identity/
│   ├── authn/
│   ├── saas/
│   │   ├── src/
│   │   │   ├── lib.rs           # CoreError, SaasState, SaasBuilder, tenant / workspace modules
│   │   │   ├── platform.rs      # Stage 3f: create_tenant, provision_tenant,
│   │   │   │                    # list_tenants, suspend_tenant, activate_tenant,
│   │   │   │                    # resolve_active_tenant, ActiveTenant
│   │   │   ├── access.rs
│   │   │   ├── invitation.rs
│   │   │   └── member.rs
│   │   └── tests/integration.rs
│   ├── db/
│   │   └── migrations/
│   │       ├── 20261026000001_init.sql
│   │       ├── 20261101000001_saas_invitations.sql
│   │       ├── 20261102000001_authn_refresh_tokens.sql
│   │       ├── 20261103000001_access_rbac_init.sql
│   │       ├── 20261103000002_saas_members_multi_role.sql
│   │       ├── 20261104000001_access_members_list_permission.sql
│   │       ├── 20261105000001_authn_email_verify.sql
│   │       ├── 20261106000001_authn_password_reset.sql
│   │       ├── 20261107000001_audit_log.sql
│   │       └── 20261108000001_platform_admin_permissions.sql
│   └── seed/
└── examples/
    ├── saas-leptos/
    │   ├── Cargo.toml
    │   └── src/
    │       ├── auth.rs
    │       ├── email.rs
    │       ├── rate_limit.rs
    │       ├── guard.rs
    │       ├── pages/
    │       │   ├── platform.rs
    │       │   └── ...
    │       └── ...
    └── axum-minimal/          # Stage 3g: pure Axum, no Leptos
        ├── Cargo.toml
        └── src/
            ├── main.rs        # entry point, router, AppState wiring
            ├── state.rs       # AppState { authn, saas, email, rate_limit }
            ├── error.rs       # AppError + IntoResponse (HTTP status mapping)
            ├── extract.rs     # CurrentUser via axum::extract::FromRequestParts
            ├── middleware.rs  # auto_refresh (protected router)
            ├── auth.rs        # register / login / logout / refresh handlers
            ├── tenant.rs      # list_my_tenants / create_tenant
            ├── workspace.rs   # list/create workspaces + documents (resolve)
            ├── audit.rs       # GET /audit (audit, read)
            ├── email.rs       # EmailSender trait + NoopEmailSender
            └── rate_limit.rs  # SimpleRateLimiter (in-memory, per-process)
```

### domain

Shared DTOs (`Tenant`, `Workspace`, `Document`, `AuthUser`, `Invitation`, `Member`), the `InvitationTarget` enum (`Tenant(Uuid) | Workspace(Uuid)`), the `TenantStatus` enum (`Active | Suspended`, Stage 3f), and authorization domain helpers (`PLATFORM_DOMAIN`, `tenant_domain`, `workspace_domain`). No SQL queries, no logic — just types. `sqlx::FromRow` / `sqlx::Type` derives are gated behind the `ssr` feature.

`AuthUser.email_verified: bool` is a **derived** boolean (`users.email_verified_at IS NOT NULL`), computed in every SELECT by `identity`. The timestamp itself is internal to `identity`/`authn`.

The `test-support` feature exposes `AuthUser::test_verified()` / `AuthUser::test_unverified()`; enabled only from `[dev-dependencies]` of crates with tests, never in production builds.

### authz

The `AuthorizationEngine` trait — seven methods: `can`, `require`, `grant_role`, `revoke_role`, `has_role`, `count_users_with_role`, `purge_role` — and `AuthzError`. Trait-only: no Casbin, no SQL, no HTTP, no specific roles.

### authz-casbin

`CasbinAuthz` — the canonical implementation of `AuthorizationEngine` on top of Casbin and `sqlx-adapter`. Two constructors: `CasbinAuthz::new(&database_url)` (own pool) and `CasbinAuthz::from_pool(PgPool)` (recommended — single pool per process). Uses raw SQL only against its own `casbin_rule` table (`has_role`, `count_users_with_role`, `purge_role`).

### audit (Stage 3e)

Trait-only `AuditLogger` (ADR-0004 §2.1) — symmetric to `authz`:

- `AuditEvent { event_type, actor_id, actor_email, target_type, target_id, metadata }` — `occurred_at` and `id` are DB-generated (`audit-pg`).
- `AuditLogger::log(&AuditEvent) -> Result<(), AuditError>`.
- `NoopAuditLogger` — always available (no feature flag); used as the default in `Authn::new` / `AccessState::new` / `SaasBuilder::build`.
- `events` module — 21 constants (`user.registered`, `tenant.created`, `tenant.suspended`, `tenant.activated`, `workspace.created`, `member.role_assigned`, `role.created`, …). All 21 are emitted by Stage 3f.

Does not depend on `sqlx`, `SaasState`, `Authn`, `AccessState`, or any business crate.

### audit-pg (Stage 3e)

`PgAuditLogger::from_pool(PgPool) -> Self`. Implements `AuditLogger` with a single `INSERT INTO audit_log (...)` per call. Owns the `audit_log` table (sole writer). No attempt to make the audit write transactional with the caller's mutation (ADR-0004 §2.4 — that would extend ADR-0003's A-lite to audit).

**Stage 3f** adds `PgAuditLogger::list(&self, limit: i64) -> Result<Vec<AuditRow>, AuditError>` and the `AuditRow` struct (DB-generated `id` / `occurred_at` + the DTO fields), used by the `/platform/audit` view. `list` is a read-only helper — it is not part of the `AuditLogger` trait (the trait is a single-method write interface; reads are implementation-specific).

### access

The sole owner of the `permissions`, `roles`, and `role_permissions` tables.

- DTOs: `Role`, `Permission`, `RoleKey`.
- `AccessState { pool, authz, audit }`, `AccessError`.
- `AccessState::with_audit(audit)` — builder-style; `new` is not broken.
- Services: `create_role` (emits `role.created`), `update_role` (emits `role.updated`), `delete_role` (does **not** emit — decision A: canonical point is `saas::access::delete_role`), `list_roles`, `get_role`, `get_role_by_id`, `delete_role_by_id`, `get_permissions_for_role`, `list_permissions`, `create_owner_role` (silent — provisioning side-effect).

### identity

The sole owner of the `users` table. Provides `AuthUser`, `UserRecord` (including `password_hash`, `email_verified_at`, `password_changed_at`; never leaves this crate's boundary), validation, CRUD, idempotent `upsert_user`, and `update_password_tx` (Stage 3d). Every `SELECT` that returns `AuthUser` computes `(email_verified_at IS NOT NULL) AS email_verified`.

### authn

Authentication mechanism on top of `identity`.

- `Authn::new` / `with_ttl` — default `NoopAuditLogger`.
- `Authn::with_audit(Arc<dyn AuditLogger>)` — builder-style (Stage 3e).
- Methods: `register`, `login`, `issue_access_token`, `issue_refresh_token`, `rotate_refresh_token`, `revoke_refresh_token`, `revoke_family`, `revoke_all_user_tokens`, `verify_token`, `create_email_verification`, `verify_email`, `request_password_reset`, `reset_password`, `hash_password`.
- Emits 8 events: `user.registered`, `user.login_succeeded`, `user.login_failed`, `user.logout`, `user.refresh_reused`, `user.email_verified`, `user.password_reset_requested`, `user.password_reset_completed`. A failed audit write is `tracing::warn!` (ADR-0004 §2.4) and does not fail the business operation.
- `login_failed` is emitted for **both** `InvalidCredentials` paths (wrong password, unknown email) with `actor_id = NULL`, `actor_email = attempted`, `metadata = {reason: "invalid_credentials"}` — no enumeration signal from the audit row.

### saas

Business logic, independent of UI framework.

- `SaasState { pool, authz, access, audit }`, `SaasBuilder` (`with_authz`, `with_access`, `with_audit`), `CoreError` (including `EmailNotVerified` and `TenantSuspended`), and services.
- `with_audit` — optional; without it `NoopAuditLogger` is used.
- `platform` (Stage 3f; extracted into `platform.rs`; re-exported at the crate root as `saas::{resolve_active_tenant, ActiveTenant}`):
  - `create_tenant` / `provision_tenant` — container and explicit-owner variants (unchanged from Stage 1.1).
  - `list_tenants` — platform admin tenant listing (`(tenants, list)`).
  - `suspend_tenant` / `activate_tenant` — idempotent status toggles (`(tenants, manage)`); emit `tenant.suspended` / `tenant.activated` only on a transition.
  - `resolve_active_tenant` — `ActiveTenant` or `Forbidden` / `TenantSuspended` / `NotFound`. Membership via `EXISTS tenant_members`; `#[server]` mutation functions (and `axum-minimal` handler functions) call it explicitly.
- Emits: `tenant.created` (in `platform::create_tenant` and `platform::provision_tenant`), `tenant.suspended` / `tenant.activated` (Stage 3f; transition only), `workspace.created` (in `tenant::create_workspace`), `invitation.created` / `.accepted` / `.revoked`, `member.role_assigned` / `.revoked` (from `saas::access::{assign_role, revoke_role}`), `role.deleted` (from `saas::access::delete_role`), `member.role_changed` (from `member::change_role`; in addition to the two events from its inner `assign_role` / `revoke_role`).

### db

PostgreSQL connection helper and migration runner. Migrations include `20261107000001_audit_log.sql` (Stage 3e: `audit_log` + 4 indexes; `actor_id ON DELETE SET NULL`; `actor_email` denormalized) and `20261108000001_platform_admin_permissions.sql` (Stage 3f: `(tenants, list)`, `(tenants, manage)`, `(audit, read)` added to the reference table and to the existing `platform` owner role).

### seed

Standalone binary for creating initial platform, tenant, workspace, user, role, policy, and audit data. Stage 3e wires a real `PgAuditLogger` into both `AccessState` and `SaasState`, so seed-produced bootstrap events (`tenant.created`, `workspace.created`, `role.created`, `member.role_assigned`) are visible in `audit_log` — the smoke-check for "did `with_audit` actually get wired?".

### examples/saas-leptos

Reference consumer. `main.rs` builds a real `PgAuditLogger` and passes it to `AccessState::with_audit`, `Authn::with_audit`, and `SaasBuilder::with_audit`. Routes: `/tenants`, `/workspaces`, `/invitations/:token`, `/verify/:token`, `/forgot-password`, `/reset-password/:token`, `/platform`, `/platform/audit` (Stage 3f), plus tenant/workspace member and role pages. `error.rs` maps errors to HTTP 400/401/403/404/409/429/500. `error.rs` does not map audit errors — audit never propagates to `ServerFnError`. `error.rs` maps `CoreError::TenantSuspended` to 403 with a distinct message (`"tenant is suspended"`) so the UI can show a dedicated banner. `guard.rs` (Stage 3f follow-up) implements the client route guards — UX-only; the backend `authz.require` / `resolve_active_tenant` remains authoritative.

### examples/axum-minimal (Stage 3g)

Second consumer — pure Axum, no Leptos; the portability proof.

- **11 endpoints**: `POST /auth/{register,login,logout,refresh}`, `GET|POST /tenants`, `GET|POST /workspaces`, `GET|POST /documents`, `GET /audit`. JSON request/response; `Set-Cookie` on the auth endpoints.
- **`CurrentUser` via `axum::extract::FromRequestParts`** — a deliberate deviation from ADR-0002 rev.2 §3.8, which deferred `FromRequestParts` for `saas-leptos` and reserved the general rule for Stage 4. The deviation is the point of 3g: it shows that the library contract (`authn.verify_token` + `Extension<Option<AuthUser>>`) works for a second extractor style. Recorded in `handoff §16` and Appendix B §2.48.
- **Same library calls, same `resolve_active_tenant`** — `saas::tenant::list_memberships`, `saas::platform::provision_tenant`, `saas::tenant::create_workspace`, `saas::workspace::{list_documents, create_document}`, `saas::platform::resolve_active_tenant` (in `create_workspace` and `create_document`), `saas::access::my_permissions` (in `list_audit`). Nothing library-side changed to support it — that is the proof.
- **`NoopEmailSender`** — no SMTP transport. `EmailSender` trait is present so a future consumer can plug in a real sender without changing `AppState`; `EmailResult` matches `saas-leptos`'s shape.
- **`SimpleRateLimiter`** — same in-memory sliding-window implementation as `saas-leptos`; applied to `POST /auth/register` (`3/h` per email). Not distributed (Stage 4).
- **Router split** — protected (`auto_refresh`) vs public (`register`/`login`/`logout`), same rationale as `saas-leptos` (ADR-0002 rev.2 §2.1).
- **No server-side per-route middleware** — same as `saas-leptos`: the `resolve_active_tenant` / `authz.require` calls inside handlers are the security boundary; the client is a JSON consumer that sees the same 401/403 responses a malicious curl would.

## Development principles

- Keep authentication separate from authorization.
- Keep authorization separate from business logic.
- **Audit is best-effort, not a security boundary.** Failures are `tracing::warn!`; they never fail the business operation (ADR-0004 §2.4). Audit is written **after** `COMMIT` in a separate transaction; it does not participate in the mutation's transaction (ADR-0003 A-lite unchanged).
- Never trust client-supplied tenant or workspace identifiers without server-side validation.
- Always scope database queries by tenant or workspace.
- Treat UI visibility as convenience, not as a security boundary.
- **Roles are data, not code.** No built-in role enums; `owner` is a row created by `access::create_owner_role` / the SQL migration; custom roles are created and edited by the domain owner.
- **`roles.key` is immutable**; `update_role` never changes it (rename = delete + create, ADR-0001).
- **Tenant suspension is enforced explicitly, not by middleware** (ADR-0002 rev.2). Mutating `#[server]` functions (in `saas-leptos`) and mutation handlers (in `axum-minimal`) call `saas::platform::resolve_active_tenant`; reads and cleanup stay available on a suspended tenant. `saas::invitation::{create, accept}_invitation` re-check the tenant status inside the service (defense in depth). Platform admin is not a superuser: a platform admin who is not a member of the target tenant gets `Forbidden` from `resolve_active_tenant`.
- **`suspend_tenant` / `activate_tenant` are idempotent.** `UPDATE … WHERE status = <expected> RETURNING *` emits `tenant.suspended` / `tenant.activated` only when a row was actually updated; a second call returns the row unchanged with no audit emission.
- `saas` and `authn` do not know about Leptos, Axum, or Casbin. `saas` does not know about `permissions`/`roles`/`role_permissions` — those belong to `access`. `authn` does not depend on `lettre` — SMTP transport lives in the example.
- **`audit` (trait) does not depend on `sqlx`.** Symmetric to `authz`. `audit-pg` owns `audit_log` (sole writer). `NoopAuditLogger` is always available — not a feature flag.
- Library crates do not depend on `examples/*`; each example has its own `Cargo.toml` and `Cargo.lock`.
- Server functions (and Axum handlers) resolve the actor through the example's `CurrentUser`; a missing actor is HTTP 401. `saas-leptos` uses a plain helper, `axum-minimal` uses `FromRequestParts` — both surface the same "no actor → 401" contract to the caller.
- Library errors (`CoreError`, `AuthnError`, `IdentityError`, `AccessError`) are mapped to HTTP status codes in each example (`src/error.rs`); keep new variants covered by that mapping. `AuditError` is **not** in that mapping — audit never propagates.
- Invitation raw tokens are returned once from `saas::invitation::create_invitation` and are never persisted; only `invitations.token_hash` (SHA-256) is stored.
- Refresh raw tokens, email-verification raw tokens, and password-reset raw tokens are returned once and never persisted; only their `token_hash` (SHA-256) is stored. `NoopEmailSender` logs only the recipient and the fact of a skipped send — **never the token**.
- **`authn::reset_password` is one-shot**: a replayed raw token returns `TokenInvalid`. In one transaction it rewrites `users.password_hash`, bumps `users.password_changed_at`, expires every outstanding reset token for the user, and revokes every refresh-token family with `revoked_reason = "password_reset"`. No auto-login.
- **Access JWT claims are `{ sub, iat, exp }` (Stage 3b).** Address and `email_verified` are resolved from `users` on `verify_token`.
- **Addressed invitations (Stage 3c).** `saas::invitation::accept_invitation` enforces verified-first (`CoreError::EmailNotVerified`) then case-insensitive email match (`CoreError::Forbidden`) for `invitation.email IS NOT NULL`; link invitations skip both. Both checks run before any mutation.
- **`saas::member::change_role` performs `assign` before `revoke`.** On a partial failure the user is over-permissioned (both roles) — recoverable idempotently by retrying `change_role`.
- **`saas::member::{change_role, remove_role}` include an owner guard**: the last holder of a `protected` role cannot be removed from a domain. Guard reads `casbin_rule`.
- **`saas::access::delete_role` cleans up `casbin_rule` (g+p), `*_members`, and the `roles` row** in six retry-safe steps; a partial failure can be recovered by calling `delete_role` again.
- All library crates in the reference apps and `seed` share a single `PgPool`.
- The `saas-leptos` `auto_refresh` middleware runs on the protected router (SSR + `/_server/*`); static files and 404 responses bypass it. The `axum-minimal` `auto_refresh` middleware runs on the protected router (`/auth/refresh`, `/tenants`, `/workspaces`, `/documents`, `/audit`); `register`/`login`/`logout` bypass it.
- **SMTP send timeout is 10 seconds** (in `saas-leptos`). Hydrate host check: `cargo check --features hydrate` catches type-level errors, not wasm-only; full `cargo leptos watch` is part of the merge checklist.
- **Audit events are constants in `audit::events`.** Adding a new event is a source change (no migration); per-event `metadata` is free-form JSONB, shape documented in Appendix B. `event_type` is `text` (not enum) — extensible without a migration.

## Roadmap

- Stage 1 (done): typed error mapping to HTTP codes, `CurrentUser` extractor, mock `AuthorizationEngine` and `#[sqlx::test]` integration tests.
- Stage 1.5 / 1.1 / 2a / 2b / 2e / 2e.1 / 2c / 2d (done): see `saas-appendix-a-changes.md`.
- Stage 3.0 (done): ADRs 0002/0003/0004.
- Stage 3a (done): UX 2.5 — role edit, member selects, return-URL preservation.
- Stage 3b (done): email verification + claims cleanup.
- Stage 3c (done): addressed invitations.
- Stage 3d (done): password reset.
- Micro-PR (done): Docker Compose v1 → v2.
- Stage 3e (done): Audit log. `audit` (trait) + `audit-pg` (`PgAuditLogger`); migration `20261107000001_audit_log.sql` (`audit_log` + 4 indexes, `actor_id ON DELETE SET NULL`). `Authn::with_audit`, `AccessState::with_audit`, `SaasBuilder::with_audit` — builder-style, additive (default `NoopAuditLogger`). 19 of 21 events emitted (all except `tenant.suspended` / `tenant.activated` — Stage 3f).
- **Stage 3f (done): Platform admin + tenant suspension.** `saas::platform::*` extended with `list_tenants` / `suspend_tenant` / `activate_tenant` / `resolve_active_tenant` / `ActiveTenant`; `CoreError::TenantSuspended`; explicit `resolve_active_tenant` call in the mutating `#[server]` functions of the example; `/platform` (rename of `PlatformPage` → `PlatformTenantListPage`) + new `/platform/audit` (`(audit, read)`); `tenant.suspended` / `tenant.activated` events (idempotent, transition-only). Migration `20261108000001_platform_admin_permissions.sql` adds `(tenants, list)`, `(tenants, manage)`, `(audit, read)` to `permissions` and tops up the platform owner. 8 new integration tests (116 → 124).
- **Client route guards follow-up (done):** `examples/saas-leptos/src/guard.rs` — `RouteGuard` enum + monolithic `GuardRoute` + standalone `RequireAuth` / `RequirePermission` / `RequireAnyPermission`. All 13 private routes in `lib.rs` under `GuardRoute`; `pages/*.rs` untouched. UX-only, not a security boundary; SSR-correct guard and server-side middleware — Stage 4.
- **Stage 3g (done): `axum-minimal`.** Second consumer on pure Axum, proving portability: `axum::Router::new()`, `axum::extract::FromRequestParts` for `CurrentUser` (deliberate deviation from ADR-0002 rev.2 §3.8), `axum-extra` cookies, `NoopEmailSender`, same `saas::*` / `authn::*` / `audit::*` calls and the same `resolve_active_tenant` in mutation handlers as `saas-leptos`. `crates/*` untouched — 0 migrations, 0 breaking changes, 124 library tests unchanged.
- Stage 3h (next): infra + minor (`has_policy` pre-check in `grant_role`, `pg_advisory_xact_lock` in the owner guard, `my_permissions` cache, `casbin_rule` dedup + unique index, owner-sync trigger). 124 → ~130–132 tests, +1 migration.
- Stage 4: Dockerfile, CI, observability, backups, cookie `Secure`/`SameSite`, CSRF, rate limiting (distributed), RLS, E2E HTTP tests, iat-vs-`password_changed_at`, outbox, audit retention/immutability, distributed single-flight refresh, escape hatch `_or_platform_admin`, pagination/filters on `/platform/audit` and `/platform/tenants`, SSR-correct guards in `saas-leptos`, server-side per-route middleware (defense in depth).

## License

See the `LICENSE` file in the root of the repository.