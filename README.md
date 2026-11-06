# Rust SaaS

**rust-saas** is a Rust library and reference application for building multi-tenant SaaS.

The library crates live in `crates/` (a Cargo workspace) and separate business logic, identity, authentication, and authorization from each other, so they can be reused in other applications through git dependencies. Three reference consumers live under `examples/`:

- `examples/saas-leptos` — Leptos SSR + Axum + `#[server]` (starter template; A7'.2 — single-dep + startup `bootstrap_*` + admin UI for `resource_types`).
- `examples/axum-minimal` — pure Axum, no Leptos (Stage 3g portability proof; **Stage 5.0-A6 — fork-free consumer on `saas-axum`**, one library dependency, 278 LOC src, 14 E2E).
- `examples/minimal-lms` — **fork-free Axum consumer on `saas-axum`** (Stage 5.0-A5; DoD-артефакт Phase A, Axum path).

## Features

- Multi-tenant architecture with tenants and workspaces
- Identity-first user model
- Email and password authentication
- Argon2 password hashing
- JWT access tokens (short-lived) and opaque refresh tokens (rotation with family revocation)
- Refresh grace window: parallel-request race does not revoke the token family
- Auto-refresh middleware scoped to protected routes (SSR + server functions); static assets bypass it
- Server-side logout (revokes refresh token family, records `revoked_reason`)
- Access-token claims `{ sub, iat, exp }` (no `email`); user is resolved from `users` on every request
- Email verification: single-active 24-hour token, idempotent verification, `/verify/:token` page, per-email rate limit (3/hour)
- Password reset (Stage 3d): single-active 1-hour token, `authn::request_password_reset` returns `Ok(None)` for unknown emails (no enumeration signal), `authn::reset_password` is **one-shot**; in one transaction it rewrites `password_hash` + bumps `password_changed_at`, expires every outstanding reset token, and revokes every refresh-token family (`revoked_reason = "password_reset"`).
- Addressed invitations (Stage 3c): `accept_invitation` requires a verified, matching email (verified-first, then case-insensitive match); link invitations (`email IS NULL`) keep Stage 2a behaviour.
- Audit log (Stage 3e): `audit` trait + `audit-pg` (`PgAuditLogger`); `Authn`/`AccessState`/`SaasState` inject `Arc<dyn AuditLogger>` via `with_audit`; 21 event types; sync after `COMMIT` in a separate transaction; `NoopAuditLogger` fallback for dev/tests/seed.
- Platform admin (Stage 3f): `saas::platform::{list_tenants, suspend_tenant, activate_tenant}` gated by `(tenant, list)`/`(tenant, manage)` in `PLATFORM_DOMAIN`; `/platform` and `/platform/audit` pages.
- Tenant suspension (Stage 3f): `resolve_active_tenant` + `ActiveTenant` + `CoreError::TenantSuspended`. Mutating `#[server]` calls resolve the tenant first; reads and cleanup stay available on a suspended tenant.
- Idempotent `p`-rows (Stage 3h, ADR-0003 §2.2): `grant_role` pre-checks `has_policy`.
- Race-free owner guard (Stage 3h, ADR-0003 §2.3): `pg_advisory_xact_lock` in `saas::member::{change_role, remove_role}`.
- Client-side permissions cache (Stage 3h): `PermsCache` with 30s TTL in `saas-leptos`.
- Owner-sync trigger (Stage 3h + Stage 5.0-A1.2, ADR-0001 §9.7): writes `role_permissions` **and** `casbin_rule.p` for every `owner` role. `AFTER DELETE` unsync — Stage 4.5c.
- Client route guards (Stage 3f follow-up + Stage 4.9): `GuardRoute` on `Resource`/`Suspense` (SSR-correct); UX-only, not a security boundary.
- Second consumer (Stage 3g): `examples/axum-minimal` — pure Axum, portability proof.
- Meta-crate `rust-saas` (Stage 4.0): one Cargo entry over all library crates (`features = ["ssr" | "hydrate" | "axum"]`).
- `[workspace.package]` + `COMPATIBILITY.md` (Stage 4.0): all `crates/*` share one version; SemVer policy + breaking-change log.
- Error isolation (Stage 4.2, breaking): `Db(String)` in `AccessError`/`IdentityError`/`AuthnError`/`CoreError`; `AuthnError::Identity(IdentityErrorKind)`.
- Auth hardening (Stage 4.1): `verify_token` rejects pre-password-change tokens (`iat` vs `password_changed_at`).
- Cookie config (Stage 4.1b): `CookieConfig { secure, access_ttl, refresh_ttl }`; `Secure` defaults to non-loopback bind address; `COOKIE_SECURE=1|0` override. `SameSite=Lax`, `Max-Age` from TTL.
- CSRF (Stage 4.1c): `axum-minimal` — double-submit (`csrf` cookie + `X-CSRF-Token`); `saas-leptos` — `Origin`/`Host` guard on top of `SameSite=Lax`.
- `AuthLayer` (Stage 4.1d + Stage 4.9): server-side defense-in-depth in both examples.
- `/healthz` (Stage 4.4a) liveness + `/readyz` (Stage 4.10) readiness (DB `SELECT 1` + optional Redis `PING`).
- Prometheus `/metrics` + `tracing` spans (Stage 4.10): counters `login_total{status}`, `register_total{status}`; `#[instrument]` on mutations in `authn`, `saas::platform`, `saas::member`, `access::role`.
- **`authz::test_support`** (Stage 4.3a): `AllowAllAuthz` / `DenyAllAuthz` under feature `test-support`.
- Pagination (Stage 4.8): `domain::Page<T>` + `list_*_paged`; old `list_*` deprecated.
- Distributed rate limiter (Stage 4.8): `crates/rate-limiter` with `RateLimiter` trait, `InMemoryRateLimiter` (default), `RedisRateLimiter` (feature `redis`).
- **Resource Registry** (Stage 5.0-A1, B2/B3/B4 closed): `resource_types` table (8 core types) + `access::registry` Rust API (`bootstrap_resource_type(s)`, `bootstrap_all_core`, `register_resource_type`, `add_action`, `list_resource_types`); `AuthorizationEngine::reload_in_memory()`; legacy import to `custom:legacy`; FK `permissions.resource → resource_types.name`.
- **`SaasBuilder::without_access()`** (Stage 5.0-A2.2b, B9 closed) + `SaasState.access: Option<Arc<AccessState>>` + `access() -> Result<&AccessState, CoreError>` (breaking).
- **`create_workspace` split** (Stage 5.0-A2.2c, B10 closed): 4-arg (no owner) + `create_workspace_with_owner` (6-arg).
- **`saas::platform::{resolve_tenant, resolve_workspace, resolve_active_workspace, is_tenant_member, is_workspace_member}`** + `ActiveWorkspace` (Stage 5.0-A2.1, B8 closed).
- **`db::migrate_composed`** (Stage 5.0-A3, B1 closed): merge workspace set + consumer migrator, one run, validated before SQL. `db::MIGRATOR` public. `db::migrate_with` deprecated.
- **`saas-axum` HTTP adapter** (Stage 5.0-A4, B5/B6/B7 closed): internal crate, consumer-facing via `rust-saas = { features = ["axum"] }`. **Four entry-points**: `build_app` (public-only), `build_app_with_protected(state, protected)`, `build_app_full(state)` (public + standard endpoints `/auth/*`, `/my_permissions*`, `/resource_types`), **`build_app_full_with(state, extra_protected)`** (Stage 5.0-A4.6 — public + standard + custom, all under `csrf_guard → auto_refresh → auth_layer`). `RouteBinding`/`BindingScope`/`RouteBindings`/`PathPermissions` for declarative path-level gating; fail-fast validation in `build()`.
- **`examples/minimal-lms`** (Stage 5.0-A5): fork-free Axum consumer — 8 files, ~290 LOC without comments, 3 E2E. Uses only `rust-saas = { features = ["axum"] }` from workspace. **All 10 pluggability blockers (B1–B10) closed.**
- **`examples/axum-minimal`** (Stage 5.0-A6): refactored onto `saas-axum` — **3 files, 278 LOC src** (was ~2000), **1 library dependency** `rust-saas = { features = ["axum"] }`, **14/14 E2E green**, `fmt --check` + `clippy -D warnings` clean. Structural refactor; behavioral contract (status codes, JSON shape, cookie flow, error bodies) preserved.
- **`examples/saas-leptos` starter template** (Stage 5.0-A7'.1 + A7'.2): **1 workspace dep** (`rust-saas` + `domain` hydrate-only). A7'.2 adds **startup `bootstrap_*`** in `main.rs` (`bootstrap_all_core` + `bootstrap_resource_types` with 3 LMS types: `course`/`assignment`/`batch`) and **admin UI** on `/platform` (`#[server] list_resource_types` + `#[server] register_resource` + form + list). **18/18 E2E green** (was 15 — A7'.2 added 3). Full `resource_types` lifecycle: startup registration + runtime registration.

## Architecture

Two layers:

```text
crates/                  (library — the Cargo workspace)
├── domain/             Shared DTOs (Tenant, Workspace, Document, AuthUser, Invitation, Member),
│                       InvitationTarget, domain helpers, PLATFORM_DOMAIN, Page<T>;
│                       AuthUser.email_verified (derived from users.email_verified_at);
│                       TenantStatus (Active / Suspended)
├── authz/              AuthorizationEngine trait
│                       (can / require / grant_role / revoke_role / has_role /
│                        count_users_with_role / purge_role / reload_in_memory) + AuthzError;
│                       test_support (AllowAllAuthz / DenyAllAuthz) — под feature `test-support`
├── authz-casbin/       CasbinAuthz: canonical trait implementation
├── audit/              AuditLogger trait, AuditEvent DTO, NoopAuditLogger, 21 event constants
├── audit-pg/           PgAuditLogger: PostgreSQL implementation (audit_log table) + MIGRATOR
├── access/             Sole owner of `permissions`, `roles`, `role_permissions`:
│                       Role, Permission, RoleKey, AccessState, AccessError, role CRUD,
│                       create_owner_role, get_role_by_id, delete_role_by_id,
│                       list_permissions, get_permissions_for_role; registry module
│                       (Stage 5.0-A1: ResourceType, ResourceScope, bootstrap_*, register_resource_type,
│                        add_action, list_resource_types)
├── identity/           Sole owner of `users`: AuthUser, UserRecord, validation, CRUD;
│                       UserRecord.email_verified_at (source of truth for the derived flag);
│                       UserRecord.password_changed_at (Stage 3d);
│                       update_password_tx (Stage 3d)
├── authn/              Argon2, JWT access tokens, opaque refresh tokens, rotation
│                       with grace window; email verification (single-active, 24h);
│                       password reset (single-active, 1h, one-shot, revoke all families);
│                       RevokeReason; audit emission (8 events)
├── saas/               Business logic: platform (incl. suspend/activate + resolve_*), tenant,
│                       workspace, invitation, member, access (wrappers, my_permissions);
│                       SaasBuilder (with_access / without_access); audit emission
├── db/                 PostgreSQL connection and migrations;
│                       MIGRATOR + migrate_composed + CONSUMER_VERSION_FLOOR (Stage 5.0-A3);
│                       migrate_with (deprecated)
├── rate-limiter/       RateLimiter trait + InMemoryRateLimiter + RedisRateLimiter (Stage 4.8)
├── saas-axum/          Internal Axum HTTP adapter (Stage 5.0-A4): AxumAppState + builder,
│                       RouteBindings + PathPermissions + auth_layer + csrf + auto_refresh,
│                       endpoints /auth/* + /my_permissions* + /resource_types,
│                       build_app / build_app_with_protected / build_app_full / build_app_full_with
├── rust-saas/          Meta-crate (Stage 4.0): features ["ssr" | "hydrate" | "axum"];
│                       migrate_all / migrate_extended (Stage 5.0-A3)
└── seed/               Bootstrap data and demo accounts (all email-verified)

examples/                (reference consumers — outside the workspace)
├── saas-leptos/        Leptos SSR + Axum + #[server] + middleware + cookies
│                       + SMTP transport (lettre, 10s timeout) + in-memory rate limiter
│                       + forgot-password / reset-password pages
│                       + /platform + /platform/audit (platform admin)
│                       + PgAuditLogger wired through Authn / AccessState / SaasBuilder
│                       + client route guards (Stage 3f + follow-up; SSR-correct Stage 4.9)
│                       + AuthLayer (Stage 4.9)
│                       + resource_types lifecycle (A7'.2: bootstrap_* in main.rs
│                         + #[server] register_resource / list_resource_types + UI)
├── axum-minimal/       Stage 3g + Stage 5.0-A6: pure Axum, no Leptos — fork-free
│                       consumer on saas-axum (3 files, 278 LOC src, 14 E2E,
│                       1 library dep)
└── minimal-lms/        Stage 5.0-A5: fork-free Axum consumer on saas-axum
                        (DoD-артефакт Phase A, Axum path; ~290 LOC без комментариев; 3 E2E)
```

`examples/*` is listed in `workspace.exclude`; each example has its own `Cargo.toml` and `Cargo.lock`, and depends on the library crates via path dependencies pointing at `../../crates/*`.

The application separates five concerns:

| Concern | Responsibility | Crate |
|---|---|---|
| Identity | Who you are as an entity (`users` table, `AuthUser`) | `identity` |
| Authentication | How you proved you are who you are (Argon2, JWT, refresh tokens, email verification, password reset) | `authn` |
| Authorization | What you are allowed to do (`AuthorizationEngine`) | `authz` / `authz-casbin` |
| Roles & permissions | Who has which rights (`roles`, `permissions`, `role_permissions`, `resource_types`) | `access` |
| Data isolation | Which rows you can see (SQL filters by tenant/workspace) | `saas` |

Plus a cross-cutting concern:

| Concern | Responsibility | Crate |
|---|---|---|
| Audit | Who did what, when (`audit_log`) | `audit` / `audit-pg` |

`Casbin does not replace SQL isolation. JWT does not replace Casbin. UI does not replace backend authorization. Roles are data, not code. Audit is best-effort, not a security boundary.`

### Crate dependency graph

```text
saas-leptos  -> rust-saas (features = ["ssr", "rate-limiter-redis"]),
                domain (hydrate-only)                                          (example)
axum-minimal -> rust-saas (features = ["axum"])                               (example)
minimal-lms  -> rust-saas (features = ["axum"])                               (example)
seed         -> authz, authz-casbin, access, authn, identity, db, domain, saas,
                audit, audit-pg
saas-axum    -> domain, authz, authz-casbin, access, identity, authn, saas, db,
                audit, audit-pg, rate-limiter, axum, axum-extra, tower-http, matchit
saas         -> authz (trait), access, identity, domain, audit, sqlx, sha2
access       -> authz (trait), domain, audit, sqlx, uuid, serde, thiserror
authn        -> identity, domain, audit, sqlx, argon2, jsonwebtoken, sha2
identity     -> domain, sqlx
authz-casbin -> authz (trait), casbin, sqlx, sqlx-adapter
authz        -> uuid, thiserror, async-trait
audit        -> serde, uuid, thiserror, async-trait, chrono, serde_json
audit-pg     -> audit, sqlx, uuid, thiserror, async-trait, serde_json
db           -> sqlx, anyhow
rate-limiter -> async-trait, uuid, tracing, redis (optional)
domain       -> serde, uuid, chrono; sqlx (optional, ssr only);
                `test-support` feature (test-only AuthUser constructors)
rust-saas    -> domain, authz, audit, rate-limiter (default);
                + access, authz-casbin, identity, authn, saas, db, audit-pg
                  + domain/ssr (feature `ssr`);
                + saas-axum (feature `axum`)                                  (meta-crate)
```

Forbidden edges:

- `saas` does not depend on Leptos, Axum, `casbin::Enforcer`, JWT, or Argon2. `sha2` is used only for `invitation::hash_token`.
- `access` does not depend on business tables (`tenants`, `workspaces`, `documents`, `invitations`, `*_members`), HTTP, UI, JWT, or Argon2.
- `authn` does not depend on `authz`. `sha2` is used only for refresh-, email-verification-, password-reset `token_hash`. `lettre` is **not** a dependency of `authn`; SMTP delivery lives in the example.
- `identity` does not depend on `authn` or `authz`.
- `authz` does not depend on Casbin, SQL, HTTP, Leptos, or JWT. It does not know about specific roles.
- `authz-casbin` does not depend on business tables; raw SQL only against `casbin_rule`.
- **`audit` does not depend on `sqlx`, `SaasState`, `Authn`, `AccessState`, `identity`, or any business crate.** Trait-only, symmetric to `authz`.
- **`audit-pg` depends on `audit` and owns the `audit_log` table.** Sole writer.
- **`saas-axum` is an internal crate.** Consumer-facing via `rust-saas::features = ["axum"]`; no consumer depends on `saas-axum` directly.
- Library crates do not depend on `examples/*`.

### Multi-tenancy model

```text
platform
└── tenant
    ├── workspace
    └── workspace
```

- A **tenant** represents a customer organization. It has a `status` (`active` or `suspended`).
- A **workspace** represents a working area inside a tenant.
- A **user** is a global identity and can participate in multiple tenants or workspaces.
- A **workspace** contains business resources such as documents.
- An **invitation** targets exactly one tenant or one workspace (`CHECK ((tenant_id IS NULL) <> (workspace_id IS NULL))`).
- **Suspended tenants** (Stage 3f): mutating `#[server]` calls that go through `resolve_active_tenant` return `TenantSuspended` (HTTP 403); reads and cleanup keep working.

### Authorization domains

Casbin policies are scoped by domain:

| Domain | Purpose |
|---|---|
| `platform` | Platform-level administration (list tenants, suspend/activate, read audit, register resource types) |
| `tenant:{tenant_id}` | Tenant-level operations |
| `workspace:{workspace_id}` | Workspace-level operations |

### Domain-ownership RBAC

- A **role** is a named set of permissions in a **domain** (not in a tenant).
- A **permission** is a `(resource, action)` pair from the `permissions` reference table. Every `permissions.resource` must be declared in `resource_types` (Stage 5.0-A1.3 FK).
- The **owner** role in a domain has **all permissions** from the reference table, is `protected=true` and `immutable=true`. Created by `access::create_owner_role(domain)` (idempotent) from `provision_tenant` / `create_workspace_with_owner`, and via the bootstrap SQL migration for the `platform` domain.
- The owner of a domain creates custom roles and assigns them to users (`saas::access::create_role` / `assign_role` / `update_role`). Roles can be edited (`name`, `description`, `permissions`) and deleted; `key` is immutable.
- Users can hold **multiple roles** in the same domain.
- The **owner guard** prevents removing the last holder of a `protected` role (`saas::member::{change_role, remove_role}` returns `Forbidden`).
- **Platform admin** (Stage 3f) is a user holding `platform` `owner` (or any role that grants platform-scoped permissions). It is **not** a superuser inside tenants/workspaces.
- **`resource_types`** (Stage 5.0-A1): declared, not enforced. `scope` (`platform` / `tenant` / `workspace` / `custom:*`) is a hint for consumer UI; enforcement remains in `casbin_rule.p.v1`. Runtime registration via `access::registry::{bootstrap_*, register_resource_type, add_action}`; `AuthorizationEngine::reload_in_memory()` makes the current process see the new permissions without a restart.

Example permissions and demo roles:

| Permission `(resource, action)` | Domain | Used by |
|---|---|---|
| `(tenant, create)` | `platform` | `saas::platform::{create_tenant, provision_tenant}` |
| `(tenant, list)` | `platform` | `saas::platform::list_tenants` (Stage 3f) |
| `(tenant, manage)` | `platform` | `saas::platform::{suspend_tenant, activate_tenant}` (Stage 3f) |
| `(audit, read)` | `platform` | `/platform/audit` view (Stage 3f) |
| `(resource, manage)` | `platform` | `access::registry::{register_resource_type, add_action}` (Stage 5.0-A1.3) |
| `(workspace, create)` | `tenant:{id}` | `saas::tenant::{create_workspace, create_workspace_with_owner}` |
| `(document, read/write)` | `workspace:{id}` | `saas::workspace::*` |
| `(member, list/manage)` | `tenant:{id}`, `workspace:{id}` | `saas::member::*` |
| `(invitation, create/revoke/list)` | `tenant:{id}`, `workspace:{id}` | `saas::invitation::*` |
| `(role, create/manage/delete/list/grant)` | `tenant:{id}`, `workspace:{id}` | `saas::access::*` |

| Role | Domain | Permissions |
|---|---|---|
| `owner` | `platform` | all from `permissions` (bootstrap) |
| `owner` | `tenant:{id}` | all from `permissions` |
| `owner` | `workspace:{id}` | all from `permissions` |
| `editor` | `workspace:{id}` | `document:read/write` (demo, created by seed) |
| `viewer` | `workspace:{id}` | `document:read` (demo, created by seed) |

### Tenant lifecycle

- `tenants.status` is `active` (default) or `suspended`.
- **Suspend/activate** are admin actions: `(tenant, manage)` in `PLATFORM_DOMAIN`. Both are **idempotent**; emit `tenant.suspended` / `tenant.activated` only on transition.
- **Resolution.** `resolve_active_tenant` returns `ActiveTenant` only when (1) the actor is a member (`EXISTS tenant_members`) and (2) `status = 'active'`.
- **Mutation paths.** `#[server]` mutation functions (and Axum handler functions) call `resolve_active_tenant` explicitly. Reads and cleanup do **not** resolve.
- **Platform admin is not a bypass.** Non-member platform admin gets `Forbidden` from `resolve_active_tenant`. Escape hatch (`_or_platform_admin`) deferred to Phase D.

## Technology stack

| Layer | Technology |
|---|---|
| Language | Rust |
| UI | Leptos (in the reference example) |
| Backend | Axum (in the reference example, `axum-minimal`, `minimal-lms`) |
| Database | PostgreSQL 16 |
| Database access | SQLx |
| Authorization | Casbin (via `authz-casbin`) |
| Authentication | Argon2, JWT (access), opaque tokens (refresh, email-verification, password-reset) |
| Audit | `audit` (trait-only) + `audit-pg` (`audit_log`) |
| Email verification | SHA-256 over random raw token; not persisted; 24h TTL, single-active |
| Password reset | SHA-256 over random raw token; not persisted; 1h TTL, single-active, one-shot |
| Email delivery | `lettre` in `saas-leptos`; `NoopEmailSender` in `axum-minimal`/`minimal-lms`; Mailpit for local dev |
| Rate limiting | `RateLimiter` trait; `InMemoryRateLimiter` default; `RedisRateLimiter` (feature `redis`) |
| Invitation tokens | SHA-256 over random raw token; not persisted |
| Refresh tokens | SHA-256 over random raw token; not persisted |
| HTTP adapter | `saas-axum` (internal) — `rust-saas::features = ["axum"]` |
| Resource registry | `resource_types` table (Stage 5.0-A1) |
| Styling | Tailwind CSS v4 (in `saas-leptos`) |
| Local infrastructure | Docker Compose v2 — PostgreSQL + Mailpit + Redis |
| Logging | `tracing` + `tracing-subscriber` (`RUST_LOG` env-filter) |
| Testing | `cargo test`; `#[sqlx::test]` for per-test isolated databases |

## Getting started

### Prerequisites

- Rust
- `wasm32-unknown-unknown` target (for `saas-leptos`; not needed for `axum-minimal` / `minimal-lms`)
- `cargo-leptos` (for `saas-leptos`)
- Docker with the Compose **v2** plugin (`docker compose version` should print `v2.x.y`)

```bash
rustup target add wasm32-unknown-unknown
cargo install --locked cargo-leptos
```

### Start PostgreSQL and Mailpit

```bash
docker compose up -d
docker compose ps
```

Mailpit (`http://localhost:8025`) is only needed for email-verify / addressed invitations / password reset. Without it, `saas-leptos` falls back to `NoopEmailSender`.

### Configure environment

```bash
cp .env.example .env
```

Generate `JWT_SECRET`:

```bash
openssl rand -base64 48
```

Put it in `.env`. Keep `.env.example` on the placeholder.

```env
DATABASE_URL=postgres://postgres:postgres@localhost:5430/rust_saas
JWT_SECRET=replace-with-a-long-random-secret
ACCESS_TOKEN_TTL_MINUTES=15
REFRESH_TOKEN_TTL_DAYS=30
BIND_ADDR=127.0.0.1:3395
SMTP_URL=smtp://localhost:1025
# SMTP_FROM=noreply@example.test
# BASE_URL=http://127.0.0.1:3395
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=rust_saas
REDIS_URL=redis://localhost:6380
RUST_LOG=info
```

Notes:
- `.env` lives in the repository root; discovered by seed, both examples, `#[sqlx::test]`.
- `.env` must be LF, not CRLF.
- Do not put `LEPTOS_*` variables into `.env`.
- `DATABASE_URL` user must have the `CREATE DATABASE` privilege for `#[sqlx::test]`.
- `SMTP_URL` is read only by `saas-leptos`.

### Apply migrations and seed data

```bash
cargo run -p seed
```

Demo users created by seed (all **email-verified**):

| Role | Email | Password |
|---|---|---|
| Platform owner | `platform-admin@example.test` | `PlatformAdmin123!` |
| Tenant owner | `owner@acme.test` | `Owner123!` |
| Workspace editor | `editor@acme.test` | `Editor123!` |
| Workspace viewer | `viewer@acme.test` | `Viewer123!` |

Seed applies 15 migrations (including Stage 5.0-A1: `resource_types` + `owner_sync` fix + legacy import). Idempotent; re-running re-hashes passwords, re-applies roles/policies, marks demo accounts verified without moving original `email_verified_at`. Seed does not touch `password_changed_at`.

Seed flow:
1. Grants `platform` `owner` role to platform admin (direct `authz.grant_role`; no audit event).
2. Provisions tenant via `provision_tenant(..., &RoleKey::parse("owner")?)` — emits `tenant.created`.
3. Creates workspace via `create_workspace_with_owner(..., &RoleKey::parse("owner")?)` — emits `workspace.created`.
4. Creates demo roles `editor`/`viewer` via `create_role` — `role.created` × 2; assigns via `assign_role` — `member.role_assigned` × 2.
5. Marks every demo account verified.

Bootstrap audit events after seed: `tenant.created`, `workspace.created`, `role.created` × 2, `member.role_assigned` × 2.

**Existing DB:** if it predates A1 (Stage 5.0), the new migrations `20261130000001..3` will be applied. Custom `permissions.resource` values get auto-imported as `custom:legacy`. A running replica still needs `authz.reload_in_memory()` after migration.

### Run the reference application (`saas-leptos`)

```bash
cd examples/saas-leptos
cargo leptos watch
```

Open `http://127.0.0.1:3395`. Reload port: `3396`.

On startup, `main.rs` calls `bootstrap_all_core` + `bootstrap_resource_types` (A7'.2) — so 3 custom LMS types (`course`, `assignment`, `batch`) are registered automatically.

Then in the browser:

1. `/register` — create account.
2. Verification link from Mailpit → `/verify/:token`. Idempotent.
3. `/login` with demo account.
4. `/platform` — create/suspend tenants. **A7'.2: also lists + registers `resource_types` (form + list).**
5. `/platform/audit` — audit rows (as platform admin).
6. `/tenants/<id>` — create workspace.
7. `/tenants/<id>/members` — assign/remove roles.
8. `/tenants/<id>/roles` — list/create/edit/delete roles.
9. `/workspaces/<id>` — create documents.
10. `/tenants/<id>/invitations` — create link / addressed invitation.
11. `/forgot-password` → `/reset-password/:token`.
12. After 15+ minutes — auto-refresh rotates refresh token.

Rate limits: register 3/hour per email; email verify 3/hour; password reset 5/hour.

### Run the `saas-leptos` Docker image

```bash
docker compose up -d
cargo run -p seed

docker run --rm -d --name saas-leptos \
  --network rust-saas_rust_saas_net \
  -e DATABASE_URL='postgres://postgres:postgres@postgres:5432/rust_saas' \
  -e JWT_SECRET='change-me' \
  -p 3395:3395 \
  rust-saas/saas-leptos:<tag>
```

Open `http://127.0.0.1:3395`. If you skip `seed`, `/login` rejects every attempt.

Dockerfile pins `cargo-leptos =0.3.11`, `wasm-bindgen =0.2.129`, `binaryen 133` (see `CHANGELOG.md` Stage 4.4b).

`examples/saas-leptos/smoke.sh` — fail-fast smoke test (SSR + static assets + `wasm < 2 MB` + guard routes + seed-user + 9 tables).

### Run the `axum-minimal` example

```bash
cargo run --manifest-path examples/axum-minimal/Cargo.toml
```

Listens on `BIND_ADDR` (default `127.0.0.1:3395`). If `saas-leptos` uses that port, set `BIND_ADDR=127.0.0.1:3397`.

Smoke (curl):

```bash
# register (rate-limited 3/h per email)
curl -X POST http://127.0.0.1:3395/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke-1@example.test","password":"Smoke123!"}' \
  -c /tmp/axum-minimal-cookies.txt

# login as seed demo
curl -X POST http://127.0.0.1:3395/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"platform-admin@example.test","password":"PlatformAdmin123!"}' \
  -c /tmp/axum-minimal-cookies.txt

# list tenants (empty for platform admin — not a tenant member)
curl -X GET http://127.0.0.1:3395/tenants -b /tmp/axum-minimal-cookies.txt

# create a tenant
curl -X POST http://127.0.0.1:3395/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"Axum Smoketest"}' \
  -b /tmp/axum-minimal-cookies.txt

# list workspaces, audit
curl -X GET http://127.0.0.1:3395/workspaces -b /tmp/axum-minimal-cookies.txt
curl -X GET 'http://127.0.0.1:3395/audit?limit=10' -b /tmp/axum-minimal-cookies.txt
```

Expected: anonymous `/tenants` → 401; `POST /workspaces` on suspended → 403; `GET /audit` as non-platform-admin → 403; 4th register/hour → 429 with `Retry-After`.

Cookie flow and auto-refresh identical to `saas-leptos` (same library calls).

### Run the `minimal-lms` example (Stage 5.0-A5)

```bash
docker compose up -d         # Postgres (default port 5430)
# DATABASE_URL + JWT_SECRET in .env (repo root)
cargo run --manifest-path examples/minimal-lms/Cargo.toml
```

`minimal-lms` is the **fork-free Axum consumer** — DoD-артефакт Phase A. Uses only `rust-saas = { features = ["axum"] }` from workspace:

- `Cargo.toml` — 8 `[dependencies]` + 4 dev-deps.
- `migrations/90000000000001_lms_tables.sql` — 4 tables (`courses`, `assignments`, `batches`, `files`), FK on `workspaces(id)` / `tenants(id)` / `courses(id)` (plural).
- `src/handlers.rs` — 4 handlers (`resolve_active_*` + `authz.require`).
- `src/lib.rs` — `build_app(state) = build_app_full_with(state, extra_routes())`.
- `src/main.rs` — `db::migrate_composed(&pool, &[&MY_MIGRATOR])` + `AxumAppState::builder(...).with_resource_types(&[...]).with_bindings([...]).build()`.
- `tests/e2e.rs` — 3 E2E via `tower::oneshot` + `#[sqlx::test(migrations = false)]`.

Run tests:

```bash
cargo test --manifest-path examples/minimal-lms/Cargo.toml
```

DoD deviations from `saas-23.md §3` (documented in A8 §5.7(i)): 8 deps (not 5); 4 handlers (not 5); `build_app_full_with` (not `build_app_full(state).route(...)`); LOC 486 raw / ~290 without comments (DoD "≤300 without comments" satisfied).

### CSRF (Stage 4.1c)

Two complementary mechanisms:

- **axum-minimal:** CSRF double-submit (csrf cookie + `X-CSRF-Token` header); `csrf_guard` rejects mutations except `/auth/{register,login,logout}`.
- **saas-leptos:** `SameSite=Lax` + `Origin`/`Host` guard (`#[server]` has no hook for custom header).

Smoke:

```bash
# axum-minimal: first request sets csrf cookie
curl -i http://127.0.0.1:3395/tenants -c /tmp/cj.txt | grep -i 'set-cookie: csrf'

# mutation without header → 403
curl -i -X POST http://127.0.0.1:3395/tenants -H 'Content-Type: application/json' -d '{"name":"Smoke"}' -b /tmp/cj.txt | head -1

# same with header → 200 (or 401 if not logged in)
CSRF=$(awk '$6=="csrf" {print $7}' /tmp/cj.txt)
curl -i -X POST http://127.0.0.1:3395/tenants -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d '{"name":"Smoke"}' -b /tmp/cj.txt | head -1
```

### Health and observability

| Endpoint | Question | Checks | Auth / CSRF | K8s probe |
|---|---|---|---|---|
| `GET /healthz` | alive and serving HTTP? | none | no / no | `livenessProbe` |
| `GET /readyz` | ready to accept traffic? | DB `SELECT 1`; Redis `PING` if `REDIS_URL` | no / no | `readinessProbe` |

`/healthz` always 200 (no DB / auth / cookie). `/readyz` 200 `{"status":"ok","checks":{"db":"ok","redis":"ok"|"not_configured"}}` or 503. Both on the public router.

Metrics (Stage 4.10): `/metrics` in Prometheus exposition format. Public on purpose; counters only. `login_total{status}`, `register_total{status}`.

Tracing (Stage 4.10): `#[instrument]` on mutations only (not `list_*` / `get_*`):
- `authn`: `register`, `login`, `rotate_refresh_token`, `verify_email`, `request_password_reset`, `reset_password`.
- `saas::platform`: `provision_tenant`, `suspend_tenant`, `activate_tenant`, `resolve_active_tenant`.
- `saas::member`: `change_role`, `remove_role`.
- `access::role`: `create_role`, `update_role`, `delete_role`.

Secrets (`password`, `raw`, `token`), PII (`actor.email`), free-form user input (`name`, `description`, `permissions`) are `skip`ped. Visible under default `RUST_LOG=info`.

### Checking the build

From the repository root:

```bash
clear && cargo test && cargo check && cargo check -p seed \
  && cargo check --manifest-path examples/saas-leptos/Cargo.toml --features ssr \
  && cargo check --manifest-path examples/saas-leptos/Cargo.toml \
  && cargo check --manifest-path examples/axum-minimal/Cargo.toml \
  && cargo check --manifest-path examples/minimal-lms/Cargo.toml
```

E2E for the three consumers:

```bash
cargo test --manifest-path examples/axum-minimal/Cargo.toml --test e2e
cargo test --manifest-path examples/saas-leptos/Cargo.toml --features ssr --test e2e
cargo test --manifest-path examples/minimal-lms/Cargo.toml --test e2e
```

### Running tests

```bash
cargo test
```

**254 workspace tests + 35 E2E, all green.** (14 `axum-minimal` + 18 `saas-leptos` (A7'.2 added 3) + 3 `minimal-lms`.)

Unit tests live inline (`#[cfg(test)] mod tests`) in `authn`, `access`, `saas`, `audit`. Integration tests live in `crates/*/tests/` and use `#[sqlx::test]`:

- Each test gets its own isolated database on `DATABASE_URL`; `crates/db/migrations` applied automatically; dropped after.
- No manual `createdb` required. User in `DATABASE_URL` needs `CREATE DATABASE`.
- Tests can run in parallel; isolation is per-database.

The reference examples have small unit-test modules too (`rate_limit.rs` in both) and E2E (`tests/e2e.rs`).

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
│   │   └── migrations/            # 000_users_bootstrap.sql + 001_audit_log.sql
│   ├── access/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── role.rs
│   │       ├── permission.rs
│   │       └── registry.rs        # Stage 5.0-A1: ResourceType, bootstrap_*, register_resource_type
│   ├── identity/
│   ├── authn/
│   ├── saas/
│   │   └── src/
│   │       ├── lib.rs             # CoreError, SaasState, SaasBuilder, tenant / workspace modules
│   │       ├── platform.rs        # create_tenant, provision_tenant, list_tenants_paged,
│   │       │                      # suspend_tenant, activate_tenant, resolve_active_tenant,
│   │       │                      # resolve_tenant, resolve_workspace, resolve_active_workspace,
│   │       │                      # is_tenant_member, is_workspace_member,
│   │       │                      # ActiveTenant, ActiveWorkspace
│   │       ├── access.rs
│   │       ├── invitation.rs
│   │       └── member.rs
│   ├── db/
│   │   └── migrations/            # 15 files (12 pre-5.0 + 3 Stage 5.0-A1)
│   │       ├── 20261026000001_init.sql
│   │       ├── 20261101000001_saas_invitations.sql
│   │       ├── 20261102000001_authn_refresh_tokens.sql
│   │       ├── 20261103000001_access_rbac_init.sql
│   │       ├── 20261103000002_saas_members_multi_role.sql
│   │       ├── 20261104000001_access_members_list_permission.sql
│   │       ├── 20261105000001_authn_email_verify.sql
│   │       ├── 20261106000001_authn_password_reset.sql
│   │       ├── 20261107000001_audit_log.sql
│   │       ├── 20261108000001_platform_admin_permissions.sql
│   │       ├── 20261110000001_casbin_rule_unique_idx.sql
│   │       ├── 20261110000002_owner_sync_trigger.sql
│   │       ├── 20261111000001_owner_sync_delete_trigger.sql
│   │       ├── 20261130000001_resource_types.sql
│   │       ├── 20261130000002_owner_sync_casbin.sql
│   │       └── 20261130000003_legacy_import_and_fk.sql
│   ├── rate-limiter/              # Stage 4.8: trait + InMemory + Redis
│   ├── saas-axum/                 # Stage 5.0-A4: internal HTTP adapter
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── router.rs          # build_app, build_app_full, build_app_full_with, build_app_with_protected
│   │   │   ├── state.rs           # AxumAppState + AxumAppStateBuilder
│   │   │   ├── bindings.rs        # RouteBinding, BindingScope, RouteBindings, PathPermissions
│   │   │   ├── endpoints/         # auth, my_permissions, resource_types
│   │   │   ├── middleware/        # auth_layer, auto_refresh, csrf
│   │   │   ├── cookie.rs
│   │   │   ├── email.rs
│   │   │   ├── error.rs
│   │   │   ├── extract.rs
│   │   │   ├── health.rs
│   │   │   └── pagination.rs
│   │   └── tests/state.rs
│   ├── rust-saas/                 # meta-crate (re-exports; feature "axum" adds saas-axum)
│   └── seed/
└── examples/
    ├── saas-leptos/
    │   ├── Cargo.toml
    │   ├── Dockerfile
    │   ├── smoke.sh
    │   └── src/
    │       ├── auth.rs
    │       ├── email.rs
    │       ├── rate_limit.rs
    │       ├── guard.rs
    │       ├── perms_cache.rs
    │       ├── cookie.rs
    │       ├── middleware.rs
    │       ├── auth_layer.rs       # Stage 4.9
    │       └── pages/
    ├── axum-minimal/              # Stage 3g, refactored Stage 5.0-A6 (fork-free on saas-axum)
    │   ├── Cargo.toml             # 1 workspace dep (rust-saas, features = ["axum"]) + 8 system + 6 dev
    │   ├── Cargo.lock
    │   ├── Dockerfile
    │   ├── src/
    │   │   ├── lib.rs             # build_app(state) = build_app_full_with(state, extra) — ~32 LOC
    │   │   ├── main.rs            # connect + migrate + AxumAppState::builder + serve — ~41 LOC
    │   │   └── handlers.rs        # 7 handlers + local PaginationQuery — ~206 LOC
    │   └── tests/e2e.rs           # 14 tests — ~377 LOC
    └── minimal-lms/               # Stage 5.0-A5: fork-free Axum consumer
        ├── Cargo.toml
        ├── Cargo.lock
        ├── build.rs
        ├── migrations/
        │   └── 90000000000001_lms_tables.sql
        ├── src/
        │   ├── lib.rs             # build_app(state) = build_app_full_with(state, extra_routes())
        │   ├── main.rs            # migrate_composed + AxumAppState::builder + serve
        │   └── handlers.rs        # 4 handlers: list/create courses, list files, create batch
        └── tests/e2e.rs           # 3 E2E
```

### domain

Shared DTOs (`Tenant`, `Workspace`, `Document`, `AuthUser`, `Invitation`, `Member`), `InvitationTarget`, `TenantStatus`, `Page<T>` (Stage 4.8), and domain helpers (`PLATFORM_DOMAIN`, `tenant_domain`, `workspace_domain`). No SQL, no logic.

`AuthUser.email_verified` is **derived** (`users.email_verified_at IS NOT NULL`).

`test-support` feature exposes `AuthUser::test_verified()` / `test_unverified()` (dev-deps only).

### authz

`AuthorizationEngine` trait — **8 methods**: `can`, `require`, `grant_role`, `revoke_role`, `has_role`, `count_users_with_role`, `purge_role`, `reload_in_memory` (Stage 5.0-A1.4). `AuthzError::ReloadError`. `test_support::{AllowAllAuthz, DenyAllAuthz}` under feature `test-support`. Trait-only.

### authz-casbin

`CasbinAuthz` — the canonical `AuthorizationEngine` impl. Two constructors: `CasbinAuthz::new(url)` and `CasbinAuthz::from_pool(PgPool)` (recommended). Raw SQL only against `casbin_rule`.

### audit (Stage 3e)

Trait-only `AuditLogger` — symmetric to `authz`:
- `AuditEvent { event_type, actor_id, actor_email, target_type, target_id, metadata }`; `id` and `occurred_at` DB-generated.
- `NoopAuditLogger` — always available.
- `events` module — 21 constants. All emitted as of Stage 3f.

### audit-pg (Stage 3e)

`PgAuditLogger::from_pool(PgPool)`. Sole writer of `audit_log`. `MIGRATOR` for standalone use (Stage 4.3c). `list_paged(limit, offset) -> Page<AuditRow>` (Stage 4.8).

### access

Sole owner of `permissions`, `roles`, `role_permissions`. `Role`, `Permission`, `RoleKey`, `AccessState`, `AccessError`. `AccessState::with_audit`. Role CRUD + `create_owner_role`. `registry` module (Stage 5.0-A1): `ResourceType`, `ResourceScope`, `bootstrap_resource_type(s)`, `bootstrap_all_core`, `register_resource_type`, `add_action`, `list_resource_types`.

### identity

Sole owner of `users`. `AuthUser`, `UserRecord` (with `password_hash`, `email_verified_at`, `password_changed_at`), validation, CRUD, idempotent `upsert_user`, `update_password_tx` (Stage 3d). Every SELECT derives `email_verified = (email_verified_at IS NOT NULL)`.

### authn

Auth mechanism on `identity`. `Authn::new` / `with_ttl` (default `NoopAuditLogger`) / `with_audit`. Methods: `register`, `login`, `issue_access_token`, `issue_refresh_token`, `rotate_refresh_token`, `revoke_refresh_token`, `revoke_family`, `revoke_all_user_tokens`, `verify_token`, `create_email_verification`, `verify_email`, `request_password_reset`, `reset_password`, `hash_password`. Emits 8 events. `login_failed` for both `InvalidCredentials` paths (`actor_id = NULL`, `actor_email = attempted`, no enumeration signal).

### saas

Business logic. `SaasState { pool, authz, access, audit }`; `SaasBuilder` (`with_authz`, `with_access`, `without_access`, `with_audit`); `CoreError` (incl. `EmailNotVerified`, `TenantSuspended`); services.

- `platform`: `create_tenant`, `provision_tenant`, `list_tenants_paged`, `suspend_tenant`, `activate_tenant`, `resolve_active_tenant`, `resolve_tenant`, `resolve_workspace`, `resolve_active_workspace`, `is_tenant_member`, `is_workspace_member`; `ActiveTenant`, `ActiveWorkspace` newtypes.
- `tenant`: `create_workspace` (4-arg, no owner), `create_workspace_with_owner` (6-arg).
- `access`: `assign_role`, `revoke_role`, `delete_role`, `update_role`, `create_role`, `list_roles_paged`, `list_permissions_paged`, `my_permissions`.

Emits: `tenant.created`, `tenant.suspended`, `tenant.activated`, `workspace.created`, `invitation.created` / `.accepted` / `.revoked`, `member.role_assigned` / `.revoked`, `member.role_changed`, `role.deleted`.

### db

PostgreSQL helper + migration runner. `MIGRATOR` (15 files) + `migrate_composed(pool, &[&Migrator])` + `CONSUMER_VERSION_FLOOR = 90_000_000_000_000` (Stage 5.0-A3). `migrate_with` deprecated.

### rate-limiter (Stage 4.8)

`RateLimiter` trait + `InMemoryRateLimiter` (default) + `RedisRateLimiter` (feature `redis`). `SimpleRateLimiter` — deprecated alias.

### saas-axum (Stage 5.0-A4)

Internal HTTP adapter. Consumer-facing via `rust-saas = { features = ["axum"] }`. Four entry-points: `build_app` (public-only), `build_app_with_protected(state, protected)`, `build_app_full(state)` (public + standard endpoints), `build_app_full_with(state, extra_protected)` (public + standard + custom, all under `csrf_guard → auto_refresh → auth_layer`). `RouteBinding` / `BindingScope` / `RouteBindings` / `PathPermissions` + `bindings::validate()` fail-fast in `build()`. Endpoints `/auth/{register,login,logout,refresh}`, `/my_permissions` (+ `/grouped`), `/resource_types`.

### rust-saas (meta-crate, Stage 4.0)

Features: `default` (no sqlx), `ssr` (all sqlx-backed crates), `hydrate` (= default), **`axum`** (= ssr + `saas-axum`). `migrate_all` / `migrate_extended` (Stage 5.0-A3).

### seed

Standalone binary. Bootstrap data + demo accounts (all email-verified). Wires real `PgAuditLogger` into both `AccessState` and `SaasState`.

### examples/saas-leptos

Reference consumer (single-dep since A7'.1: `rust-saas = { features = ["ssr", "rate-limiter-redis"] }` + `domain` hydrate-only). `main.rs` builds real `PgAuditLogger` + passes to `AccessState::with_audit`, `Authn::with_audit`, `SaasBuilder::with_audit`. **A7'.2: `main.rs` also calls `bootstrap_all_core` + `bootstrap_resource_types` (3 LMS types) at startup; `pages/platform.rs` has a "Resource Types" UI section (form + list) backed by `#[server] list_resource_types` / `register_resource`.** `GuardRoute` on `Resource`/`Suspense` (Stage 4.9). `auth_layer.rs` (Stage 4.9). `error.rs` maps errors to 400/401/403/404/409/429/500 (including `TenantSuspended` → 403 distinct message).

### examples/axum-minimal (Stage 3g, refactored Stage 5.0-A6)

**Pure Axum consumer, fork-free on `saas-axum` since Stage 5.0-A6.** Portability proof that the library contracts compose without Leptos.

- **Structure (after A6):** 3 files in `src/` — `lib.rs` (~32 LOC, `build_app(state) = build_app_full_with(state, extra)` with 7 consumer routes), `handlers.rs` (~206 LOC, 7 handlers + local `PaginationQuery`), `main.rs` (~41 LOC, `db::connect` → `db::migrate` → `AxumAppState::builder` → `axum::serve`). Total **278 LOC src** (was ~2000).
- **One library dependency:** `rust-saas = { path = "../../crates/rust-saas", features = ["axum"] }`. All other deps are system crates (`tokio`, `sqlx`, `anyhow`, `dotenvy`, `axum`, `serde`, `uuid`, `tracing`, `tracing-subscriber`).
- **Endpoints:** `/tenants` (GET+POST), `/workspaces` (GET+POST), `/documents` (GET+POST), `/audit` (GET) — via `build_app_full_with(state, extra)`, all under `csrf_guard → auto_refresh → auth_layer`. Standard endpoints (`/auth/*`, `/my_permissions*`, `/resource_types`, `/healthz`, `/readyz`, `/metrics`) come from `build_app_full_with` automatically.
- **14 E2E** (`tests/e2e.rs`, `#[sqlx::test(migrations = "../../crates/db/migrations")]`): smoke, auth flow, tenant+workspace, platform permission, CSRF rejection, suspension, audit access, rate-limit, pagination, `/readyz`, `/metrics`.
- **Behavioral contract preserved:** status codes, JSON shape (`{"items","total","limit","offset"}` for `/tenants`/`/workspaces`), cookie flow, error bodies (`{"error": "..."}`) are identical to the pre-A6 version. The migration is a structural refactor, not a behavior change.

**A6 deviations** (documented in `saas-25.md` §1.9): 8 system deps (not 5) — `serde`/`uuid` for handler DTOs, `tracing`/`tracing-subscriber` for `.init()`; no `with_bindings`/`with_prometheus` in `main.rs` (minimal path); `list_audit` does `my_permissions` + gate instead of `RouteBinding` on `/audit`. `minimal-lms` is the "custom resource types + custom bindings" reference; `axum-minimal` is the "minimal path" reference.

### examples/minimal-lms (Stage 5.0-A5)

**Fork-free Axum consumer** — DoD-артефакт Phase A (Axum path). 8 files, ~290 LOC without comments, 3 E2E green, `fmt --check` + `clippy -D warnings` clean.

- `Cargo.toml` — 8 `[dependencies]` (only `rust-saas` from workspace) + 4 dev-deps. `Cargo.lock` committed.
- `migrations/90000000000001_lms_tables.sql` — 4 tables. `enrollments` deliberately out of scope.
- `src/handlers.rs` — 4 handlers using `resolve_active_*` + `authz.require` (defense in depth).
- `src/lib.rs` — `build_app_full_with(state, extra_routes())`.
- `src/main.rs` — `migrate_composed` + `AxumAppState::builder(...).with_resource_types(&[...]).with_bindings([...]).build()`.
- `tests/e2e.rs` — 3 E2E.

Deviations from `saas-23.md §3` documented in A8 §5.7(i): 8 deps (not 5), 4 handlers (not 5), `build_app_full_with` (not `build_app_full(state).route(...)`), LOC ~486 raw / ~290 without comments.

## Development principles

- Keep authentication separate from authorization.
- Keep authorization separate from business logic.
- **Audit is best-effort, not a security boundary.** Failures are `tracing::warn!`; they never fail the business operation (ADR-0004 §2.4). Audit written **after** `COMMIT` in a separate transaction; ADR-0003 A-lite unchanged.
- Never trust client-supplied tenant or workspace identifiers without server-side validation.
- Always scope database queries by tenant or workspace.
- Treat UI visibility as convenience, not as a security boundary.
- **Roles are data, not code.** No built-in role enums.
- **`roles.key` is immutable.** Rename = delete + create.
- **Tenant suspension is enforced explicitly, not by middleware** (ADR-0002 rev.2). `resolve_active_tenant` in mutations; reads/cleanup stay available.
- **`suspend_tenant` / `activate_tenant` are idempotent.** Only on transition emits events.
- `saas` and `authn` do not know Leptos, Axum, or Casbin. `saas` does not know `permissions`/`roles`/`role_permissions` — those belong to `access`. `authn` does not depend on `lettre`.
- **`audit` (trait) does not depend on `sqlx`.** `audit-pg` owns `audit_log`. `NoopAuditLogger` always available.
- Library crates do not depend on `examples/*`.
- Server functions (and Axum handlers) resolve the actor through the example's `CurrentUser`; a missing actor is HTTP 401.
- Library errors (`CoreError`, `AuthnError`, `IdentityError`, `AccessError`) mapped to HTTP status codes in each example (`src/error.rs`); keep new variants covered. `AuditError` is **not** mapped — audit never propagates.
- Invitation / refresh / email-verification / password-reset raw tokens returned once and never persisted; only `token_hash` (SHA-256) stored. `NoopEmailSender` logs only recipient + skipped send — **never token**.
- **`authn::reset_password` is one-shot.** In one transaction: rewrites `password_hash`, bumps `password_changed_at`, expires all reset tokens, revokes all refresh families (`revoked_reason = "password_reset"`). No auto-login.
- **Access JWT claims `{ sub, iat, exp }`.** Address + `email_verified` resolved from `users` on `verify_token`.
- **Addressed invitations (Stage 3c).** Verified-first (`EmailNotVerified`), then case-insensitive email match (`Forbidden`). Link invitations skip both.
- **`saas::member::change_role` performs `assign` before `revoke`** (over-permissioning recoverable by retry).
- **`saas::member::{change_role, remove_role}` owner guard.** Last holder of `protected` role cannot be removed. Reads `casbin_rule`.
- **`saas::member::{change_role, remove_role}` serialize owner guard** with `pg_advisory_xact_lock` (Stage 3h, ADR-0003 §2.3).
- **`authz-casbin::grant_role` idempotent on `p`-rows.** `has_policy` pre-check + `casbin_rule_unique_idx` (Stage 3h).
- **`saas::access::delete_role` cleans up `casbin_rule` (g+p), `*_members`, `roles` row** in retry-safe steps.
- All library crates in reference apps + `seed` share one `PgPool`.
- `saas-leptos` `auto_refresh` on protected router; `axum-minimal` on protected router; `minimal-lms` via `build_app_full_with`.
- **SMTP send timeout 10 seconds** (in `saas-leptos`). Hydrate host check: `cargo check --features hydrate` catches type-level errors, not wasm-only; full `cargo leptos watch` part of merge checklist.
- **Audit events constants in `audit::events`.** Adding a new event is a source change (no migration); per-event `metadata` free-form JSONB. `event_type` is `text` (not enum) — extensible without migration.
- **`resource_types` declared, not enforced.** `scope` is a hint. Enforcement in `casbin_rule.p.v1`. Runtime registration via `access::registry`; `reload_in_memory()` refreshes current process.
- **`build_app_full_with` is the fork-free entry-point.** Consumer-supplied protected routes get the same `csrf_guard → auto_refresh → auth_layer` chain as the standard endpoints. `.route(...)` on `build_app_full(state)`'s return value does **not** accept handlers with `State<Arc<AxumAppState>>` (structure: `Router<()>` after `.with_state(state)`).
- **`bootstrap_*` in `main.rs` is the recommended startup pattern.** `examples/saas-leptos` (A7'.2) and `examples/minimal-lms` (A5) both call it after `CasbinAuthz::from_pool`, before `SaasBuilder`. Idempotent; safe on every start. `register_resource_type` (runtime, permission-checked) is the admin-UI variant.

## Roadmap

- Stage 1 (done): typed error mapping, `CurrentUser`, mock `AuthorizationEngine`, integration tests.
- Stage 1.5 / 1.1 / 2a / 2b / 2e / 2e.1 / 2c / 2d (done): see `saas-appendix-a-changes.md`.
- Stage 3.0 (done): ADRs 0002/0003/0004.
- Stage 3a (done): UX 2.5.
- Stage 3b (done): email verification + claims cleanup.
- Stage 3c (done): addressed invitations.
- Stage 3d (done): password reset.
- Stage 3e (done): Audit log.
- Stage 3f (done): Platform admin + tenant suspension.
- Client route guards follow-up (done): `RouteGuard` + `GuardRoute` + `RequireAuth`/`RequirePermission`/`RequireAnyPermission`. SSR-correct — Stage 4.9.
- Stage 3g (done): `axum-minimal`.
- Stage 3h (done): `has_policy` pre-check; `casbin_rule_unique_idx`; advisory lock; `PermsCache`.
- Stage 4.0 (done): meta-crate, `[workspace.package]`, `COMPATIBILITY.md`, `delete_role_emits_role_deleted`, `PermsCache::invalidate_all()`, `domain` removed from `authz-casbin`.
- Stage 4.1 (done): `verify_token` iat check; cookie; CSRF; `AuthLayer`.
- Stage 4.2 (done, breaking): error isolation.
- Stage 4.3 (done): `test-support`; `migrate_with` + `audit-pg::MIGRATOR`.
- Stage 4.4a (done): `/healthz`.
- Stage 4.4b (partial): Dockerfile + WASM bundle (1.7 MB; target 400 KB not met).
- Stage 4.5 (done): §4.21/§4.22/§4.23 fixes; `clock_timestamp()`; `role.updated` diff.
- Stage 4.6 (done): CI + `cargo-deny` + `rust-toolchain.toml` + `smoke.sh`.
- Stage 4.7 (done): E2E HTTP tests (both examples).
- Stage 4.8 (done): pagination + `rate-limiter` crate (ADR-0005).
- Stage 4.9 (done): SSR-correct guards + `AuthLayer` в `saas-leptos` (ADR-0006).
- Stage 4.10 (done): `/readyz` + `/metrics` + `#[instrument]` (ADR-0007).
- Stage 4.11 (done): close-out.
- **Stage 5.0 Phase A part 1 (done):** A1 Resource Registry (B2/B3/B4 closed); A2 `without_access` + `create_workspace` split (B8/B9/B10); A3 `migrate_composed` (B1 closed).
- **Stage 5.0 Phase A part 2 (done):** A4.0–A4.5 `saas-axum` (B5/B6/B7 closed). PR-1 (state + builder + `build_app`), PR-2 (`RouteBindings` + `auth_layer` + `build_app_with_protected` + `/readyz`), PR-3 (endpoints + `build_app_full` + `deny.toml` wrappers).
- **A4.6 (done):** `build_app_full_with(state, extra_protected)` — additive fork-free entry-point.
- **A5 (done, PR #36):** `examples/minimal-lms` — DoD-артефакт Phase A (Axum path). **All 10 pluggability blockers (B1–B10) closed.**
- **A6 (done):** `examples/axum-minimal` → `saas-axum` — 278 LOC src (was ~2000), 3 files in `src/`, 1 library dependency `rust-saas = { features = ["axum"] }`, 14/14 E2E green, `fmt --check` + `clippy -D warnings` clean.
- **A7'.1 (done):** `saas-leptos` single-dep — `Cargo.toml` (one workspace dep `rust-saas = { features = ["ssr", "rate-limiter-redis"] }`) + `domain` hydrate-only; `README.md` "starter template"; 15/15 E2E; `fmt --check` + `clippy -D warnings` clean.
- **A7'.2 (done, this stage):** `saas-leptos` starter template — `bootstrap_all_core` + `bootstrap_resource_types` in `main.rs`; `#[server] list_resource_types` / `register_resource` + UI form on `/platform`; **18/18 E2E** (was 15 — +3 bootstrap/register tests); `fmt --check` + `clippy -D warnings` clean. Consumer-only; 0 lines changed in `crates/*`.
- **A8 (next):** docs (`saas-external-02.md`, `ADR-0008`, `ADR-0009`, `CHANGELOG`, `README`, Appendix B) + CI jobs for both examples (`minimal-lms` + `axum-minimal`).
- **A9:** DoD Phase A, tag `v0.3.0`.
- **Stage 5.1+ (open):** ABAC/ReBAC (Phase B); OIDC + TOTP + WebAuthn (Phase C); RLS + cleanup TTL + escape hatch + polish (Phase D).

## Pluggability: what can be replaced, what cannot

`rust-saas` is **not** a hexagonal framework with a port on every axis. It is a PostgreSQL-backed core with **three ports** (`authz`, `audit`, `rate-limiter`) and concrete implementations elsewhere.

### Ports (traits + implementations)

| Concern | Trait | Default impl | Replace without forking? |
|---|---|---|---|
| Authorization | `authz::AuthorizationEngine` | `authz-casbin::CasbinAuthz` | **yes** — e.g. OPA, Keycloak |
| Audit | `audit::AuditLogger` | `audit-pg::PgAuditLogger` | **yes** — Kafka, file, OTel |
| Rate limiter | `rate-limiter::RateLimiter` | `InMemoryRateLimiter` / `RedisRateLimiter` | **yes** — Redis, custom store |

### Concrete dependencies (replacement = fork)

| Concern | Concrete | Replacement |
|---|---|---|
| Identity storage | `identity::*` (`users`) | fork `identity` + edits in `authn`, `saas` |
| Auth mechanism | `authn::Authn` | fork `authn` + edits in `saas`, examples |
| Role storage | `access::AccessState` (`roles`, `permissions`, `role_permissions`, `resource_types`) | fork `access` + edits in `saas` |
| SaaS business logic | `saas::*` | fork `saas` |
| Database | `PgPool` everywhere | non-goal |

### Composition & migrations

- **Full schema:** `db::migrate` (15 migrations in `crates/db/migrations/`).
- **Composed schema:** `db::migrate_composed(pool, &[&Migrator])` merges consumer migrations with the workspace set. Version floor: `CONSUMER_VERSION_FLOOR = 90_000_000_000_000`.
- **Per-crate:** `audit-pg::MIGRATOR` (2 files) — worked example. A consumer picks **one** path per database; `migrate_composed` handles "rust-saas + consumer" correctly (workspace set + consumer set validated before SQL).
- **`examples/minimal-lms/migrations/90000000000001_lms_tables.sql`** — worked example consumer migration (Stage 5.0-A5).

### Stack

- Library crates do not depend on Leptos, Axum, HTTP, JWT delivery, or SMTP. Examples use the same public contracts.
- Email delivery (`EmailSender`) is example-local. CSRF is example-local. Cookies are example-local. `AuthLayer` is example-local.
- **`saas-axum` HTTP adapter** — internal crate; consumer-facing via `rust-saas::features = ["axum"]`. Four entry-points.

## Non-goals

Explicitly **out of scope** for this reference:

1. **Multi-DB.** PostgreSQL only.
2. **Generic DAL / repository traits over `PgPool`.** `PgPool` in public signatures is deliberate.
3. **`RoleStore` / `UserStore` / `Authn` trait / `saas` split (S1–S4).** Replacement is a fork; the three ports cover common cases.
4. **Full hexagonal architecture.** Three ports, not "everything is a trait".
5. **Runtime pluggability (dynamic dispatch for everything).** `Arc<dyn Trait>` only for `AuthorizationEngine`, `AuditLogger`, `RateLimiter`.
6. **HTTP-framework-specific features in the library.** CSRF, cookies, rate limiting, IP/user-agent, email transport — all at the consumer.
7. **`no_std` / zero-copy.**
8. **Distributed transactions / 2PC.** ADR-0003 (A-lite) records the trade-off.

## Compatibility

All `crates/*` share **one version** (`[workspace.package] version = "0.3.0"`). Consumers must pin every path / git dependency to the same revision.

## License

See the `LICENSE` file in the root of the repository.