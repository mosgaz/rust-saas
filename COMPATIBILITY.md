# Compatibility

The `crates/*` workspace follows one rule: **all crates share one version
and one revision**. Do not mix, for example, `access 0.1.0` with `saas
0.2.0`. `[workspace.package]` in the root `Cargo.toml` enforces the
version at the source; consumers must pin every path / git dependency to
the same tag.

**Current version:** `0.3.0` (unreleased — Phase A / Stage 5.0 is
in progress; `Cargo.toml` → `[workspace.package]` reflects `0.3.0` so a
consumer who pulls `main` sees cargo's incompatibility warning
immediately, but the `v0.3.0` tag is applied only after Phase A's DoD
(`# Stage 5 — план реализации.txt` §4.A9) is closed). See the `0.3.0`
section below.

## Versioning policy

- **Patch (`0.x.Y`)** — bugfixes, internal improvements. No public-API
  change.
- **Minor (`0.X.0`)** — new functionality; additive public API; may
  include **breaking changes** before `1.0` (SemVer allows this in the
  `0.x` line, and this project follows it explicitly because the crates
  are pre-stable).
- **Major (`X.0.0`)** — out of `0.x`; full SemVer.

## Breaking changes so far

### 0.1.0 — initial release

Baseline for `0.2.0`. No documented breaking changes; the crate set,
error types, and public API as of Stage 3h.

### 0.2.0 — Stage 4.1 (iat-vs-`password_changed_at`)

`authn::verify_token` now rejects access JWTs whose `iat` claim is older
than `users.password_changed_at`. Before this, a token issued *before* a
password reset remained valid until its `exp` (up to
`ACCESS_TOKEN_TTL_MINUTES`, default 15 min). After this, it is rejected
as `AuthnError::TokenInvalid` (same variant as "signature mismatch" — the
error mapping in `error.rs` is unchanged).

**Migration.** A consumer that intentionally relied on old access tokens
surviving a password change should re-issue access + refresh tokens after
`authn::reset_password` / a successful login. The normal flow is
unaffected: a freshly issued token has `iat >= password_changed_at`.

**Why.** A stolen access token could otherwise survive a password reset
for up to `access_ttl`. The check closes that window.

### 0.2.0 — Stage 4.2 (error isolation)

Public error types no longer leak `sqlx::Error` or `IdentityError` into
consumer crates:

- `access::AccessError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `identity::IdentityError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `authn::AuthnError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `saas::CoreError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `authn::AuthnError::Identity(#[from] IdentityError)` →
  `AuthnError::Identity(IdentityErrorKind)` where
  `IdentityErrorKind = { NotFound, DuplicateEmail, Validation, Internal }`.

**Migration.**

- A consumer that matched `Db(e)` and used `e` as `sqlx::Error` now sees
  `String`: `tracing::warn!(error = %e, …)` still works; anything that
  inspected `sqlx::Error` fields must move that inspection inside the
  crate that produced the error (`access`, `identity`, `authn`, `saas`).
- A consumer that matched `AuthnError::Identity(inner)` where `inner` was
  `IdentityError` must now match `IdentityErrorKind`. The four variants
  cover the public cases; `Internal(String)` carries the original
  `Display` for logging.

**Why.** The library must not require a consumer to depend on `sqlx`
just to pattern-match an error, nor to depend on `identity` just to
handle a login failure. `audit-pg` (`AuditError::Internal(String)`)
already followed this pattern; Stage 4.2 applies it to the remaining
error types.

### 0.2.1 — Stage 4.8 (pagination + distributed rate limiter)

**Additive** public API (no breaking changes; `0.2.0` contracts preserved):

- `domain::Page<T>` — DTO for paginated results (`items`, `total`, `limit`, `offset`).
- `access::list_permissions_paged`, `access::list_roles_paged` — `LIMIT`/`OFFSET` pagination.
- `saas::platform::list_tenants_paged`, `saas::member::list_paged`, `saas::access::{list_roles_paged, list_permissions_paged}`.
- `audit_pg::PgAuditLogger::list_paged`.
- New crate `crates/rate-limiter`: `RateLimiter` trait, `InMemoryRateLimiter` (default), `RedisRateLimiter` (feature `redis`).

**Deprecations** (not removed until Stage 5+):

- `access::list_permissions`, `access::list_roles`, `saas::platform::list_tenants`, `saas::member::list`, `saas::access::{list_roles, list_permissions}`, `PgAuditLogger::list` — use the `_paged` variants with `(i64::MAX, 0)` for "all rows".
- `rate_limiter::SimpleRateLimiter` — alias for `InMemoryRateLimiter`.

**Why.** Stage 4.8 closes the two production-readiness blockers from `saas-21.md` §4: unbounded `list_*` (UI freeze on large datasets) and per-process rate limiting (multi-replica bypass). Additive API keeps `0.2.x` compatible; `0.2.1` is a patch bump per `COMPATIBILITY.md` policy.

### 0.2.2 — Stage 4.9 + 4.10 (SSR-correct guards, AuthLayer, observability)

**Additive** public API (no breaking changes; `0.2.0` / `0.2.1`
contracts preserved):

- `#[instrument]` spans on mutation paths in `authn`, `saas::platform`,
  `saas::member`, `access::role`. Fields: `operation`, `actor_id`, plus
  `domain` / `role_key` / `tenant_id` / `user_id` where relevant.
  Secrets and PII are `skip`ped (no observable change in public API
  or error types).
- `crates/*` unchanged at the API level; Stage 4.9 and 4.10 are
  consumer-local changes (`/readyz`, `/metrics`, `auth_layer`,
  `GuardRoute` on `Resource`/`Suspense`) plus additive `tracing`
  instrumentation.

**Why.** Stage 4.9 closed two UX defects (SSR placeholder / CLS for
guarded routes; no defense-in-depth middleware in `saas-leptos`).
Stage 4.10 closed production-readiness (deep `/readyz`, `tracing`
spans, Prometheus `/metrics`). Both are non-breaking; patch bump
per `COMPATIBILITY.md` policy.

**Note.** This entry also covers the `0.2.1` release (Stage 4.8): the
`0.2.1` version was declared in `COMPATIBILITY.md` but not published
as a tag; `0.2.2` is the first tagged release after `0.2.0`.

### 0.3.0 — Stage 5.0 (Phase A: A1–A6)

Breaking changes and new API introduced across `crates/*` in Phase A
(`crates/db/migrations/20261130*`, A1.4, A2.2a, A2.2c, A4.0–A4.6, A5,
A6). Phase A's DoD (`# Stage 5 — план реализации.txt` §4.A9) is **not**
yet closed; this entry documents what has already landed on `main` under
`0.3.0`.

**New public API (additive):**

- **A1 (Resource Registry):**
  - `authz::AuthorizationEngine::reload_in_memory() -> Result<(), AuthzError>` — refresh in-memory policy after an external `INSERT INTO casbin_rule` (e.g. the `owner_sync` trigger). No-op for engines without in-memory state.
  - `authz::AuthzError::ReloadError(String)` — new variant.
  - `access::AccessError::UnknownResourceType { name }` — new variant.
  - `access::AccessError::ScopeMismatch { name, existing, requested }` — new variant.
  - `access::registry` module: `ResourceType`, `ResourceScope`, `bootstrap_resource_type`, `bootstrap_resource_types`, `bootstrap_all_core`, `register_resource_type`, `add_action`, `list_resource_types`.

- **A2 (`without_access` + `create_workspace` split):**
  - `saas::SaasBuilder::without_access()` — build a `SaasState` without `AccessState`. `authz` is still required.
  - `saas::tenant::create_workspace(actor, tenant_id, name)` — new 4-arg form (no owner, no `access::*`).
  - `saas::platform::{resolve_tenant, resolve_workspace, resolve_active_workspace, is_tenant_member, is_workspace_member}` + `ActiveWorkspace` newtype.

- **A3 (`migrate_composed`):**
  - `db::migrate_composed(pool, &[&Migrator])` — apply the workspace set + consumer sets, in one run.
  - `db::MIGRATOR` — public static (`sqlx::migrate!("./migrations")` of `crates/db/migrations/`).
  - `db::CONSUMER_VERSION_FLOOR: i64 = 90_000_000_000_000` — recommended version floor for consumer migrations.
  - `rust_saas::migrate_all(pool)` / `rust_saas::migrate_extended(pool, &consumer)` — convenience wrappers under feature `ssr`.

- **A4 (`saas-axum` HTTP adapter; feature `axum`):**
  - **New crate `crates/saas-axum`** — internal HTTP adapter. Consumer-facing via `rust-saas = { features = ["axum"] }`.
  - **New feature `axum`** on the `rust-saas` meta-crate: `["ssr", "dep:saas-axum"]`.
  - **Re-exports under `rust_saas::*` (feature `axum`):** `AxumAppState`, `AxumAppStateBuilder`, `build_app`, `build_app_full`, `build_app_with_protected`, `AppError`, `CurrentUser`, `CookieConfig`, `EmailSender`, `NoopEmailSender`, `EmailResult`, `RouteBinding`, `BindingScope`, `RouteBindings`, `PathPermissions`, `OwnedAuthzTarget`. Plus everything under `ssr`.
  - **Four entry-points** (all return `Router`):
    - `build_app(state)` — public-only (`/healthz`, `/readyz`, `/metrics`, 404 fallback).
    - `build_app_with_protected(state, protected)` — public + custom protected routes, with `csrf_guard → auto_refresh → auth_layer`.
    - `build_app_full(state)` — public + standard endpoints (`/auth/*`, `/my_permissions*`, `/resource_types`) + middleware chain.
    - `build_app_full_with(state, extra_protected)` — public + standard + custom, all under the middleware chain. `extra_protected` is `.merge(…)'d **before** the `route_layer` chain.
  - **Standard endpoints** (via `build_app_full` / `build_app_full_with`): `POST /auth/register` (public, rate-limited 3/h per email), `POST /auth/login` (public), `POST /auth/logout` (public), `POST /auth/refresh` (protected), `GET /my_permissions?domain=…` (protected, `Vec<String>`), `GET /my_permissions/grouped?domain=…` (protected, `BTreeMap<String, Vec<String>>`), `GET /resource_types` (protected).
  - **`deny.toml` wrappers:** `axum` / `axum-extra` / `tower-http` / `matchit` / `hyper` covered; `lettre` — bare ban.

- **A5 (`examples/minimal-lms`):**
  - **New example** `examples/minimal-lms/` — fork-free Axum consumer, DoD-артефакт Phase A (Axum path). 8 files, ~290 LOC without comments, 3 E2E.
  - **No library API added** — consumer-only. Demonstrates `build_app_full_with`, `migrate_composed`, `with_resource_types`, `with_bindings`, `RouteBinding::{read, mutating}`, `BindingScope::{WorkspaceFromPath, TenantFromPath}`.

- **A6 (`examples/axum-minimal` → `saas-axum`):**
  - **No library API added or changed.** A6 is a consumer-only structural refactor.
  - `examples/axum-minimal/` after A6: 3 `src/*.rs` (278 LOC, was ~2000), one workspace dep `rust-saas = { features = ["axum"] }`, 14/14 E2E green, `fmt --check` + `clippy -D warnings` clean.
  - Behavioral contract preserved: status codes, JSON shape (`{"items","total","limit","offset"}` for `/tenants`/`/workspaces`), cookie flow, error bodies (`{"error": "..."}`) — identical to pre-A6.
  - `saas-axum::pagination::PaginationQuery` deliberately **not** re-exported through `rust-saas`; `axum-minimal` keeps a local 15-line `PaginationQuery` in `handlers.rs`. If consumers need it later, promote to `rust_saas::saas_axum::pagination` (additive).

**Breaking:**

1. **`authz::AuthorizationEngine::reload_in_memory()`** — every impl must implement it (`Ok(())` for engines without in-memory state). `AllowAllAuthz` / `DenyAllAuthz` from `authz::test_support` already ship it; a consumer's custom impl needs one more method.

2. **`access::AccessError` gained two variants** (`UnknownResourceType` and `ScopeMismatch`). Any `match` on `AccessError` is now non-exhaustive. Both new variants map to HTTP 400 (validation) in the reference examples. Same for `saas::CoreError` (its `From<AccessError>` maps both to `CoreError::Validation`).

3. **`saas::SaasState::access()`** — signature changed from `&AccessState` to `Result<&AccessState, CoreError>`. Every call site needs `?` (or `.expect(..)` in tests). Returns `CoreError::Internal("RBAC not configured…")` on a `without_access()` build.

4. **`saas::SaasBuilder::build()`** — behaviour change. Before: required `with_access(..)`. Now: requires *either* `with_access(..)` *or* `without_access()`, or fails with `Internal("access state is required…")`. A builder that already called `with_access(..)` is unaffected (the check passes).

5. **`saas::tenant::create_workspace`** — signature split. The old 6-arg form (`actor, tenant_id, name, owner, owner_role_key`) is renamed to `create_workspace_with_owner`. The old name now refers to a new 4-arg form (`actor, tenant_id, name`) that does not assign an owner and does not require `AccessState`. Consumers who want owner assignment on creation use `create_workspace_with_owner`.

6. **`db::migrate_with` — `#[deprecated]`** (not removed). Use `db::migrate_composed(pool, &[&Migrator])` for the "rust-saas + consumer migrations" case. `migrate_with` remains for per-crate sets that do not need the rust-saas schema at all.

**Migration.**

- **`without_access()` users.** New consumers that want RBAC-disabled builds must supply their own `AuthorizationEngine` impl (e.g. `AlwaysAllow` in ~5 lines) and call `without_access()` after `with_authz(..)`.

- **`create_workspace` call sites.** Rename to `create_workspace_with_owner` (mechanical; 20 call sites in this repo, a consumer sees the same). 4-arg `create_workspace` is available for "bare" workspace creation without an owner (used by `without_access()` builds).

- **`state.access()` call sites.** Add `?` (or `.expect(..)` in tests). Mechanical; 21 call sites in this repo.

- **Exhaustive `match` on `AccessError` / `AuthzError` / `CoreError`.** Add arms for the new variants. The reference examples (`examples/*/src/error.rs`) already do.

- **Custom `AuthorizationEngine` impl.** Add `async fn reload_in_memory(&self) -> Result<(), AuthzError> { Ok(()) }` (no-op if the engine has no in-memory state).

- **Migration path for consumer migrations.** Replace `db::migrate_with(&pool, &[…])` with `db::migrate_composed(&pool, &[…])`. Composed set validates version collisions and version floor (`> max(rust-saas version)`). Use `db::CONSUMER_VERSION_FLOOR` (`90000000000000`) as the start of your consumer version namespace.

- **Database.** New migrations (`20261130000001_resource_types.sql`, `20261130000002_owner_sync_casbin.sql`, `20261130000003_legacy_import_and_fk.sql`) must be applied. Consumer databases that predate this set and contain custom `permissions.resource` values (`course`, `deal`, …) get them auto-imported as `custom:legacy`; `resource:manage` is added and propagated to `platform` owner by the fixed trigger. A running replica still needs `authz.reload_in_memory()` after the migration to see the new permissions — the standard practice is `migrate_composed` before process start.

- **`axum` feature (additive — no migration).** Consumers that want the standard `saas-axum` endpoints add `rust-saas = { …, features = ["axum"] }`. Consumers that do not — no change (`ssr` / `hydrate` / default behave exactly as before).

- **`build_app_full_with` (additive — no migration).** `build_app_full(state)` is unchanged (signature, semantics, behaviour). Consumers using `.route(...)` on the return value of `build_app_full` must be aware that `.route(...)` after `.with_state(state)` does not accept `State<Arc<AxumAppState>>` — this was true before A4.6, it is still true after. To add custom routes with the standard middleware chain, use `build_app_full_with(state, extra_routes)` (A4.6).

- **A6 (consumer-only — no library migration).** The `examples/axum-minimal` refactor does not change any library API, error type, or wire contract. A consumer who was using `examples/axum-minimal` as a template should treat its post-A6 layout (`lib.rs` = `build_app_full_with`, `handlers.rs` = 7 handlers + local `PaginationQuery`, `main.rs` = `db::connect` → `db::migrate` → `AxumAppState::builder().build()`) as the reference for "pure Axum, minimal path". For "custom resource types + custom bindings", see `examples/minimal-lms` (A5).

- **A7'.1 (consumer-only — no library API).** `examples/saas-leptos` becomes a single-workspace-dependency reference: one workspace dep `rust-saas = { path = "../../crates/rust-saas", features = ["ssr", "rate-limiter-redis"], optional = true }` + a direct `domain = { path = "../../crates/domain", default-features = false }` (hydrate-only; `rust-saas` is `optional = true`, so `rust_saas::*` is unavailable in hydrate-compiled code — `domain` stays direct). All `use`-lines in `src/*.rs` / `src/pages/*.rs` reference `rust_saas::*` instead of the individual crates. `README.md` is a starter template ("copy, rename, extend"). Code does not change (only `Cargo.toml` + `use`-lines + `README.md`); 15/15 E2E green; `cargo check --features ssr` and `cargo check --features hydrate` green. No library API change — the `rate-limiter-redis` feature and the direct `domain` dep were already available; consumer-only.

**Why.** Phase A closes all 10 pluggability blockers (B1–B10) and adds a fork-free Axum consumer path. Breaking changes are mechanical (5 signature changes + 1 new required method) and documented individually above. `examples/minimal-lms` is the reference consumer for "custom resource types + custom bindings"; `examples/axum-minimal` (post-A6) is the reference for "pure Axum, minimal path".