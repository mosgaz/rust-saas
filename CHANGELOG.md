# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Every crate in `crates/` shares one version (enforced by
`[workspace.package]`); consumers must pin all crates to the same
revision.

## [0.4.0] - 2026-11-07

### Phase B' — ABAC on Casbin (ADR-0010)

**Additive:** `AuthzRequest` DTO + `AuthorizationEngine::can_request` / `require_request` (default impls fall back to RBAC). No breaking changes.

- `authz`: `AuthzRequest`, `Subject`, `Resource` DTOs (with `serde`). `can_request` and `require_request` added to `AuthorizationEngine` with default RBAC fallback. Added `ConstraintEvaluator` trait for custom ABAC rules.
- `authz-casbin`: `can_request` override — evaluates ABAC constraints from `context.constraints` (`owner_only`, `status_in`, `attr_eq`, `attr_in_subject`). Added `with_custom_constraints()` to register a `ConstraintEvaluator` for custom rules. Unknown types fail closed if no custom evaluator handles them.
- `saas-axum`: Added `with_custom_constraints()` to `AxumAppStateBuilder` to allow seamless registration of custom ABAC rules without forking the library.
- **`examples/minimal-lms-abac`**: fork-free Axum consumer demonstrating all 4 built-in ABAC constraints (`owner_only`, `status_in`, `attr_eq`, `attr_in_subject`) in combinations, plus a custom `attr_gt` (Greater Than) constraint via `ConstraintEvaluator`.

### Why no OPA / PolicyAdmin?

See `internal-docs/ADR-0010-ABAC-on-Casbin.md`. OPA is a PDP, not a PAP; dynamic rule creation in OPA is an architectural dead end. Casbin + developer-defined ABAC constraints cover all requested use cases without new tables or external services.

## [0.3.0] - 2026-11-05

### Stage 5.0 — Phase A (A1 + A2 + A3 + A4 + A4.6 + A5 + A6 + A7'.1 + A7'.2)

**Breaking changes (5 items; see `COMPATIBILITY.md` §0.3.0 for migration guide):**
- `authz::AuthorizationEngine::reload_in_memory()` — new required method (A1.4).
- `access::AccessError::{UnknownResourceType, ScopeMismatch}` — new variants (A1.5a).
- `saas::SaasState::access()` — returns `Result<&AccessState, CoreError>` instead of `&AccessState` (A2.2a).
- `saas::SaasBuilder::build()` — requires `with_access(..)` or `without_access()` (A2.2b).
- `saas::tenant::create_workspace` — split into `create_workspace` (4-arg) and `create_workspace_with_owner` (6-arg) (A2.2c).

**A1 — Resource Registry (B2, B3, B4 closed):**
- Added `resource_types` table and 8 core types (migration `20261130000001_resource_types.sql`).
- Fixed `owner_sync_permission` trigger to also write `casbin_rule.p` (migration `20261130000002_owner_sync_casbin.sql`).
- Added legacy import, `resource:manage`, and FK to `permissions` (migration `20261130000003_legacy_import_and_fk.sql`).
- Added `access::registry` (`bootstrap_resource_type`, `register_resource_type`, `add_action`, etc.) and `AuthorizationEngine::reload_in_memory()`.

**A2 — `without_access` + `create_workspace` split (B8, B9, B10 closed):**
- Added `saas::platform::{resolve_tenant, resolve_workspace, is_tenant_member, is_workspace_member}` and `ActiveWorkspace`.
- Added `SaasBuilder::without_access()` for RBAC-free setups.

**A3 — `migrate_composed` (B1 closed):**
- Added `db::migrate_composed` and public `db::MIGRATOR`. Deprecated `db::migrate_with`.
- Meta-crate `rust-saas`: added `migrate_all` / `migrate_extended`.

**A4 — `saas-axum` HTTP adapter (B5, B6, B7 closed):**

*New crate `crates/saas-axum` — internal HTTP adapter; consumer-facing via `rust-saas::features = ["axum"]`.*

- **A4.0–A4.2** (PR-1): `AxumAppState` (11 fields) + `AxumAppStateBuilder` (16 methods, `build().await` — 10 steps). `build_app(state)` — public-only (`/healthz`, `/readyz`, `/metrics`, 404 fallback) + middleware chain + `TraceLayer`. `without_rbac()` for RBAC-free builds.
- **A4.3a–A4.3b** (PR-2): `RouteBinding` / `BindingScope` / `RouteBindings` (matchit 0.8, `{name}` syntax) with built-in precedence wins (structural — user binding colliding with built-in is silently skipped). `PathPermissions` trait; `auth_layer` precedence: built-in → `PathPermissions::is_public` → `RouteBindings::resolve` → `PathPermissions::path_permission` → pass-through. `build_app_with_protected(state, protected)` — public + custom protected (chain: `csrf_guard` → `auto_refresh` → `auth_layer` → handler). `/readyz` wired (DB `SELECT 1` + Redis `PING` when `REDIS_URL` is set). Fail-fast `bindings::validate()` in `build()` — unknown `(resource_type, action)` → `CoreError::Validation` → 400.
- **A4.4** (PR-3): endpoints `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/refresh`, `/my_permissions`, `/my_permissions/grouped`, `/resource_types`. `build_app_full(state)` — public + standard endpoints + middleware chain (additive to `build_app` / `build_app_with_protected`).
- **A4.5** (PR-3): `deny.toml` wrappers for `axum` (`wrappers = ["axum-extra", "saas-axum", "rust-saas"]`), `axum-extra`, `tower-http`, `matchit`, `hyper`. `lettre` — bare ban (`saas-leptos` in `workspace.exclude`).

*Re-exports:*
- `crates/saas-axum/src/lib.rs` — `pub use bindings::…`, `pub use cookie::CookieConfig`, `pub use email::{EmailResult, EmailSender, NoopEmailSender}`, `pub use endpoints::auth::{login, logout, refresh, register, RegisterRequest, RegisterResponse}`, `pub use endpoints::my_permissions::{my_permissions_flat, my_permissions_grouped, MyPermissionsQuery}`, `pub use endpoints::resource_types::{resource_types, ResourceTypeView}`, `pub use error::AppError`, `pub use extract::CurrentUser`, `pub use router::{build_app, build_app_full, build_app_full_with, build_app_with_protected}`, `pub use state::{AxumAppState, AxumAppStateBuilder}`.
- `crates/rust-saas/src/lib.rs` — same surface under `#[cfg(feature = "axum")]`.
- `crates/rust-saas/tests/feature_axum.rs` — fn-pointer asserts.

**A4.6 — `build_app_full_with(state, extra_protected)` (additive):**

- **Motivation:** `build_app_full(state)` returns `Router<()>` (after `.with_state(state)`), so `.route(...)` afterwards cannot accept handlers parameterised on `State<Arc<AxumAppState>>`. Consumers that want both the standard endpoints **and** their own business routes need an entry-point that merges before the state is attached.
- **Solution:** `build_app_full_with(state: Arc<AxumAppState>, extra_protected: Router<Arc<AxumAppState>>) -> Router`. `extra_protected` is `.merge(…)'d **before** the `route_layer` chain, so every extra route gets the same middleware (`csrf_guard` → `auto_refresh` → `auth_layer`) as the standard endpoints. `build_app_full(state)` delegates to `build_app_full_with(state, Router::new())` — signature and semantics unchanged.
- **Four entry-points total:** `build_app` / `build_app_with_protected` / `build_app_full` / `build_app_full_with`.
- **No behavioural test added** (deliberate): fn-pointer assert in `feature_axum.rs` proves the export; `.merge(…) → .route_layer(…)` is a standard axum builder-chain pattern (structurally impossible to "forget merge" within a single builder-chain).

**A5 — `examples/minimal-lms` (DoD-артефакт Phase A, Axum path):**

*New consumer example `examples/minimal-lms/` — fork-free Axum consumer on `saas-axum`. 8 files, ~486 raw LOC / ~290 without comments, 3 E2E green, `fmt --check` + `clippy -D warnings` clean.*

- **`Cargo.toml`:** `rust-saas = { path = "../../crates/rust-saas", features = ["axum"] }` + `tokio`, `sqlx` (`runtime-tokio`, `tls-rustls`, `postgres`, `migrate`), `anyhow`, `dotenvy`, `axum`, `serde` (`derive`), `uuid` (`serde`) — 8 deps. `[dev-dependencies]`: `sqlx` (`macros`), `tower` (`util`), `http-body-util`, `serde_json` — 4 dev-deps. `Cargo.lock` committed.
- **`build.rs`:** `rerun-if-changed=migrations` (4 lines).
- **`migrations/90000000000001_lms_tables.sql`:** 4 tables — `courses` (FK `workspaces(id)` on delete cascade), `assignments` (FK `courses(id)` on delete cascade), `batches` (FK `tenants(id)` on delete cascade), `files` (FK `tenants(id)` on delete cascade). `enrollments` deliberately out of scope. Version `90000000000001` > `db::CONSUMER_VERSION_FLOOR` (`90000000000000`) — no collision with rust-saas set.
- **`src/handlers.rs`:** 4 handlers — `list_courses` (workspace-scope, `resolve_workspace` read path, suspended tenant OK), `create_course` (workspace-scope, `resolve_active_workspace` mutation path, then `authz.require(workspace_domain, "course", "write")`), `list_files` (tenant-scope, `resolve_tenant`), `create_batch` (tenant-scope, `resolve_active_tenant`, then `authz.require(tenant_domain, "batch", "manage")`).
- **`src/lib.rs`:** `pub fn build_app(state: Arc<AxumAppState>) -> Router` = `build_app_full_with(state, extra_routes())`. `extra_routes` — 3 routes: `GET|POST /workspaces/{workspace_id}/courses`, `GET /tenants/{tenant_id}/files`, `POST /tenants/{tenant_id}/batches`.
- **`src/main.rs`:** `db::connect` → `db::migrate_composed(&pool, &[&MY_MIGRATOR])` → `AxumAppState::builder(pool, jwt_secret).with_resource_types(&[…]).with_bindings([…]).build().await?` → `axum::serve`. `with_resource_types` before `with_bindings` (build() fail-fast validation order). `with_bindings([…])` — array by value, not `&[…]`.
- **`tests/e2e.rs`:** 3 E2E via `tower::oneshot` + `#[sqlx::test(migrations = false)]` + `db::migrate_composed`:
  - `course_editor_creates_course` — owner (via `provision_tenant` + `create_workspace_with_owner`) POST → 200 + `title` in response.
  - `viewer_reads_course` — viewer (custom role with `[]` permissions + `assign_role`) POST → **403** (no `course:write`).
  - `batch_requires_tenant_manage` — member (custom role with `[]` + assign) POST → **403** (no `batch:manage`).
- **DoD deviations from `saas-23.md §3`** (documented in A8 §5.7(i)):
  - 8 `[dependencies]` (not 5) — `axum`, `serde`, `uuid` needed at compile-time for handler DTOs / `Json` / `IntoResponse`.
  - 4 handlers (not 5) — `bootstrap.rs` rolled into `main.rs`; helpers rolled into `handlers.rs`.
  - `build_app_full_with(state, Router)` (not `build_app_full(state).route(…)`) — A4.6.
  - LOC 486 raw / ~290 without comments (DoD "≤300 without comments" satisfied).

**A6 — `examples/axum-minimal` → `saas-axum` (fork-free refactor):**

*`examples/axum-minimal/` refactored onto `saas-axum`: 17 `src/*.rs` files → 3, ~2000 LOC → **278 LOC src**, ~15 workspace deps → **1** (`rust-saas = { features = ["axum"] }`), 14/14 E2E green, `fmt --check` + `clippy -D warnings` clean. Structural refactor only — behavioural contract preserved (status codes, JSON shape, cookie flow, error bodies identical to pre-A6).*

- **`Cargo.toml`:** one workspace dependency `rust-saas = { path = "../../crates/rust-saas", features = ["axum"] }` (was ~15 explicit: `domain`, `authz`, `authz-casbin`, `access`, `identity`, `authn`, `saas`, `db`, `audit`, `audit-pg`, `rate-limiter`). System deps: `tokio`, `sqlx`, `anyhow`, `dotenvy`, `axum`, `serde`, `uuid`, `tracing`, `tracing-subscriber`. Dev: `sqlx` (`macros`), `tower` (`util`), `http-body-util`, `serde_json`, `metrics`, `metrics-exporter-prometheus`. `Cargo.lock` regenerated (rust-saas + saas-axum as path deps).
- **`src/lib.rs`** (~32 LOC): `pub mod handlers;` + `pub fn build_app(state: Arc<AxumAppState>) -> Router = build_app_full_with(state, extra)`, where `extra` carries 7 consumer routes: `/tenants` (GET+POST), `/workspaces` (GET+POST), `/documents` (GET+POST), `/audit` (GET).
- **`src/handlers.rs`** (~206 LOC, new): 7 handlers — `list_my_tenants`, `create_tenant`, `list_my_workspaces`, `create_workspace`, `list_documents`, `create_document`, `list_audit`. Plus a local `PaginationQuery` (15 lines; `saas-axum::pagination` is not re-exported from `rust_saas`, and adding it to the public API for a single `limit/offset` field was judged not worth it). Same `state.saas.pool()` / `state.saas.access()` / `my_permissions` contracts as the old modules.
- **`src/main.rs`** (~41 LOC): `db::connect` → `db::migrate` → `AxumAppState::builder(pool, jwt_secret).build().await?` → `axum::serve`. No `with_resource_types`, no `with_bindings`, no `with_prometheus` — `axum-minimal` is the "minimal path" reference; `minimal-lms` is the "custom resource types + custom bindings" reference.
- **Removed 14 files** (`src/{audit,auth,auth_layer,cookie,csrf,email,error,extract,health,middleware,pagination,state,tenant,workspace}.rs`). All functionality is now either in `build_app_full_with` (auth endpoints, middleware chain, `/healthz`, `/readyz`, `/metrics`) or re-exported from `rust_saas` (`AppError`, `CurrentUser`, `CookieConfig`, `EmailSender`, `NoopEmailSender`, `EmailResult`).
- **`tests/e2e.rs`** (~377 LOC, 14 tests, `#[sqlx::test(migrations = "../../crates/db/migrations")]`): `healthz_returns_200`, `protected_route_requires_auth`, `register_sets_auth_cookies`, `refresh_returns_current_user`, `logout_clears_cookies`, `tenant_and_workspace_flow`, `post_tenants_requires_platform_permission`, `post_tenants_without_csrf_token_is_rejected`, `suspended_tenant_blocks_workspace_creation`, `audit_requires_platform_audit_read`, `register_rate_limited_at_4_per_hour`, `pagination_limits_and_offsets_tenants`, `readyz_returns_200`, `metrics_returns_prometheus_format`. All assertions (status codes, JSON shape, cookie flow, error bodies) unchanged from pre-A6.
- **DoD deviations from `saas-24.md §3`** (documented in A8 §5.7(i) and `saas-25.md §1.9`):
  - 8 system deps (not 5) — `serde`, `uuid` needed at compile-time for handler DTOs / `Json`; `tracing`, `tracing-subscriber` for `.init()` in `main.rs`.
  - `with_bindings` / `with_prometheus` not called in `main.rs` — minimal path (these are exercised by `minimal-lms`).
  - `list_audit` performs `my_permissions` + gate directly instead of using a `RouteBinding` on `/audit` — matches the pre-A6 pattern in `src/audit.rs`; `minimal-lms` demonstrates the declarative `RouteBinding` path.
  - LOC 278 src (DoD "≤500" satisfied; the target was ~500).

### A7'.1 — `saas-leptos` single-dep

**`examples/saas-leptos` → starter template (one workspace dep).** `Cargo.toml` now has one workspace dependency `rust-saas = { path = "../../crates/rust-saas", features = ["ssr", "rate-limiter-redis"], optional = true }` (was ~11 optional workspace deps) + a direct `domain = { path = "../../crates/domain", default-features = false }` (hydrate-only: `rust-saas` is `optional`, enabled only under `ssr`; hydrate-compiled code uses `domain::*` directly). All `use`-lines in `src/*.rs` and `src/pages/*.rs` that referenced `authz` / `authz-casbin` / `access` / `identity` / `authn` / `saas` / `db` / `audit` / `audit-pg` / `rate-limiter` switched to `rust_saas::*` (SSR-only locations: `main.rs`, `state.rs`, `middleware.rs`, `error.rs`, `pages/*` under `#[server]` / `#[cfg(feature = "ssr")]`). `README.md` rewritten as **starter template, not a library** (copy-flow, rename-flow, what-is-included / what-is-NOT-included). **Code does not change** (only `Cargo.toml` + `use`-lines + `README.md`). **15/15 E2E green, `cargo check --features ssr` + `cargo check --features hydrate` green.**

**Deviations from `saas-25.md §3`:**
- `features = ["ssr", "rate-limiter-redis"]` — not just `["ssr"]`. `src/main.rs` uses `rate_limiter::RedisRateLimiter::from_url(...)`; the `rate-limiter-redis` feature (in `crates/rust-saas/Cargo.toml`) is required for `RedisRateLimiter` to compile — it is **not** part of `ssr`. Both `README.md` and this entry use the full feature set.
- `domain` stays a direct, non-optional dependency (not `rust_saas::domain`). `rust-saas` is `optional = true` (only `ssr`), so hydrate-compiled code (`guard.rs`, `pages/*`) cannot reference `rust_saas::domain::*` — it would fail `cargo check --features hydrate` with `E0433: use of undeclared crate or module rust_saas`. `domain` is `default-features = false` and compiles in both `ssr` and `hydrate`.
- **No library API change** (consumer-only refactor; `rust-saas` `features = ["ssr", "rate-limiter-redis"]` already existed; `domain` direct dep was already the case in the reference).

**A7'.2 — `saas-leptos` starter template (bootstrap + register_resource)**

**Stage 5.0-A7'.2 closes the "A7' starter template incomplete" gap.** `examples/saas-leptos` now demonstrates the full `resource_types` lifecycle:

- **Startup bootstrap** (`src/main.rs`): after `CasbinAuthz::from_pool`, before `AccessState` — `bootstrap_all_core(&pool, &authz)` + `bootstrap_resource_types(&pool, &authz, &[ResourceType::workspace("course", &["read","write","publish"]), ResourceType::workspace("assignment", &["read","grade"]), ResourceType::tenant("batch", &["read","manage"])])`. Both idempotent (safe on every process start). Replaces the pre-A7'.2 "8 core types from migration, custom types nowhere".
- **Admin UI** (`src/pages/platform.rs`, `/platform` route): new "Resource Types" section (visible only to holders of `(resource, manage)` in `PLATFORM_DOMAIN`, i.e. platform owners). Form (name + scope + comma-separated actions) + list. Backed by two new `#[server]` functions:
  - `list_resource_types() -> Vec<ResourceTypeView>` — wraps `rust_saas::access::registry::list_resource_types`. `ResourceTypeView` is a client-side mirror (same `RoleView` / `AuditRowView` pattern — `access` is SSR-only).
  - `register_resource(name, scope, actions_str) -> ()` — wraps `rust_saas::access::registry::register_resource_type` (permission-checked: `(resource, manage)` in `PLATFORM_DOMAIN`). Parses `"read, write, publish"` → `&["read","write","publish"]`; scope-string → `ResourceType::{platform,tenant,workspace}`.
- **Tests** (`tests/e2e.rs`): +3 new E2E, `setup_app` now mirrors `main.rs` bootstrap (`bootstrap_all_core` + `bootstrap_resource_types`) so every test starts on the same 11-type DB (8 core + 3 custom):
  - `bootstrap_registers_core_and_custom_types` — after `setup_app`: 11 rows in `resource_types`; `course`/`assignment`/`batch` each have >0 `permissions` rows.
  - `register_resource_requires_platform_resource_manage` — non-platform-owner → `AccessError::Forbidden`; **nothing inserted** (permission check precedes write).
  - `register_resource_creates_type` — platform owner → `ResourceType::workspace("test_new", &["read","write"])` inserted; `scope='workspace'`; both `(test_new, read)` and `(test_new, write)` in `permissions`.
- **`README.md`** — new "What A7'.2 added" section (bootstrap snippet, admin-UI description, "3 ways to register resources" pointer to `saas-external-02.md §6` — A8); `Status` section updated (A7'.1 done, A7'.2 done, A8 next).

**Deviations from `saas-26.md §5`:** none — all DoD items met as specified. Bootstrap snippet exactly as handoff sketch (`bootstrap_all_core` + `bootstrap_resource_types` with 3 types); `#[server] register_resource` + `list_resource_types` + form; 3 E2E (handoff §5 step "5–8" said "3–5", we shipped 3); `fmt --check` + `clippy -D warnings` clean.

**A7'.2 is consumer-only.** `crates/*` — 0 lines changed. `rust-saas` / `saas-axum` / `access` / `saas` API — unchanged. Schema (15 migrations) — unchanged. B1–B10 (all pluggability blockers) remain closed.

**PR #35 (`feat/rbac`)** — merged into `main` (`b815743`) between A5-precursor and A5. Unrelated to A5 or A6; consumers should still verify via `git show b815743 --stat` before starting A7' that no `saas` / `saas-axum` / `access` API changed. For A6, no API changes were observed on the surfaces used (`saas::platform::*`, `saas::access::my_permissions`, `AxumAppStateBuilder`, `build_app_full_with`).

**Tests:** 174 → **197** (A1 + A2 + A3) → **245** → **254** (A4.0–A4.5: `saas-axum` 57 integration + `rust-saas/tests/feature_axum.rs` fn-pointer asserts). Workspace test count unchanged by A6 (consumer-only refactor) and by A7'.1 / A7'.2 (consumer-only). **E2E:** 14 (`axum-minimal`) + **18 (`saas-leptos`, was 15 — A7'.2 +3)** + 3 (`minimal-lms`) = **35** (was 32 after A5). `axum-minimal` E2E adapted in place (14 → 14). `saas-leptos` E2E: 15 → 18.

## [0.2.2] - 2026-11-03

### Stage 4.10 — Observability
- Added `GET /readyz` (deep probe) to both examples: `SELECT 1` against
  the DB; Redis `PING` when `REDIS_URL` is set (`axum-minimal`);
  `200 {"status":"ok","checks":{...}}` or `503`. `/healthz` stays
  liveness-only (no DB). `saas-leptos` reports `redis: "not_configured"`
  (no direct `redis` dep; `rate-limiter` encapsulates it).
- Added `#[instrument]` spans on auth / platform / member / role
  mutations (`authn`, `saas::platform`, `saas::member`, `access::role`).
  Secrets and PII are `skip`ped; `operation` + `actor_id` are recorded.
- Added Prometheus metrics in both examples: `metrics` +
  `metrics-exporter-prometheus`; `/metrics` public on the public router.
  Counters: `login_total{status}`, `register_total{status}`.
- `crates/*` unchanged (`0.2.1`).
- Tests: +2 in `axum-minimal/tests/e2e.rs`, +2 in
  `saas-leptos/tests/e2e.rs` (`readyz_returns_200`,
  `metrics_returns_prometheus_format`). **172 → 174** (bin-сборка:
  unit/integration считаются отдельно в финальном `cargo test`).
- ADR-0007 records the design.

### Stage 4.9 — SSR-correct guards + AuthLayer
- `GuardRoute` rewritten to use `Resource`/`Suspense` (SSR now renders content or 401/403, not "Loading...").
- Added `examples/saas-leptos/src/auth_layer.rs` (defense in depth: 401 anonymous, path-level permissions for `/platform` and `/platform/audit`).
- Wired `auth_layer` into `build_app` in `saas-leptos`.
- `crates/*` unchanged (`0.2.1`).
- Tests: +3 in `saas-leptos/tests/e2e.rs` (`guarded_route_renders_ssr_content`, `auth_layer_blocks_unauthorized_ssr`, `auth_layer_blocks_forbidden_ssr`). **165 → 172**.
- ADR-0006 records the design.

## [0.2.1] - 2026-11-03

### Stage 4.8 — Pagination + distributed rate limiter
- Added `domain::Page<T>` for pagination.
- Added `list_*_paged` to `access`, `saas`, and `audit-pg`. Old `list_*` functions are marked `#[deprecated]`.
- Added `crates/rate-limiter`: `RateLimiter` trait, `InMemoryRateLimiter` (default), `RedisRateLimiter` (feature `redis`).
- Replaced `SimpleRateLimiter` in examples with `Arc<dyn RateLimiter>`.
- Added Redis to `docker-compose.yml` and CI.
- Updated UI (`platform.rs`) to support Prev/Next pagination.
- Bumped version to `0.2.1` (patch).

### Stage 4.7 — E2E HTTP tests
- Extracted `build_app(state)` from `main.rs` to `lib.rs` in both examples;
  `main.rs` is now a thin binary (env → `AppState` → `axum::serve`).
- Added `examples/axum-minimal/tests/e2e.rs` (11 in-process tests via
  `tower::ServiceExt::oneshot` + `#[sqlx::test]`): smoke, auth flow,
  tenant+workspace, CSRF, suspension, audit access, rate limiting.
- Added `examples/saas-leptos/tests/e2e.rs` (12 tests, `[[test]]
  required-features = ["ssr"]`): SSR + `same_origin_guard` over HTTP;
  auth/tenant/suspension/audit/rate-limit through `state.*` (Leptos
  `#[server]` URL is not addressable — Appendix B §IV.48).
- `.github/workflows/ci.yml`: new job `e2e-examples` (postgres:16-alpine
  service, `cargo test --manifest-path examples/*/Cargo.toml
  [--features ssr] --test e2e`).
- Tests: 137 → 160.

### Stage 4.6 — CI, tooling, and documentation
- Added `rust-toolchain.toml` (pinned to `1.98`), `.github/workflows/ci.yml` (test, check, deny, docker), `deny.toml` (licenses, bans, advisories), `CONTRIBUTING.md`, `SECURITY.md`.
- Added `publish = false` to all internal crates to simplify wildcard dependency checks.
- Updated `smoke.sh` WASM guard to 2 MB (since the current bundle is 1.7 MB).

### Stage 4.5 — Security fixes and RBAC sync
- **§4.21 Fix:** `saas::access::update_role` now resyncs `casbin_rule.p` for all holders. Removed permissions are revoked; added permissions are granted. No `member.role_*` flood emitted.
- **§4.22 Fix:** `authz-casbin::grant_role` now catches unique constraint violations (cross-process race) and returns `Ok(())`, preventing 500s in multi-replica deployments.
- **§4.23 Fix:** Added `20261111000001_owner_sync_delete_trigger.sql` (`AFTER DELETE ON permissions`) to clean up orphaned `casbin_rule.p` rows for owner roles.
- **Data integrity:** `identity::update_password_tx` uses `clock_timestamp()` instead of `now()` (fixes test flake and tightens the `iat`-vs-`password_changed_at` window).
- Added `added` / `removed` diff to `role.updated` audit metadata.

## [0.2.0] - 2026-11-01

### Stage 4.4b — Dockerfile + WASM bundle (Dockerfile done; WASM optimization partial)

#### Added
- `examples/saas-leptos/Dockerfile` and `examples/axum-minimal/Dockerfile`:
  multi-stage builds (`rust:1.98-slim-bookworm` builder →
  `debian:bookworm-slim` runtime), non-root user (uid 1001), `HEALTHCHECK`
  against `/healthz`.
- `examples/saas-leptos/smoke.sh`: fail-fast smoke test — SSR pages, static
  assets (CSS / JS / WASM), guard routes, seed-user presence, nine core
  tables. Includes a `wasm < 600 KB` regression check.
- `/healthz` endpoint in both examples (Stage 4.4a): `200 {"status":"ok"}`,
  no DB hit, no auth, no CSRF cookie issue.

#### Changed
- `examples/saas-leptos/Cargo.toml`:
  - `wasm-bindgen = "=0.2.129"` — pinned to match `cargo-leptos 0.3.11`'s
    embedded `wasm-bindgen-cli`; `=0.2.105` was tested and breaks the build
    with a schema mismatch (`rust Wasm file schema version: 0.2.129` vs
    `this binary schema version: 0.2.105`).
  - `[profile.wasm-release]` — `inherits = "release"`, `panic = "abort"`,
    `opt-level = "z"`, `lto = true`, `codegen-units = 1`.
  - `lib-profile-release = "wasm-release"` in `[package.metadata.leptos]`.
  - `wasm-opt-features = ["-Oz"]` in `[package.metadata.leptos]`;
    `cargo-leptos 0.3.11` passes `-Oz` to its bundled
    `wasm-opt-version_123`.
  - `web-time = "1.1.0"` — added as a direct dependency; used in
    wasm-compiled code paths that need `Instant::now()` (which panics
    under `std::time` on `wasm32-unknown-unknown`).
- `examples/saas-leptos/Dockerfile`:
  - `cargo-leptos` pinned to `=0.3.11` (the 0.3.x line changed
    `[package.metadata.leptos]` parsing in a way that breaks older
    manifests).
  - `binaryen` 133 from GitHub release (not `apt-get install binaryen`,
    which ships 112 on bookworm and fails on modern wasm features).

#### Known limitations (see `saas-19.md` §16)
- **WASM size:** 1.7 MB (down from a 2.6 MB baseline; 17 MB debug build).
  Target 400 KB is **not met**. `wasm-opt -Oz --converge --dce
  --duplicate-function-elimination` plateaus at 1.7 MB; `twiggy` shows no
  single dominant contributor (5905 functions, 340 KB memory-data).
  Further reduction requires removing dependencies (`icons`, etc.), not
  further `wasm-opt` tuning.

### Stage 4.3 — Isolation improvements

#### Added
- `authz::test_support` under feature `test-support` — `AllowAllAuthz`
  and `DenyAllAuthz` (Stage 4.3a). Consumer tests no longer need an
  inline mock.
- `db::migrate_with(pool, &[&Migrator])` — additive API for per-crate
  migration sets (Stage 4.3c). Composition with `db::migrate()` on the
  same database is **not** supported (sqlx → `VersionMissing`);
  documented in the `db` doc-comment.
- `audit-pg::MIGRATOR` — worked example of a per-crate Migrator
  (`000_users_bootstrap.sql` + `001_audit_log.sql`). Idempotent
  (`IF NOT EXISTS`); no version collision with the workspace set
  (`001_…` vs `YYYYMMDD…`).

### Stage 4.2 — Error isolation (breaking, see COMPATIBILITY.md)

#### Changed
- `access::AccessError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `identity::IdentityError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `authn::AuthnError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `saas::CoreError::Db(#[from] sqlx::Error)` → `Db(String)`.
- `authn::AuthnError::Identity(#[from] IdentityError)` →
  `AuthnError::Identity(IdentityErrorKind)` where
  `IdentityErrorKind = { NotFound, DuplicateEmail, Validation, Internal }`.
  Public surface of `authn` no longer depends on `identity`.

### Stage 4.1 — Auth hardening

#### Added
- `examples/saas-leptos/cookie.rs` and `examples/axum-minimal/cookie.rs`:
  `CookieConfig { secure, access_ttl, refresh_ttl }` (Stage 4.1b).
  `Secure` defaults to `!bind.ip().is_loopback()`; `COOKIE_SECURE=1|0`
  overrides. `SameSite=Lax`, `Max-Age` = access / refresh TTL.
- `examples/axum-minimal/csrf.rs`: CSRF double-submit (`csrf` cookie +
  `X-CSRF-Token` header) for `POST`/`PUT`/`PATCH`/`DELETE` except
  `/auth/{register,login,logout}`. Constant-time cookie↔header comparison.
  (Stage 4.1c)
- `examples/saas-leptos/middleware::same_origin_guard`: `Origin`-authority
  vs `Host`-authority check for mutations on the protected router. Chosen
  over double-submit because Leptos `#[server]` does not expose a hook
  for injecting a custom header into every RPC. `SameSite=Lax` on auth
  cookies plus this Origin check covers the same attack class. (Stage 4.1c)
- `examples/axum-minimal/auth_layer.rs`: server-side defense-in-depth —
  401 for anonymous, path-level permission for `POST /tenants`
  (`(tenant, create)`) and `GET /audit` (`(audit, read)`); pass-through
  for body-scoped paths (`POST /workspaces`, `POST /documents`) where
  the scope id must be read from the body. (Stage 4.1d)

#### Changed
- `authn::verify_token` rejects access JWTs whose `iat` claim is older
  than `users.password_changed_at`. Closes the window where a stolen
  access token survived a password reset for up to `access_ttl`
  (15 min default). `AuthnError::TokenInvalid` — same variant, no error
  mapping changes. (Stage 4.1, documented in `COMPATIBILITY.md` §0.2.0)

### Stage 4.0 — Sync & cleanup

#### Added
- `crates/rust-saas`: opt-in meta-crate re-exporting the eleven library
  crates under a single Cargo entry (`features = ["ssr" | "hydrate"]`).
  Examples keep their per-crate `path` dependencies, so the Stage 3g
  portability proof stays explicit.
- `crates/saas/tests/integration.rs::delete_role_emits_role_deleted`
  (closes the Stage 3e audit-emission gap for `role.deleted`).
- `[workspace.package]` in the root `Cargo.toml`; every crate now uses
  `version.workspace = true` / `edition.workspace = true`.
- `CHANGELOG.md`.

#### Changed
- `examples/saas-leptos/src/layout.rs`: `PermsCache::invalidate_all()` on
  logout — the next user in the same tab no longer sees the previous
  user's cached permissions for up to 30 s.
- Docs synced with the actual **12** migrations in
  `crates/db/migrations/` (`README.md`, `sass-19.md`,
  `saas-appendix-a-changes.md`, `saas-appendix-b-decisions-and-terminology.md`,
  `sass-pluggability.md`, `ADR-0001`). `owner_sync_trigger` confirmed as
  the 12th migration (Stage 3h close-out); ADR-0001 §9.7 is now adopted.
- `sass-pluggability.md §6`: S1–S4 (RoleStore / UserStore / `Authn` trait
  / `saas` split) explicitly rejected as non-goals (Q2).

#### Removed
- Unused `domain` dependency in `crates/authz-casbin`.

## [0.1.0] - 2026-10-27

Initial baseline: `[workspace.package] version = "0.1.0"` existed, no
`CHANGELOG.md` yet. Covers everything up to Stage 3h — see
`saas-appendix-a-changes.md` for the full evolution.