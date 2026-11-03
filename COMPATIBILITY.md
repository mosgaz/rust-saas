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


### 0.3.0 — Stage 5.0 (Phase A, in progress)

Breaking changes and new API introduced across `crates/*` in Phase A
(`crates/db/migrations/20261130*`, A1.4, A2.2a, A2.2c). Phase A's DoD
(`# Stage 5 — план реализации.txt` §4.A9) is **not** yet closed; this
entry documents what has already landed on `main` under `0.3.0`.

**New public API (additive):**

- `authz::AuthorizationEngine::reload_in_memory() -> Result<(), AuthzError>` —
  refresh in-memory policy after an external `INSERT INTO casbin_rule`
  (e.g. the `owner_sync` trigger). No-op for engines without in-memory
  state.
- `authz::AuthzError::ReloadError(String)` — new variant.
- `access::AccessError::UnknownResourceType { name }` — new variant
  (`add_action` fail-fast).
- `access::AccessError::ScopeMismatch { name, existing, requested }` —
  new variant (`bootstrap_resource_type`).
- `access::registry` module: `ResourceType`, `ResourceScope`,
  `bootstrap_resource_type`, `bootstrap_resource_types`,
  `bootstrap_all_core`, `register_resource_type`, `add_action`,
  `list_resource_types`.
- `saas::SaasBuilder::without_access()` — build a `SaasState` without
  `AccessState`. `authz` is still required.
- `saas::tenant::create_workspace(actor, tenant_id, name)` — new 4-arg
  form (no owner, no `access::*`).
- `saas::platform::{resolve_tenant, resolve_workspace,
  resolve_active_workspace, is_tenant_member, is_workspace_member}` +
  `ActiveWorkspace` newtype (re-exported at the crate root alongside
  `ActiveTenant`).

**Breaking:**

1. **`authz::AuthorizationEngine::reload_in_memory()`** — every impl
   must implement it (`Ok(())` for engines without in-memory state).
   `AllowAllAuthz` / `DenyAllAuthz` from `authz::test_support` already
   ship it; a consumer's custom impl needs one more method.

2. **`access::AccessError` gained two variants** (`UnknownResourceType`
   and `ScopeMismatch`). Any `match` on `AccessError` is now
   non-exhaustive. Both new variants map to HTTP 400 (validation) in
   the reference examples — a caller passing bad config, not a
   business-rule violation. Same for `saas::CoreError` (its
   `From<AccessError>` maps both to `CoreError::Validation`).

3. **`saas::SaasState::access()`** — signature changed from
   `&AccessState` to `Result<&AccessState, CoreError>`. Every call site
   needs `?` (or `.expect(..)` in tests). Returns
   `CoreError::Internal("RBAC not configured…")` on a
   `without_access()` build.

4. **`saas::SaasBuilder::build()`** — behaviour change. Before:
   required `with_access(..)`. Now: requires *either*
   `with_access(..)` *or* `without_access()`, or fails with
   `Internal("access state is required…")`. A builder that already
   called `with_access(..)` is unaffected (the check passes).

5. **`saas::tenant::create_workspace`** — signature split. The old
   6-arg form (`actor, tenant_id, name, owner, owner_role_key`) is
   renamed to `create_workspace_with_owner`. The old name now refers
   to a new 4-arg form (`actor, tenant_id, name`) that does not assign
   an owner and does not require `AccessState`. Consumers who want
   owner assignment on creation use `create_workspace_with_owner`.

**Migration.**

- **`without_access()` users.** None yet (this is the first release
  with the method). New consumers that want RBAC-disabled builds must
  supply their own `AuthorizationEngine` impl (e.g. `AlwaysAllow` in
  ~5 lines) and call `without_access()` after `with_authz(..)`.

- **`create_workspace` call sites.** Rename to
  `create_workspace_with_owner` (mechanical; 20 call sites in this
  repo, a consumer sees the same).

- **`state.access()` call sites.** Add `?` (or `.expect(..)` in
  tests). Mechanical; 21 call sites in this repo.

- **Exhaustive `match` on `AccessError` / `AuthzError` / `CoreError`.**
  Add arms for the new variants. The reference examples
  (`examples/*/src/error.rs`) already do.

- **Database.** New migrations
  (`20261130000001_resource_types.sql`,
  `20261130000002_owner_sync_casbin.sql`,
  `20261130000003_legacy_import_and_fk.sql`) must be applied. Consumer
  databases that predate this set and contain custom
  `permissions.resource` values (`course`, `deal`, …) get them
  auto-imported as `custom:legacy`; `resource:manage` is added and
  propagated to `platform` owner by the fixed trigger. A running
  replica still needs `authz.reload_in_memory()` after the migration
  to see the new permissions — the standard practice is
  `migrate_composed` before process start (once A3 lands; currently
  the only supported path is the workspace-wide `db::migrate`).

