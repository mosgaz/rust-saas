# Compatibility

The `crates/*` workspace follows one rule: **all crates share one version
and one revision**. Do not mix, for example, `access 0.1.0` with `saas
0.2.0`. `[workspace.package]` in the root `Cargo.toml` enforces the
version at the source; consumers must pin every path / git dependency to
the same tag.

**Current version:** `0.2.1` (`Cargo.toml` → `[workspace.package]`).

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
