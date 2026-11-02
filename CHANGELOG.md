# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Every crate in `crates/` shares one version (enforced by
`[workspace.package]`); consumers must pin all crates to the same
revision.

## [Unreleased]

### Stage 4.8 — Pagination + distributed rate limiter
- Added `domain::Page<T>` for pagination.
- Added `list_*_paged` to `access`, `saas`, and `audit-pg`. Old `list_*` functions are marked `#[deprecated]`.
- Added `crates/rate-limiter`: `RateLimiter` trait, `InMemoryRateLimiter` (default), `RedisRateLimiter` (feature `redis`).
- Replaced `SimpleRateLimiter` in examples with `Arc<dyn RateLimiter>`.
- Added Redis to `docker-compose.yml` and CI.
- Updated UI (`platform.rs`) to support Prev/Next pagination.
- Bumped version to `0.2.1` (patch).

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
  (`(tenants, create)`) and `GET /audit` (`(audit, read)`); pass-through
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