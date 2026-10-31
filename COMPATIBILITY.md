# Compatibility

The `crates/*` workspace follows one rule: **all crates share one version
and one revision**. Do not mix, for example, `access 0.1.0` with `saas
0.2.0`. `[workspace.package]` in the root `Cargo.toml` enforces the
version at the source; consumers must pin every path / git dependency to
the same tag.

## Versioning policy

- **Patch (`0.x.Y`)** — bugfixes, internal improvements. No public-API
  change.
- **Minor (`0.X.0`)** — new functionality; additive public API; may
  include **breaking changes** before `1.0` (SemVer allows this in the
  `0.x` line, and this project follows it explicitly because the crates
  are pre-stable).
- **Major (`X.0.0`)** — out of `0.x`; full SemVer.

## Breaking changes so far

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
