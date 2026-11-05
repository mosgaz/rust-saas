# `saas-leptos` — starter template

**Starter template, not a library.** `saas-leptos` is a complete reference consumer of `rust-saas`, intended to be **copied** and **renamed** to bootstrap your own Leptos LMS/CRM/CMS project.

## Why a starter template, not a library?

`#[server]` (Leptos) functions must live in **your** crate namespace — `my_lms::auth::register` ≠ `saas_leptos::auth::register`. The macro-generated `/_server/{hash}` endpoint encodes the fully-qualified function name, so a library cannot be reused through a shared `#[server]` facade.

Result: **structural constraint**. `saas-leptos` is a template — copy it, rename it, extend it. That is the intended flow, not a limitation.

What you do not copy: `rust_saas::*` — that is a single workspace dependency (`rust-saas = { features = ["ssr", "rate-limiter-redis"], optional = true }`). All auth/access/saas/db/audit/rate-limiter crates are re-exported from it.

## Quick start

```bash
git clone https://github.com/…/rust-saas.git rust-saas
cp -r rust-saas/examples/saas-leptos my_lms
cd my_lms
cargo leptos build
```

## Copy-flow (what to copy)

Whole `saas-leptos/` directory:

- `Cargo.toml` — 1 workspace dep (`rust-saas = { features = ["ssr", "rate-limiter-redis"] }`) + Leptos/Axum/DB/Email/Metrics
- `Cargo.lock` — regenerate with `cargo leptos build`
- `src/` — auth, tenant, workspace, member, role, invitation, document, platform, health, metrics
- `tests/e2e.rs` — 15 E2E tests (adapt to your domain)
- `migrations/` — your migrations with versions `90000000000000+` (see `db::CONSUMER_VERSION_FLOOR`)
- `Dockerfile`, `smoke.sh` — reference
- `rust-toolchain.toml`, `assets/`, `public/`

## Rename-flow (what to rename)

1. `Cargo.toml` → `name = "my_lms"` (instead of `saas-leptos`)
2. `crate::` in `src/*.rs` → `my_lms::` (if `crate::auth` is re-exported in `lib.rs`)
3. `Cargo.toml` → `[package.metadata.leptos] output-name = "my-lms"` — otherwise conflict with other Leptos projects in `target/site/pkg/`
4. `Dockerfile` — `saas-leptos` → `my-lms` (binary name)
5. `src/main.rs` — `BIND_ADDR` env (default `127.0.0.1:3395`)

`use rust_saas::*` — **do not touch**: the only workspace dependency.

## What-is-included (via `rust_saas::*`)

- `/auth/{register,login,logout,refresh}` endpoints + middleware
- `/my_permissions`, `/my_permissions/grouped`, `/resource_types`
- `AppError` → HTTP (400/401/403/404/409/429/500)
- `CurrentUser` extractor (plain helper — Leptos `#[server]` does not pass through the Axum-extractor pipeline)
- CSRF: `SameOriginGuard` (`Origin`/`Host` check — Leptos has no hook for a custom header)
- `AuthLayer` (defense in depth: `/platform`, `/platform/audit`)
- `/healthz`, `/readyz`, `/metrics`
- `Authn::with_ttl`, `SaasBuilder`, `AccessState`, `PgAuditLogger`
- `CookieConfig`, `EmailSender` / `NoopEmailSender` / `SmtpEmailSender`
- `PerRequest` instrumentation (`#[instrument]` in `authn`/`saas`/`access`)

## What-is-NOT-included (you write these)

- Your domain model (`courses`, `lessons`, `assignments` — 1:1 to `workspaces`/`documents` via consumer migrations `90000000000000+`)
- `#[server]` functions for your business (`create_course`, `list_lessons`, …)
- `pages/*` (Leptos UI — structural)
- `guard.rs` (`RouteGuard`/`GuardRoute` — rewrite for your permissions)
- `seed` — your data seeding
- Custom SMTP (`lettre`) — if you need a real sender

## Next steps (post-A7')

- **A7'.2** — `bootstrap_*` in `main.rs` (5+ lines: `bootstrap_all_core` + `bootstrap_resource_types`) + `#[server] register_resource` in `pages/platform.rs` + form. See `saas-external-02.md §6` (A8) — decision matrix "3 ways to register resources": SQL / `bootstrap_*` / `register_resource_type`.

## What is copied from which `crates/*`

| What | From where (in `rust_saas::*`) |
|---|---|
| `Authn`, `AuthnError`, `Claims` | `rust_saas::authn` |
| `AccessState`, `RoleKey`, `Permission`, `Role` | `rust_saas::access` |
| `SaasState`, `SaasBuilder`, `CoreError`, `platform::*`, `tenant::*`, `workspace::*` | `rust_saas::saas` |
| `AuditLogger`, `PgAuditLogger`, `NoopAuditLogger` | `rust_saas::audit` / `rust_saas::audit_pg` |
| `AuthorizationEngine`, `CasbinAuthz` | `rust_saas::authz` / `rust_saas::authz_casbin` |
| `AuthUser`, `Tenant`, `Workspace`, `Document`, `Member`, `PLATFORM_DOMAIN` | `rust_saas::domain` |
| `MIGRATOR`, `migrate`, `migrate_composed`, `CONSUMER_VERSION_FLOOR` | `rust_saas::db` |
| `RateLimiter`, `InMemoryRateLimiter`, `RedisRateLimiter` | `rust_saas::rate_limiter` |

## Pre-A7' status

- **A7'.1 (this sub-stage)** — `Cargo.toml` (1 workspace dep) + `README.md` (this file). Code does not change (except `use` lines). 15/15 E2E green.
- **A7'.2 (next)** — `bootstrap_*` + `register_resource` + form.
- **A8** — `saas-external-02.md`, `ADR-0008`, `ADR-0009`.
- **A9** — DoD Phase A, tag `v0.3.0`.

## Reference

- `examples/minimal-lms/` — Axum-path reference: 8 files, ~290 LOC without comments, 3 E2E. Custom resource types + bindings.
- `examples/axum-minimal/` — Axum-path reference (minimal): 3 files, 278 LOC, 14 E2E. Minimal path.
- `saas-external-01.md` — guide for an external consumer.
- `saas-external-02.md` — §6 "If you use Leptos" (A8).
- `saas-appendix-b-decisions-and-terminology.md` — why a starter template.