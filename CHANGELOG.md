# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Every crate in `crates/` shares one version (enforced by
`[workspace.package]`); consumers must pin all crates to the same
revision.

## [Unreleased]

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
