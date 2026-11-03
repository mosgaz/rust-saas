# Contributing to rust-saas

First off, thank you for considering contributing to `rust-saas`! 

## Local development

### Prerequisites
- Rust (see `rust-toolchain.toml` for the exact version).
- `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`).
- `cargo-leptos` (`cargo install --locked cargo-leptos`).
- Docker with Compose v2.

### Setup
```bash
# 1. Start PostgreSQL and Mailpit
docker compose up -d

# 2. Apply migrations and create seed data
cargo run -p seed
```

### Running checks before a PR
We use a strict CI pipeline. To avoid failing CI, run these commands locally:
```bash
# Formatting
cargo fmt --all

# Linting
cargo clippy --workspace --all-targets -- -D warnings

# Tests (requires running Postgres)
cargo test --workspace

# Dependency hygiene
cargo deny check

# Check examples
cargo check --manifest-path examples/axum-minimal/Cargo.toml
cargo check --manifest-path examples/saas-leptos/Cargo.toml --features ssr
```

## Pull Request Guidelines

- **One logical change per PR.** Do not mix refactoring with new features or bug fixes.
- **Commit messages:** Use [Conventional Commits](https://www.conventionalcommits.org/) (e.g., `feat:`, `fix:`, `chore:`, `docs:`). The body should explain the *why*, not just the *what*.
- **Tests:** Every new feature or bug fix must be covered by a test (unit or integration).
- **Documentation:** Update doc comments and `internal-docs/` if the architecture changes.

## Internal Docs

The `internal-docs/` folder contains handoffs, ADRs, and architectural decisions. It is **gitignored** in the public repository but is crucial for the maintainers. Do not commit changes to `internal-docs/` in the same PR as the code; they are synced separately.
