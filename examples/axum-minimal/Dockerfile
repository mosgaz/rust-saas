# syntax=docker/dockerfile:1.6
#
# Multi-stage build for `axum-minimal` (pure Axum, no Leptos, no wasm).
# Build context: repository root.
#
#   docker build -f examples/axum-minimal/Dockerfile -t rust-saas/axum-minimal .
#
# Why the repository root as context: `examples/axum-minimal` uses path
# dependencies on `../../crates/*` and the crates resolve `version.workspace
# = true` from the root `Cargo.toml`. The context must therefore include
# `crates/` and the root manifests. `.dockerignore` keeps `target/`,
# `.git/`, `internal-docs/`, `.env*` out.

ARG RUST_VERSION=1.98
ARG DEBIAN_VERSION=bookworm

# ── builder ────────────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS builder

WORKDIR /build

# `build-essential` gives the linker; SQLx uses the plain `query`/`query_as`
# API (no compile-time `query!` macros), so no `DATABASE_URL` is needed at
# build time. `sqlx::migrate!` compiles from local `./migrations` dirs.
#
# `pkg-config` + `libssl-dev`: `sqlx-adapter 1.x` pulls `sqlx` with default
# features (`tls-native-tls` -> `native-tls` -> `openssl-sys`), which needs
# OpenSSL headers at build time. Our own `sqlx` uses `tls-rustls`, but Cargo
# feature unification merges the two. The resulting binary links `libssl`
# dynamically; the runtime `debian:bookworm-slim` already ships `libssl3`,
# so no extra runtime package is required.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Single COPY is simpler than layered COPYs and reliable across workspace
# path-dep resolution. Layer-caching optimization (copy manifests first,
# dummy-build, copy src) is deferred until image-build time becomes a
# bottleneck; `.dockerignore` already excludes the large directories.
COPY . .

WORKDIR /build/examples/axum-minimal
RUN cargo build --release --locked

# ── runtime ────────────────────────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION}-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 rust-saas \
 && useradd  --system --uid 1001 --gid rust-saas \
            --no-create-home --shell /usr/sbin/nologin rust-saas

COPY --from=builder \
    /build/examples/axum-minimal/target/release/axum-minimal \
    /usr/local/bin/axum-minimal

USER rust-saas

# BIND_ADDR must be 0.0.0.0 inside a container — the default
# `127.0.0.1:3395` would only be reachable from inside the container.
ENV BIND_ADDR=0.0.0.0:3395 \
    RUST_LOG=info

EXPOSE 3395

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:3395/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/axum-minimal"]