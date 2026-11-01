# syntax=docker/dockerfile:1.6
#
# Multi-stage build for `saas-leptos` (Leptos SSR + Axum + SMTP transport).
# Build context: repository root.
#
#   docker build -f examples/saas-leptos/Dockerfile -t rust-saas/saas-leptos .
#
# Why the repository root as context: same reasoning as
# `examples/axum-minimal/Dockerfile` — path deps on `../../crates/*`, and
# `[workspace.package]` lives at the root. `.dockerignore` excludes
# `target/`, `.git/`, `internal-docs/`, `.env*`.

ARG RUST_VERSION=1.98
ARG DEBIAN_VERSION=bookworm

# ── builder ────────────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS builder

WORKDIR /build

# - `build-essential` — linker.
# - `pkg-config` + `libssl-dev` — `sqlx-adapter 1.x` pulls `sqlx` with
#   default features (`native-tls` → `openssl-sys`), needing OpenSSL headers
#   at build time. Runtime `debian:bookworm-slim` already ships `libssl3`.
# - `binaryen` — `wasm-opt` for Leptos WASM size optimization
#   (`cargo leptos build --release` invokes it).
# - `curl` — healthcheck in runtime + convenience during build debug.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        binaryen \
        curl \
 && rm -rf /var/lib/apt/lists/*

# Leptos 0.8 builds the client half against wasm32.
RUN rustup target add wasm32-unknown-unknown

# wasm-opt v133 — из GitHub release, а не apt: binaryen 112 в
# debian:bookworm не понимает wasm-features, которые Rust 1.98
# генерирует по умолчанию (bulk-memory, reference-types,
# multivalue), и молчаливо фейлит — cargo-leptos копирует
# неоптимизированный .wasm (~2.6 MB вместо ~400 KB).
ARG BINARYEN_VERSION=133
RUN ARCH=$(uname -m) \
 && case "$ARCH" in \
      x86_64) BIN_ARCH=x86_64 ;; \
      aarch64) BIN_ARCH=aarch64 ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL \
      "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-${BIN_ARCH}-linux.tar.gz" \
      -o /tmp/binaryen.tar.gz \
 && tar -xzf /tmp/binaryen.tar.gz -C /opt \
 && ln -s "/opt/binaryen-version_${BINARYEN_VERSION}/bin/wasm-opt" /usr/local/bin/wasm-opt \
 && rm /tmp/binaryen.tar.gz \
 && wasm-opt --version

# Tailwind CSS 4 is built by `cargo-leptos` via a **standalone binary**
# it downloads on first use — **no Node.js, no npm, no `npx`**. That is the
# project rule: this repository must not depend on Node in any form (build,
# Docker image, CI, dev shell). If a future tool ever wants Node, it must
# be rejected and the decision escalated before being wired in.
#
# Pinning the Tailwind binary version makes the Docker build reproducible
# and avoids silent upgrades. Bump deliberately, in the same commit as a
# change to `assets/styles/tailwind.css`.
#   TODO: replace `v4.x.y` with the Tailwind 4 version used locally
#   (the one `cargo leptos watch` downloads on the dev host).
ENV LEPTOS_TAILWIND_VERSION=v4.2.1


# `cargo-leptos` orchestrates the dual (SSR + WASM) build. Pinning a
# specific version would make the image reproducible byte-for-byte;
# `--locked` (with Cargo.lock committed) already pins cargo-leptos'
# own dependencies. We pin the major version in the comment below and
# revisit when reproducible builds become a goal.
#   cargo-leptos 0.2.x — current stable.
RUN cargo install cargo-leptos --version "=0.3.11" --locked

# Same single-COPY reasoning as `axum-minimal`: `.dockerignore` keeps the
# large directories out, and layered manifest-copy is deferred until build
# time matters.
COPY . .

WORKDIR /build/examples/saas-leptos
RUN cargo leptos build --release


# ── runtime ────────────────────────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION}-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 rust-saas \
 && useradd  --system --uid 1001 --gid rust-saas \
            --no-create-home --shell /usr/sbin/nologin rust-saas

WORKDIR /app

# `[package.metadata.leptos]` paths are relative to `cwd`:
#   `site-root = "target/site"`, `site-pkg-dir = "pkg"`.
# `cargo leptos build` emits the SSR binary at
# `target/release/saas-leptos` and the site tree (CSS, JS, WASM, assets
# from `public/`) at `target/site/`. Copy both, keep `cwd = /app`.
COPY --from=builder /build/examples/saas-leptos/target/site /app/target/site
COPY --from=builder \
    /build/examples/saas-leptos/target/release/saas-leptos \
    /app/saas-leptos

USER rust-saas

# Explicit `LEPTOS_SITE_ROOT` / `LEPTOS_SITE_PKG_DIR` — defence-in-depth
# against cwd drift. `BIND_ADDR=0.0.0.0:3395` is required so the process
# is reachable from outside the container (`main.rs` falls back to
# `leptos_options.site_addr` = `127.0.0.1:3395` otherwise, which would only
# listen on loopback).
ENV BIND_ADDR=0.0.0.0:3395 \
    LEPTOS_SITE_ROOT=target/site \
    LEPTOS_SITE_PKG_DIR=pkg \
    RUST_LOG=info

EXPOSE 3395

# `saas-leptos` has a longer startup than `axum-minimal` (Leptos SSR init),
# so `start-period` is bumped to 15s. `HEALTHCHECK` hits `GET /healthz` —
# public router, no session, no DB.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:3395/healthz || exit 1

ENTRYPOINT ["/app/saas-leptos"]
