# syntax=docker/dockerfile:1.6
ARG RUST_VERSION=1.98
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . .
WORKDIR /build/examples/minimal-lms-abac
RUN cargo build --release --locked

FROM debian:${DEBIAN_VERSION}-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 1001 rust-saas && useradd --system --uid 1001 --gid rust-saas --no-create-home --shell /usr/sbin/nologin rust-saas
COPY --from=builder /build/examples/minimal-lms-abac/target/release/minimal-lms-abac /usr/local/bin/minimal-lms-abac
USER rust-saas
ENV BIND_ADDR=0.0.0.0:3395 RUST_LOG=info
EXPOSE 3395
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD curl --fail --silent --show-error http://127.0.0.1:3395/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/minimal-lms-abac"]
