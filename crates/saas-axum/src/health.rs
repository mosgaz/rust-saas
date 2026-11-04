//! Health and readiness probes (Stage 4.4a / 4.10, ported to `saas-axum`).
//!
//! - `/healthz` — liveness: "process is up and responding". No DB, no
//!   auth, no CSRF. Docker `HEALTHCHECK` / k8s `livenessProbe`.
//! - `/readyz` — readiness: "process is ready to accept traffic". Checks
//!   the DB (`SELECT 1`) and, if `REDIS_URL` is set, Redis (`PING`).
//!   `200 {"status":"ok","checks":{...}}` or `503 {"status":"fail",...}`.
//!   k8s `readinessProbe`.
//! - `/metrics` — Prometheus exposition format (counters only, no PII).
//!   `404` when `state.prometheus` is `None` (no `with_prometheus(...)`
//!   call).
//!
//! **PR-1 wiring:** `build_app` (see `router.rs`) mounts **only
//! `/healthz`**. `/readyz` and `/metrics` are declared here so A4.3b can
//! wire them with two `.route(...)` calls; they have no dependencies the
//! router does not already have. This keeps PR-1's diff minimal while
//! keeping the handlers in their final shape.
//!
//! `redis` field values: `"ok"`, `"down"`, `"not_configured"` (no
//! `REDIS_URL`). Only `"down"` fails readiness — `"not_configured"` is a
//! legitimate single-replica / dev setup (`InMemoryRateLimiter`).
//!
//! `redis::Client::open` + `PING` are done **inside** `check_redis()`,
//! not stored in state: `/readyz` is rare, `Client::open` is cheap, and
//! `AxumAppState` stays free of a Redis handle (the `rate-limiter` crate
//! encapsulates it, and a consumer with `InMemoryRateLimiter` does not
//! want a `redis` dep).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::state::AxumAppState;

/// Liveness probe: `200 {"status":"ok"}`. No DB, no auth, no CSRF.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Serialize)]
struct Checks {
    db: &'static str,
    redis: &'static str,
}

#[derive(Serialize)]
struct ReadyzBody {
    status: &'static str,
    checks: Checks,
}

/// Readiness probe: deep check of DB (+ Redis, if `REDIS_URL` is set).
///
/// - `db = "down"` → **503** (without a DB the process is useless).
/// - `redis = "down"` → **503** (if `REDIS_URL` is set, the deployment
///   expects a distributed rate limiter; Redis being down is a contract
///   violation).
/// - `redis = "not_configured"` → pass (single-replica or dev;
///   `InMemoryRateLimiter` is a legitimate mode).
pub async fn readyz(State(state): State<Arc<AxumAppState>>) -> impl IntoResponse {
    let db = check_db(&state).await;
    let redis = check_redis().await;
    let ok = db == "ok" && redis != "down";

    let body = ReadyzBody {
        status: if ok { "ok" } else { "fail" },
        checks: Checks { db, redis },
    };
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
}

/// Prometheus exposition format. `404` when no recorder was installed
/// (`with_prometheus(...)` not called on the builder).
pub async fn metrics(State(state): State<Arc<AxumAppState>>) -> impl IntoResponse {
    match &state.prometheus {
        Some(handle) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            handle.render(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "metrics not enabled" })),
        )
            .into_response(),
    }
}

async fn check_db(state: &AxumAppState) -> &'static str {
    match sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(state.saas.pool())
        .await
    {
        Ok(1) => "ok",
        _ => "down",
    }
}

async fn check_redis() -> &'static str {
    let url = match std::env::var("REDIS_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => return "not_configured",
    };
    let client = match redis::Client::open(url) {
        Ok(c) => c,
        Err(_) => return "down",
    };
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return "down",
    };
    match redis::cmd("PING").query_async::<String>(&mut conn).await {
        Ok(_) => "ok",
        Err(_) => "down",
    }
}
