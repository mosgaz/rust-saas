//! `/healthz` — liveness probe (Stage 4.4a).
//! `/readyz` — readiness probe (Stage 4.10).
//!
//! Разделение:
//!
//! - `/healthz` — «процесс жив и отвечает по HTTP». Без БД, без auth, без
//!   CSRF. Дёргается Docker `HEALTHCHECK` / k8s `livenessProbe`.
//! - `/readyz` — «процесс **готов принимать трафик**». Проверяет БД
//!   (`SELECT 1`) и, если задан `REDIS_URL`, — Redis (`PING`). Возвращает
//!   `200 {"status":"ok","checks":{...}}` или `503` со списком упавших.
//!   Дёргается k8s `readinessProbe`; пока `/readyz` возвращает 503,
//!   балансировщик не шлёт трафик на этот pod.
//!
//! `redis::Client::open` + PING вызывается **внутри** `check_redis()`,
//! а не хранится в `AppState`: `/readyz` дёргается редко, `Client::open`
//! дёшев, `AppState` остаётся неизменным (`state.rs` не входит в scope
//! Stage 4.10).
//!
//! Attached to the **public** router — `/readyz` (как и `/healthz`) должен
//! быть доступен без аутентификации, иначе orchestrator-проверки
//! потребуют сессии.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::state::AppState;

/// Liveness probe: «процесс жив и отвечает по HTTP». Без БД, без Redis.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

/// `checks` в теле `/readyz`.
///
/// `db`: `"ok"` | `"down"`.
/// `redis`: `"ok"` | `"down"` | `"not_configured"` (`REDIS_URL` не задан —
/// это не failure, `InMemoryRateLimiter` работает без Redis).
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

/// Readiness probe: deep check БД (+ Redis, если задан `REDIS_URL`).
///
/// Логика:
/// - `db = "down"` → **503** (без БД приложение бесполезно).
/// - `redis = "down"` → **503** (если `REDIS_URL` задан, значит multi-replica
///   deployment рассчитывает на distributed rate limiter; без Redis
///   rate-limit в каждой реплике независим — это нарушение контракта).
/// - `redis = "not_configured"` → **pass** (single-replica или dev,
///   `InMemoryRateLimiter` — легитимный режим).
pub async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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

async fn check_db(state: &AppState) -> &'static str {
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
