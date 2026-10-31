//! `GET /healthz` — readiness probe (Stage 4.4a).
//!
//! Cheapest possible check: returns `200 {"status": "ok"}` without
//! touching the database. This is intentional — Docker `HEALTHCHECK` /
//! Kubernetes `livenessProbe` only need to know the process is alive and
//! serving HTTP. A DB probe (a separate `/readyz` or `/healthz?deep=1`)
//! is out of scope for the reference: a failed DB connection already makes
//! every business handler return 500, which the probe's caller sees as
//! "not ready" through request failures.
//!
//! Attached to the **public** router — `/healthz` must be reachable
//! without an authenticated actor, or every orchestrator restart would
//! need a session.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}
