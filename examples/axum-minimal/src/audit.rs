//! Audit-view handler for `axum-minimal` (Stage 3g).
//!
//! One endpoint: `GET /audit?limit=…` — the most recent `audit_log` rows,
//! newest first. Read-only; mirrors `saas-leptos`'s
//! `#[server] list_audit` (`pages/platform.rs`) with the Axum substitution:
//!
//! - `saas-leptos` returns a client-side `AuditRowView` (a mirror of
//!   `audit_pg::AuditRow`), because `audit_pg` pulls `sqlx` and cannot be
//!   linked into the WASM hydrate build. `axum-minimal` is a single
//!   server-side binary with no hydrate target, so it returns
//!   `audit_pg::AuditRow` directly — no mirror struct, no `From` impl.
//! - `saas-leptos` enforces `(audit, read)` in `PLATFORM_DOMAIN` via
//!   `saas::access::my_permissions` (the reference consumer never calls
//!   `authz.require` directly — handoff §4). Same here.
//! - `limit` is clamped to `[1, 200]` server-side, exactly as in
//!   `saas-leptos` (`LIMIT_MAX = 200`). The `audit_log` table is
//!   append-only and unbounded in 3g; the clamp prevents accidental large
//!   reads before pagination (Stage 4).
//!
//! **Response shape.** `200` + `[ { … AuditRow … }, … ]`, where each row
//! carries `id`, `occurred_at`, `actor_id`, `actor_email`, `event_type`,
//! `target_type`, `target_id`, `metadata` (JSONB as `serde_json::Value`).
//! Same field set as `saas-leptos`'s `AuditRowView`.

use std::sync::Arc;

use audit_pg::PgAuditLogger;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;

use crate::error::AppError;
use crate::extract::CurrentUser;
use crate::pagination::PaginationQuery;
use crate::state::AppState;

/// Query params of `GET /audit`.
///
/// `limit` is `Option<i64>`: a caller that omits it gets
/// [`DEFAULT_LIMIT`]; a caller that supplies `0` or a negative value gets
/// clamped to `1`; a caller that supplies `> LIMIT_MAX` gets clamped to
/// [`LIMIT_MAX`]. Out-of-range values are not errors — the clamp is a
/// safety net, not a validation (same behaviour as `saas-leptos`).
pub type ListAuditQuery = PaginationQuery;

/// Lists the most recent `audit_log` rows.
///
/// Order:
/// 1. `CurrentUser::require()` — 401 for an anonymous request.
/// 2. `saas::access::my_permissions(state, actor, "platform")` — read-only
///    UX helper (handoff §4: the example never calls `authz.require`).
/// 3. Reject if `(audit, read)` is not in the effective permission set →
///    `CoreError::Forbidden` (403).
/// 4. `PgAuditLogger::list(clamped_limit)` — one `SELECT … ORDER BY
///    occurred_at DESC, id DESC LIMIT $1`.
pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
    Query(q): Query<ListAuditQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;

    // 2. Effective permissions in `PLATFORM_DOMAIN`.
    let perms = saas::access::my_permissions(&state.saas, &user, domain::PLATFORM_DOMAIN).await?;

    // 3. Enforce `(audit, read)`.
    let allowed = perms.iter().any(|(r, a)| r == "audit" && a == "read");
    if !allowed {
        return Err(AppError::Core(saas::CoreError::Forbidden));
    }

    let (limit, offset) = q.clamp();

    let logger = PgAuditLogger::from_pool(state.saas.pool().clone());
    let page = logger
        .list_paged(limit, offset)
        .await
        .map_err(|e| AppError::Core(saas::CoreError::Internal(e.to_string())))?;

    Ok(Json(page))
}
