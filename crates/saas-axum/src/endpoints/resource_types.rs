//! `GET /resource_types` for `saas-axum` (Stage 5.0-A4.4).
//!
//! Reads the `resource_types` registry (A1.1) — the 8 core types from the
//! migration plus any types a consumer registered via `bootstrap_*` or
//! `register_resource_type`. Read-only.
//!
//! **Protected.** Requires an authenticated actor (`CurrentUser::require`
//! → 401 anonymous). The `resource_types` table is not sensitive, but it
//! is an admin/UX aid rather than a public discovery endpoint — a
//! consumer that wants it public can mount its own handler.
//!
//! **Backend call.** [`access::registry::list_resource_types`] takes only
//! `&PgPool` (no `actor`; §5 p.5 exception), so this works identically on
//! a `without_rbac()` build — `resource_types` is populated by migrations
//! regardless of `AccessState` presence. Documented behaviour (handoff §4.2).
//!
//! **Response shape.** `200` + `[{ "name": …, "scope": …, "default_actions": [...] }, …]`.
//! - `scope` is the string form (`"platform"` / `"tenant"` / `"workspace"`
//!   / `"custom:…"`) via [`access::registry::ResourceScope::as_str`], not
//!   the default serde encoding of the `Custom(String)` variant (which
//!   would be `{"custom": "…"}` — an implementation leak).
//! - `description` and `metadata` are omitted: not part of the
//!   consumer-facing contract (handoff §3). A consumer that needs them
//!   can call `access::registry::list_resource_types` directly.
//! - Sorted by `name` (the library already `order by name`).

use std::sync::Arc;

use access::registry::ResourceType;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::error::AppError;
use crate::extract::CurrentUser;
use crate::state::AxumAppState;

// ─── DTO ────────────────────────────────────────────────────────────────────

/// Consumer-facing projection of [`ResourceType`]. Omits `description` /
/// `metadata` (internal to the registry) and flattens `scope` to its
/// string form.
#[derive(Debug, Serialize)]
pub struct ResourceTypeView {
    pub name: String,
    /// `"platform"` / `"tenant"` / `"workspace"` / `"custom:…"`.
    pub scope: String,
    pub default_actions: Vec<String>,
}

impl From<ResourceType> for ResourceTypeView {
    fn from(rt: ResourceType) -> Self {
        Self {
            name: rt.name,
            scope: rt.scope.as_str().to_string(),
            default_actions: rt.default_actions,
        }
    }
}

// ─── GET /resource_types ────────────────────────────────────────────────────

/// Lists every declared resource type, ordered by `name`.
///
/// Protected: `CurrentUser::require()` → 401 for an anonymous request.
/// Works on `without_rbac()` builds too — see module docs.
pub async fn resource_types(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    let _user = current.require()?;
    let rows = access::registry::list_resource_types(state.saas.pool()).await?;
    let items: Vec<ResourceTypeView> = rows.into_iter().map(ResourceTypeView::from).collect();
    Ok(Json(items))
}
