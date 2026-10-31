//! Tenant handlers for `axum-minimal` (Stage 3g).
//!
//! Covers the two `/tenants` endpoints in plan §3:
//!
//! - `GET  /tenants` — `saas::tenant::list_memberships`; returns the
//!   tenants the current user is a member of. Read-only; **no**
//!   `resolve_active_tenant` (membership is the only filter — a suspended
//!   tenant must still be listed so its members can see it; ADR-0002
//!   rev.2 §2.4).
//! - `POST /tenants` — `saas::platform::provision_tenant` with
//!   `actor == owner`: the caller becomes the tenant's `owner`. Same
//!   behaviour as `saas-leptos`'s `#[server] create_tenant`
//!   (`pages/platform.rs`), which keeps the name `create_tenant` and
//!   delegates to `provision_tenant` with `owner = actor`. `(tenants,
//!   create)` in `PLATFORM_DOMAIN` is enforced inside the service.
//!
//! **No `resolve_active_tenant` in `create_tenant`.** Provisioning creates
//! a **new** tenant; there is no pre-existing tenant to resolve. The
//! Stage 3f invariant (`resolve` before mutating an existing tenant's
//! resources) does not apply here — the target tenant does not exist yet.
//!
//! **Response shapes.**
//!
//! - `GET  /tenants` → `200` + `[ { … Tenant … }, … ]`
//! - `POST /tenants` → `200` + `{ … Tenant … }` (the new tenant)

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use access::RoleKey;
use domain::Tenant;
use serde::Deserialize;

use crate::error::AppError;
use crate::extract::CurrentUser;
use crate::state::AppState;

// ─── GET /tenants ──────────────────────────────────────────────────────────

/// Lists the tenants the current user is a member of.
///
/// Read-only; no `resolve_active_tenant` (see module doc).
pub async fn list_my_tenants(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let tenants = saas::tenant::list_memberships(&state.saas, &user).await?;
    Ok(Json(tenants))
}

// ─── POST /tenants ─────────────────────────────────────────────────────────

/// Body of `POST /tenants`.
#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
}

/// Creates a tenant and assigns the caller as its `owner`.
///
/// Delegates to `saas::platform::provision_tenant` with
/// `owner_role_key = "owner"`, `owner = actor` — the same contract as
/// `saas-leptos`'s `#[server] create_tenant`. Requires `(tenants, create)`
/// in `PLATFORM_DOMAIN`; the `require` lives inside the service.
pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
    Json(body): Json<CreateTenantRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;

    let owner_key = RoleKey::parse("owner").map_err(|e| AppError::Access(e))?;

    let tenant: Tenant =
        saas::platform::provision_tenant(&state.saas, &user, body.name, &user, &owner_key)
            .await?;

    Ok(Json(tenant))
}