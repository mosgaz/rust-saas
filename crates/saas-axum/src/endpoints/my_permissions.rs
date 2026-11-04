//! `/my_permissions` endpoints for `saas-axum` (Stage 5.0-A4.4).
//!
//! Two read-only views of the actor's effective permissions in a domain
//! (`?domain=…` query param — `platform` / `tenant:{uuid}` /
//! `workspace:{uuid}`, matching `saas::access::my_permissions`):
//!
//! - `GET /my_permissions`          → `Vec<String>` (`["document:read", …]`),
//!   sorted lexicographically (= sorted by `(resource, action)` because
//!   `:` sorts before any lowercase letter).
//! - `GET /my_permissions/grouped`  → JSON object
//!   `{"document": ["read", "write"], …}`, sorted keys and sorted values.
//!
//! **Divergence with `saas-leptos` (A4.4 → A8 §5.6).**
//! `examples/saas-leptos` returns `Vec<(String, String)>`; `saas-axum`
//! returns flat `Vec<String>` (this module). Unification is tracked as
//! Phase D §D9.
//!
//! **Backend call.** Both handlers delegate to
//! [`saas::access::my_permissions`], which iterates the reference table
//! and calls `authz.can(actor, domain, resource, action)` per row. It is a
//! **read-only UX helper**, not the primary authorization check — the
//! `saas::*` methods still call `authz.require` server-side.
//!
//! **Error mapping.** `saas::CoreError` (DB error, validation, …) →
//! [`AppError`] via `From<CoreError>` (declared in `crate::error`). An
//! invalid `domain` string (not `platform` / `tenant:*` /
//! `workspace:*`) yields an empty permission list from the library —
//! not a 4xx — because `saas::access::my_permissions` does not reject
//! unknown domain formats; it just returns `[]` for them (a non-member
//! has no permissions there either). Documented behaviour; a stricter
//! `domain` check would be a breaking change in the library.
//!
//! Both endpoints are **protected** (no public router mounts them);
//! `CurrentUser::require()` → 401 for an anonymous caller.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::error::AppError;
use crate::extract::CurrentUser;
use crate::state::AxumAppState;

// ─── Query param ────────────────────────────────────────────────────────────

/// `?domain=…` query parameter — `platform`, `tenant:{uuid}`, or
/// `workspace:{uuid}`. Same accepted formats as
/// [`saas::access::my_permissions`]; an unknown format yields an empty
/// permission list (not a 4xx), matching the library.
#[derive(Debug, Deserialize)]
pub struct MyPermissionsQuery {
    pub domain: String,
}

// ─── GET /my_permissions ────────────────────────────────────────────────────

/// Flat view: `["document:read", "document:write", …]`, sorted
/// lexicographically. Sorting is equivalent to sorting by
/// `(resource, action)` because `':'` (`0x3A`) sorts before any
/// lowercase ASCII letter, so `"document:read"` < `"document:write"`
/// < `"workspace:read"` when the pairs are in that order.
pub async fn my_permissions_flat(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Query(q): Query<MyPermissionsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let mut pairs = saas::access::my_permissions(&state.saas, &user, &q.domain).await?;
    // Sort by `(resource, action)` *before* formatting — deterministic
    // output, independent of the library's `my_permissions` iteration
    // order (which walks `permissions` in `(resource, action)` order
    // today, but the contract does not promise it).
    pairs.sort();
    let items: Vec<String> = pairs
        .into_iter()
        .map(|(resource, action)| format!("{resource}:{action}"))
        .collect();
    Ok(Json(items))
}

// ─── GET /my_permissions/grouped ────────────────────────────────────────────

/// Grouped view: `{"document": ["read", "write"], …}`, sorted keys,
/// sorted values.
///
/// Return type is `BTreeMap<String, Vec<String>>` (not `HashMap`) so the
/// JSON is byte-for-byte deterministic regardless of the hash seed — a
/// stable contract for clients and for tests. The wire shape is a plain
/// JSON object; `BTreeMap` and `HashMap` are indistinguishable to a
/// consumer.
///
/// Inner `BTreeSet<String>` collapses duplicate actions (should not occur
/// — `permissions` is keyed by `(resource, action)` — but a future
/// `my_permissions` implementation returning duplicates cannot produce a
/// `["read", "read"]` array).
pub async fn my_permissions_grouped(
    State(state): State<Arc<AxumAppState>>,
    current: CurrentUser,
    Query(q): Query<MyPermissionsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    let pairs = saas::access::my_permissions(&state.saas, &user, &q.domain).await?;

    let mut grouped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (resource, action) in pairs {
        grouped.entry(resource).or_default().insert(action);
    }

    let out: BTreeMap<String, Vec<String>> = grouped
        .into_iter()
        .map(|(resource, actions)| (resource, actions.into_iter().collect()))
        .collect();
    Ok(Json(out))
}
