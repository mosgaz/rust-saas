//! Resource Registry: runtime declaration of `resource_types` (Stage 5.0-A1.5).
//!
//! Closes blockers B2, B3 (partially — the trigger side is A1.2), B4 from
//! `saas-pluggability-04` §4.
//!
//! A consumer previously had to add `(resource, action)` pairs via a SQL
//! migration (`INSERT INTO permissions`). That was a blocker for "install
//! as a git dependency, no SQL copy". This module exposes a Rust API:
//!
//! - [`bootstrap_resource_type`] — declare a new resource kind together
//!   with its default actions; typically called once in `main.rs` before
//!   `axum::serve`.
//! - [`bootstrap_resource_types`] — the same for a batch, in one
//!   transaction, with a single in-memory reload at the end.
//! - [`bootstrap_all_core`] — idempotent re-run of the 8 core types;
//!   used by `saas-axum`'s `AxumAppStateBuilder::build` so that a
//!   consumer that skipped the bootstrap path still gets them.
//! - [`register_resource_type`] — runtime, permission-checked variant
//!   (`(resource, manage)` in `PLATFORM_DOMAIN`); used by an admin UI.
//! - [`add_action`] — add one action to an existing resource kind;
//!   fails fast with `UnknownResourceType` if the kind is not declared.
//! - [`list_resource_types`] — read-only enumeration.
//!
//! **Transactionality.** Every function that writes to `permissions` (via
//! the A1.2 trigger on `permissions`) is followed by
//! `authz.reload_in_memory()` (Stage 5.0-A1.4) so the current process sees
//! the change without a restart. The reload happens **after** commit — a
//! reload on a transaction that later rolls back would sync from a stale
//! view.
//!
//! **Idempotency.**
//! - `bootstrap_resource_type(s)` is a full upsert: `default_actions` are
//!   array-unioned, `metadata` is jsonb-merged, `scope` is validated (a
//!   change → `ScopeMismatch`). Calling it twice with the same input is a
//!   no-op apart from the `reload_in_memory`.
//! - `register_resource_type` / `add_action` are also idempotent
//!   (`ON CONFLICT DO NOTHING` at every level).
//!
//! **`scope` is declared, not enforced** (see migration A1.1). The Rust
//! type keeps the string representation so that a future consumer can
//! inspect it; enforcement remains in `casbin_rule.p.v1`.
//!
//! Not a cross-table transaction. The `role_permissions` and `casbin_rule`
//! writes are performed by the `owner_sync_permission_after_insert` trigger
//! (A1.2) inside the same transaction as the `INSERT INTO permissions`.
//! ADR-0003 A-lite concerns `saas` + `access` + `authz-casbin` boundaries,
//! not intra-database SQL.

use std::sync::Arc;

use authz::AuthorizationEngine;
use domain::AuthUser;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{AccessError, AccessState};

/// Scope of a resource type.
///
/// `Platform` / `Tenant` / `Workspace` describe the *usual* domain.
/// `Custom(_)` holds the full string (`custom:legacy`, `custom:course:abc`
/// in Phase B) — see the migration's header comment for "declared, not
/// enforced".
///
/// String representation (via [`ResourceScope::as_str`] and
/// [`std::str::FromStr`]): `"platform"` / `"tenant"` / `"workspace"` /
/// `"custom:…"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceScope {
    Platform,
    Tenant,
    Workspace,
    /// Full `custom:*` string. Kept as `String` (not a nested enum) so
    /// Phase B's `custom:<resource>:<id>` format does not need a
    /// migration.
    Custom(String),
}

impl ResourceScope {
    pub fn as_str(&self) -> &str {
        match self {
            ResourceScope::Platform => "platform",
            ResourceScope::Tenant => "tenant",
            ResourceScope::Workspace => "workspace",
            ResourceScope::Custom(s) => s,
        }
    }
}

impl std::fmt::Display for ResourceScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ResourceScope {
    type Err = AccessError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "platform" => Ok(ResourceScope::Platform),
            "tenant" => Ok(ResourceScope::Tenant),
            "workspace" => Ok(ResourceScope::Workspace),
            other if other.starts_with("custom:") => {
                Ok(ResourceScope::Custom(other.to_string()))
            }
            other => Err(AccessError::Validation(format!(
                "invalid resource scope: {other}"
            ))),
        }
    }
}

impl TryFrom<String> for ResourceScope {
    type Error = AccessError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        use std::str::FromStr;
        Self::from_str(&s)
    }
}

/// A declared resource type; a row of the `resource_types` table.
///
/// `default_actions` is advisory — the source of truth for what a role
/// can actually be assigned is `permissions` (see migration A1.1's header
/// comment). `metadata` is free-form JSONB, reserved for consumer tags and
/// (Phase B) ABAC attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct ResourceType {
    pub name: String,
    #[sqlx(try_from = "String")]
    pub scope: ResourceScope,
    pub default_actions: Vec<String>,
    pub description: String,
    pub metadata: serde_json::Value,
}

impl ResourceType {
    /// New `platform`-scoped resource type.
    pub fn platform(name: &str, actions: &[&str]) -> Self {
        Self::new(name, ResourceScope::Platform, actions)
    }

    /// New `tenant`-scoped resource type.
    pub fn tenant(name: &str, actions: &[&str]) -> Self {
        Self::new(name, ResourceScope::Tenant, actions)
    }

    /// New `workspace`-scoped resource type.
    pub fn workspace(name: &str, actions: &[&str]) -> Self {
        Self::new(name, ResourceScope::Workspace, actions)
    }

    fn new(name: &str, scope: ResourceScope, actions: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            scope,
            default_actions: actions.iter().map(|a| a.to_string()).collect(),
            description: String::new(),
            metadata: serde_json::json!({}),
        }
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn with_metadata(mut self, m: serde_json::Value) -> Self {
        self.metadata = m;
        self
    }
}

// ─── Bootstrap API (Stage 5.0-A1.5b) ───────────────────────────────────────

/// Declare one new resource type. Idempotent.
///
/// Equivalent to [`bootstrap_resource_types`] with a one-element slice.
pub async fn bootstrap_resource_type(
    pool: &PgPool,
    authz: &Arc<dyn AuthorizationEngine>,
    resource: &ResourceType,
) -> Result<(), AccessError> {
    bootstrap_resource_types(pool, authz, std::slice::from_ref(resource)).await
}

/// Declare N new resource types in one transaction, with one in-memory
/// reload at the end.
///
/// Per-type merge (idempotent):
/// - `default_actions` — array-union with the existing value, sorted.
/// - `metadata` — jsonb-merge (`existing || new`); new keys override.
/// - `scope` — **not** updated. A mismatch against the existing row
///   aborts the whole batch with [`AccessError::ScopeMismatch`].
/// - `description` — overwritten only if the incoming value is non-empty;
///   an empty string never clobbers an existing description. (First-time
///   inserts take the incoming value as-is.)
///
/// Every `(name, action)` from `default_actions` is also inserted into
/// `permissions` (`ON CONFLICT DO NOTHING`); the A1.2 trigger then
/// propagates it to `role_permissions` and `casbin_rule.p` for every
/// `owner` role in every domain, inside the same transaction.
///
/// After `COMMIT`: `authz.reload_in_memory()` — one call, after the
/// transaction has committed. A reload before commit would sync a
/// pre-commit view into memory.
pub async fn bootstrap_resource_types(
    pool: &PgPool,
    authz: &Arc<dyn AuthorizationEngine>,
    resources: &[ResourceType],
) -> Result<(), AccessError> {
    // Pre-flight: reject scope changes *before* opening the transaction.
    // Two passes would be needed inside the tx anyway (scope is a PK
    // column and cannot be changed via `ON CONFLICT DO UPDATE`); doing it
    // outside keeps the error path free of rollbacks.
    for r in resources {
        if let Some(existing) =
            sqlx::query_scalar::<_, String>("select scope from resource_types where name = $1")
                .bind(&r.name)
                .fetch_optional(pool)
                .await?
        {
            if existing != r.scope.as_str() {
                return Err(AccessError::ScopeMismatch {
                    name: r.name.clone(),
                    existing,
                    requested: r.scope.as_str().to_string(),
                });
            }
        }
    }

    let mut tx = pool.begin().await?;

    for r in resources {
        sqlx::query(
            r#"
            insert into resource_types (name, scope, default_actions, metadata, description)
            values ($1, $2, $3, $4, $5)
            on conflict (name) do update set
                default_actions = (
                    select array_agg(distinct x order by x)
                    from unnest(resource_types.default_actions || excluded.default_actions) as x
                ),
                metadata = resource_types.metadata || excluded.metadata,
                description = case
                    when excluded.description = '' then resource_types.description
                    else excluded.description
                end
            "#,
        )
        .bind(&r.name)
        .bind(r.scope.as_str())
        .bind(&r.default_actions)
        .bind(&r.metadata)
        .bind(&r.description)
        .execute(&mut *tx)
        .await?;

        for action in &r.default_actions {
            sqlx::query(
                r#"
                insert into permissions (resource, action, description)
                values ($1, $2, '')
                on conflict (resource, action) do nothing
                "#,
            )
            .bind(&r.name)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;

    // A1.4: refresh in-memory enforcer after the commit. Exactly one call
    // per batch, regardless of how many types/actions it declared.
    authz.reload_in_memory().await?;

    Ok(())
}

/// Idempotently re-declare the 8 core types (and their actions) that ship
/// with the A1.1 migration.
///
/// Called by `saas-axum`'s `AxumAppStateBuilder::build` (A4.2) so that a
/// consumer that skipped the `main.rs` bootstrap path still gets the core
/// types registered. Safe to call on every process start.
pub async fn bootstrap_all_core(
    pool: &PgPool,
    authz: &Arc<dyn AuthorizationEngine>,
) -> Result<(), AccessError> {
    let core = [
        ResourceType::platform("tenant", &["create", "list", "manage"])
            .with_description("Tenant containers"),
        ResourceType::tenant("workspace", &["create", "read"])
            .with_description("Workspaces inside a tenant"),
        ResourceType::workspace("document", &["read", "write"])
            .with_description("Documents in a workspace"),
        ResourceType::tenant("member", &["list", "manage"])
            .with_description("Members (tenant/workspace domains)"),
        ResourceType::tenant("invitation", &["create", "list", "revoke"])
            .with_description("Invitations (tenant/workspace domains)"),
        ResourceType::tenant("role", &["create", "delete", "grant", "list", "manage"])
            .with_description("Roles (tenant/workspace domains)"),
        ResourceType::platform("audit", &["read"]).with_description("Audit log"),
        ResourceType::platform("resource", &["manage"])
            .with_description("Resource registry itself"),
    ];
    bootstrap_resource_types(pool, authz, &core).await
}

/// Runtime, permission-checked variant of [`bootstrap_resource_type`].
///
/// Requires `(resource, manage)` in `PLATFORM_DOMAIN`. Intended for an
/// admin UI that lets a privileged user register resource types from the
/// running application (vs `bootstrap_*` which is a `main.rs` startup
/// call with no actor).
pub async fn register_resource_type(
    state: &AccessState,
    actor: &AuthUser,
    resource: &ResourceType,
) -> Result<(), AccessError> {
    state
        .authz()
        .require(actor.id, domain::PLATFORM_DOMAIN, "resource", "manage")
        .await?;
    bootstrap_resource_type(state.pool(), state.authz(), resource).await
}

/// Add a single action to an already-declared resource type.
///
/// Fail-fast: if `resource_name` is not in `resource_types`, returns
/// [`AccessError::UnknownResourceType`] before touching `permissions`
/// (avoiding a raw FK violation from the A1.3 constraint).
///
/// Requires `(resource, manage)` in `PLATFORM_DOMAIN`.
pub async fn add_action(
    state: &AccessState,
    actor: &AuthUser,
    resource_name: &str,
    action: &str,
) -> Result<(), AccessError> {
    state
        .authz()
        .require(actor.id, domain::PLATFORM_DOMAIN, "resource", "manage")
        .await?;

    let exists: bool = sqlx::query_scalar(
        "select exists(select 1 from resource_types where name = $1)",
    )
    .bind(resource_name)
    .fetch_one(state.pool())
    .await?;

    if !exists {
        return Err(AccessError::UnknownResourceType {
            name: resource_name.to_string(),
        });
    }

    sqlx::query(
        r#"
        insert into permissions (resource, action, description)
        values ($1, $2, '')
        on conflict (resource, action) do nothing
        "#,
    )
    .bind(resource_name)
    .bind(action)
    .execute(state.pool())
    .await?;

    state.authz().reload_in_memory().await?;

    Ok(())
}

/// List every declared resource type, ordered by `name`.
///
/// No `actor` — the reference is not sensitive (same exemption as
/// `list_permissions`; §5 p.5).
pub async fn list_resource_types(pool: &PgPool) -> Result<Vec<ResourceType>, AccessError> {
    let rows = sqlx::query_as::<_, ResourceType>(
        r#"
        select name, scope, default_actions, description, metadata
        from resource_types
        order by name
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn scope_parse_roundtrip() {
        for (s, want) in [
            ("platform", ResourceScope::Platform),
            ("tenant", ResourceScope::Tenant),
            ("workspace", ResourceScope::Workspace),
            (
                "custom:legacy",
                ResourceScope::Custom("custom:legacy".to_string()),
            ),
            (
                "custom:course:abc",
                ResourceScope::Custom("custom:course:abc".to_string()),
            ),
        ] {
            let parsed = ResourceScope::from_str(s).unwrap();
            assert_eq!(parsed, want);
            assert_eq!(parsed.as_str(), s);
        }
    }

    #[test]
    fn scope_parse_rejects_unknown() {
        assert!(ResourceScope::from_str("nonsense").is_err());
        assert!(ResourceScope::from_str("Custom:foo").is_err());
        assert!(ResourceScope::from_str("").is_err());
    }

    #[test]
    fn scope_try_from_string() {
        let s = ResourceScope::try_from("workspace".to_string()).unwrap();
        assert_eq!(s, ResourceScope::Workspace);
    }

    #[test]
    fn constructors_set_scope_and_actions() {
        let p = ResourceType::platform("x", &["a", "b"]);
        assert_eq!(p.scope, ResourceScope::Platform);
        assert_eq!(p.default_actions, vec!["a", "b"]);
        assert_eq!(p.metadata, serde_json::json!({}));

        let t = ResourceType::tenant("y", &["c"]);
        assert_eq!(t.scope, ResourceScope::Tenant);

        let w = ResourceType::workspace("course", &["read", "write"])
            .with_description("Course")
            .with_metadata(serde_json::json!({"tag": "lms"}));
        assert_eq!(w.scope, ResourceScope::Workspace);
        assert_eq!(w.description, "Course");
        assert_eq!(w.metadata["tag"], "lms");
    }
}
