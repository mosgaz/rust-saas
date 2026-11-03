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

use serde::{Deserialize, Serialize};

use crate::AccessError;

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

// `bootstrap_*`, `register_resource_type`, `add_action`, `list_resource_types`
// land in Stage 5.0-A1.5b (the type-only step above is A1.5a). Keeping them
// out of this module for now keeps the compiler check focused: `FromRow` /
// `TryFrom<String>` derivation must work before any DB call is written.

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
