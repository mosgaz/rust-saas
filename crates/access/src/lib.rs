//! Access-control crate (ADR-0001, Stage 2e; Stage 2d cleanup helpers).
//!
//! Sole owner of `permissions`, `roles`, and `role_permissions`. DTOs
//! (`Role`, `Permission`, `RoleKey`), `AccessState`, `AccessError`, and the
//! role/permission services (`create_role`, `update_role`, `delete_role`,
//! `list_roles`, `list_permissions`, `get_role`, `get_role_by_id`,
//! `delete_role_by_id`, `get_permissions_for_role`, `create_owner_role`)
//! live here.
//!
//! This crate does not know about HTTP, UI, Leptos, JWT, Argon2, or business
//! tables (`tenants`, `workspaces`, `documents`, `invitations`,
//! `*_members`). It knows `casbin_rule` only indirectly, through
//! `authz::AuthorizationEngine`.
//!
//! Invariant (§5 p.5): every mutation service calls
//! `authz.require(actor.id, domain, "roles", "<action>")` first, except the
//! following helpers (no `actor`, called after `require` in a caller):
//! `get_role`, `get_role_by_id`, `delete_role_by_id`,
//! `get_permissions_for_role`, `list_permissions`, `create_owner_role`.

use std::sync::Arc;

use authz::AuthorizationEngine;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

mod permission;
mod role;

pub use permission::{get_permissions_for_role, list_permissions};
pub use role::{
    create_owner_role, create_role, delete_role, delete_role_by_id, get_role, get_role_by_id,
    list_roles, update_role,
};

/// Errors produced by `access::*`.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    /// `authz.require` denied the action.
    #[error("forbidden")]
    Forbidden,
    /// `RoleKey::parse` rejected the raw string.
    #[error("invalid role key: {0}")]
    InvalidRoleKey(String),
    /// `roles` has no row for `(domain, key)` or no row for `role_id`.
    #[error("role not found: {0}")]
    RoleNotFound(String),
    /// `permissions` has no row for `(resource, action)`.
    #[error("permission not found: {0}:{1}")]
    PermissionNotFound(String, String),
    /// `update_role`/`delete_role` refused a `protected=true` role.
    #[error("role is protected")]
    Protected,
    /// `update_role` refused an `immutable=true` role.
    #[error("role is immutable")]
    Immutable,
    /// Validation failure other than `InvalidRoleKey`.
    #[error("validation error: {0}")]
    Validation(String),
    /// Internal failure (e.g. from the authorization engine).
    #[error("internal error: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl From<authz::AuthzError> for AccessError {
    fn from(e: authz::AuthzError) -> Self {
        match e {
            authz::AuthzError::Forbidden => AccessError::Forbidden,
            authz::AuthzError::Internal(s) => AccessError::Internal(s),
        }
    }
}

/// A `(resource, action)` pair with a description; a row of the `permissions`
/// reference table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    pub resource: String,
    pub action: String,
    pub description: String,
}

impl Permission {
    /// Derived representation for UI/logs: `"documents:read"`.
    pub fn key(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }
}

/// A validated role key: `[a-z0-9_]{1,64}`.
///
/// `#[sqlx(transparent)]` lets sqlx decode a `text` column directly into
/// `RoleKey`; validation happens at construction (`RoleKey::parse`), not at
/// decode. Values inserted by `create_role`/`create_owner_role` are already
/// validated, so DB rows are trusted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct RoleKey(String);

impl RoleKey {
    /// Validates `raw` and wraps it. `[a-z0-9_]{1,64}`.
    pub fn parse(raw: impl Into<String>) -> Result<Self, AccessError> {
        let s: String = raw.into();
        if s.is_empty()
            || s.len() > 64
            || !s
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(AccessError::InvalidRoleKey(s));
        }
        Ok(Self(s))
    }

    /// Borrowed view of the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A role in a domain (data, not code — ADR-0001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub domain: String,
    pub key: RoleKey,
    pub name: String,
    pub description: String,
    pub protected: bool,
    pub immutable: bool,
    pub permissions: Vec<Permission>,
}

/// State shared by every `access::*` service: the database pool and the
/// authorization engine. The actual `casbin_rule` writes on role assignment
/// live in `saas::access::{assign_role, revoke_role}` (which call
/// `authz.grant_role`/`authz.revoke_role`); `access` only stores the role
/// rows and permissions.
pub struct AccessState {
    pool: PgPool,
    authz: Arc<dyn AuthorizationEngine>,
}

impl AccessState {
    /// Builds an [`AccessState`].
    pub fn new(pool: PgPool, authz: Arc<dyn AuthorizationEngine>) -> Self {
        Self { pool, authz }
    }

    /// Shared pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Shared authorization engine.
    pub fn authz(&self) -> &Arc<dyn AuthorizationEngine> {
        &self.authz
    }
}