//! Authorization abstraction: the `AuthorizationEngine` trait and error types.
//!
//! This crate is trait-only: no Casbin, no SQL, no HTTP, no Leptos, no JWT.
//! A concrete implementation (for example `authz-casbin`) is plugged in
//! separately and passed to business code as `Arc<dyn AuthorizationEngine>`.
//!
//! Roles are data, not code (ADR-0001). The engine knows only `g`-rows
//! (`user -> role_key -> domain`) and `p`-rows (`role_key -> domain ->
//! resource -> action`). It does not know about `owner`, `editor`, or any
//! other specific role.

use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("forbidden")]
    Forbidden,
    #[error("internal authorization error: {0}")]
    Internal(String),
}

#[async_trait::async_trait]
pub trait AuthorizationEngine: Send + Sync {
    /// Checks whether `user_id` can perform `(resource, action)` in `domain`.
    async fn can(
        &self,
        user_id: Uuid,
        domain: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, AuthzError>;

    /// Requires that `user_id` can perform `(resource, action)` in `domain`.
    /// Returns [`AuthzError::Forbidden`] otherwise.
    async fn require(
        &self,
        user_id: Uuid,
        domain: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), AuthzError>;

    /// Grants `role_key` to `user_id` in `domain` with the given permissions.
    ///
    /// `permissions` is a list of `(resource, action)` pairs. Writes one
    /// `g`-row (`user -> role_key -> domain`) and one `p`-row for each
    /// `(resource, action)`. The implementation must be idempotent.
    async fn grant_role(
        &self,
        user_id: Uuid,
        domain: &str,
        role_key: &str,
        permissions: &[(String, String)],
    ) -> Result<(), AuthzError>;

    /// Revokes `role_key` from `user_id` in `domain`.
    ///
    /// Removes the `g`-row. The `p`-rows are shared by all users with this
    /// role in this domain and remain intact while the role exists. The
    /// implementation must be idempotent.
    async fn revoke_role(
        &self,
        user_id: Uuid,
        domain: &str,
        role_key: &str,
    ) -> Result<(), AuthzError>;
}
