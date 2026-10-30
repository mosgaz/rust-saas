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
//!
//! Stage 2d adds three non-transactional helpers used by `saas` for
//! owner-guarding (`count_users_with_role`, `has_role`) and for role cleanup
//! on delete (`purge_role`). These helpers do not participate in the
//! caller's SQL transaction; they are idempotent and safe to retry (see
//! handoff §16).

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
    /// implementation must be idempotent: revoking a role the user does not
    /// hold is a no-op.
    async fn revoke_role(
        &self,
        user_id: Uuid,
        domain: &str,
        role_key: &str,
    ) -> Result<(), AuthzError>;

    /// Returns `true` iff `user_id` holds `role_key` in `domain` (i.e. the
    /// `g`-row `(user_id, role_key, domain)` exists).
    ///
    /// Non-transactional; used by `saas::member` owner-guarding. See handoff
    /// §16 for the read-then-write race caveat.
    async fn has_role(
        &self,
        user_id: Uuid,
        domain: &str,
        role_key: &str,
    ) -> Result<bool, AuthzError>;

    /// Returns the number of distinct users holding `role_key` in `domain`.
    ///
    /// This counts `g`-rows only (`casbin_rule` is the source of truth for
    /// authorization, handoff §5 p.4), not `*_members`. Non-transactional;
    /// used by `saas::member` owner-guarding. Returns `0` if the role has no
    /// holders.
    async fn count_users_with_role(&self, domain: &str, role_key: &str) -> Result<i64, AuthzError>;

    /// Deletes every `g`-row and `p`-row for `(domain, role_key)` and
    /// returns the number of deleted rows.
    ///
    /// Used by `saas::access::delete_role` to remove the orphaned Casbin
    /// policies left behind when a role row is deleted from `roles`.
    /// Idempotent: purging a role with no rows is a no-op and returns `0`.
    ///
    /// This is the only method in this trait that performs a bulk delete
    /// without a per-user or per-permission call; implementations may use a
    /// raw `DELETE` against `casbin_rule` and reload their in-memory model
    /// afterwards (see `authz-casbin` for the concrete strategy).
    async fn purge_role(&self, domain: &str, role_key: &str) -> Result<u64, AuthzError>;
}
