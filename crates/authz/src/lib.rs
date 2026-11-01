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

// ─── Stage 4.3a: test-only doubles ──────────────────────────────────────────

/// Test doubles for `AuthorizationEngine` that do not need a database.
///
/// Enabled only under the `test-support` feature (from `[dev-dependencies]`
/// of crates whose tests exercise `saas::*` / `access::*` control flow but
/// do not need real Casbin policy). Production builds must not enable the
/// feature.
///
/// Use [`AllowAllAuthz`] to make every `can` return `true` (so every
/// `require` succeeds) and [`DenyAllAuthz`] to make every `can` return
/// `false` (so every `require` returns [`AuthzError::Forbidden`]).
#[cfg(feature = "test-support")]
pub mod test_support {
    use uuid::Uuid;

    use super::{AuthorizationEngine, AuthzError};

    /// Every `can` returns `true`; `require` succeeds. Grants and revokes
    /// are no-ops (in-memory state does not exist).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct AllowAllAuthz;

    #[async_trait::async_trait]
    impl AuthorizationEngine for AllowAllAuthz {
        async fn can(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _resource: &str,
            _action: &str,
        ) -> Result<bool, AuthzError> {
            Ok(true)
        }

        async fn require(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _resource: &str,
            _action: &str,
        ) -> Result<(), AuthzError> {
            Ok(())
        }

        async fn grant_role(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _role_key: &str,
            _permissions: &[(String, String)],
        ) -> Result<(), AuthzError> {
            Ok(())
        }

        async fn revoke_role(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _role_key: &str,
        ) -> Result<(), AuthzError> {
            Ok(())
        }

        async fn has_role(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _role_key: &str,
        ) -> Result<bool, AuthzError> {
            // Matching `can` semantics: an "allow all" actor is conceptually
            // a holder of every role. Used by owner-guard tests via
            // `saas::member::{change_role, remove_role}` — the guard
            // short-circuits to "the actor holds the role", which is what a
            // permissive double should do.
            Ok(true)
        }

        async fn count_users_with_role(
            &self,
            _domain: &str,
            _role_key: &str,
        ) -> Result<i64, AuthzError> {
            Ok(1)
        }

        async fn purge_role(&self, _domain: &str, _role_key: &str) -> Result<u64, AuthzError> {
            Ok(0)
        }
    }

    /// Every `can` returns `false`; `require` returns
    /// [`AuthzError::Forbidden`]. Used for "actor is forbidden" tests.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct DenyAllAuthz;

    #[async_trait::async_trait]
    impl AuthorizationEngine for DenyAllAuthz {
        async fn can(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _resource: &str,
            _action: &str,
        ) -> Result<bool, AuthzError> {
            Ok(false)
        }

        async fn require(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _resource: &str,
            _action: &str,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden)
        }

        async fn grant_role(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _role_key: &str,
            _permissions: &[(String, String)],
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden)
        }

        async fn revoke_role(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _role_key: &str,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden)
        }

        async fn has_role(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _role_key: &str,
        ) -> Result<bool, AuthzError> {
            Ok(false)
        }

        async fn count_users_with_role(
            &self,
            _domain: &str,
            _role_key: &str,
        ) -> Result<i64, AuthzError> {
            Ok(0)
        }

        async fn purge_role(&self, _domain: &str, _role_key: &str) -> Result<u64, AuthzError> {
            Ok(0)
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
mod test_support_tests {
    use uuid::Uuid;

    use super::test_support::{AllowAllAuthz, DenyAllAuthz};
    use super::{AuthorizationEngine, AuthzError};

    #[tokio::test]
    async fn allow_all_grants_every_check() {
        let a = AllowAllAuthz;
        let uid = Uuid::new_v4();
        assert!(a.can(uid, "d", "r", "a").await.unwrap());
        a.require(uid, "d", "r", "a").await.unwrap();
        assert!(a.has_role(uid, "d", "owner").await.unwrap());
        assert_eq!(a.count_users_with_role("d", "owner").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn deny_all_rejects_every_check() {
        let d = DenyAllAuthz;
        let uid = Uuid::new_v4();
        assert!(!d.can(uid, "d", "r", "a").await.unwrap());
        let err = d.require(uid, "d", "r", "a").await.unwrap_err();
        assert!(matches!(err, AuthzError::Forbidden));
        assert!(!d.has_role(uid, "d", "owner").await.unwrap());
        assert_eq!(d.count_users_with_role("d", "owner").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn allow_all_grant_and_revoke_are_noops() {
        let a = AllowAllAuthz;
        let uid = Uuid::new_v4();
        a.grant_role(uid, "d", "editor", &[("documents".into(), "read".into())])
            .await
            .unwrap();
        a.revoke_role(uid, "d", "editor").await.unwrap();
        a.purge_role("d", "editor").await.unwrap();
    }
}
