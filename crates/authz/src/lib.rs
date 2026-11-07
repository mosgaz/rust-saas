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
//!
//! Phase B (ADR-0010): `AuthzRequest` / `can_request` / `require_request`
//! add an ABAC/ReBAC-aware decision path. The default impls fall back to
//! RBAC via [`AuthorizationEngine::can`]; `authz-casbin` overrides
//! `can_request` with the Casbin ABAC matcher.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("forbidden")]
    Forbidden,
    #[error("internal authorization error: {0}")]
    Internal(String),
    #[error("reload error: {0}")]
    ReloadError(String),
}

/// Request for an ABAC/ReBAC-aware authorization decision.
///
/// Phase B (ADR-0010): ABAC is built on Casbin matchers, not on a separate
/// policy engine. `domain` matches the RBAC domain (`platform` /
/// `tenant:{uuid}` / `workspace:{uuid}`). `subject.roles` and
/// `resource.attrs` are the inputs the Casbin ABAC matcher (B2') reads via
/// `r.sub_roles` / `r.obj_attrs`; `context` is request-level (IP, time, …).
///
/// # Example
///
/// ```ignore
/// let req = AuthzRequest {
///     domain: workspace_domain(ws_id),
///     subject: Subject { id: actor, roles: vec!["editor".into()], attrs: json!({}) },
///     resource: Resource {
///         kind: "document".into(),
///         id: Some(doc_id),
///         attrs: json!({ "owner_id": doc.owner_id, "status": doc.status }),
///     },
///     action: "write".into(),
///     context: Value::Null,
/// };
/// authz.can_request(&req).await?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzRequest {
    /// RBAC domain: `platform` / `tenant:{uuid}` / `workspace:{uuid}`.
    pub domain: String,
    /// The actor (id, role keys, free-form ABAC attributes).
    pub subject: Subject,
    /// The resource being accessed (kind, optional instance id, attributes).
    pub resource: Resource,
    /// The action (`read`, `write`, `manage`, …).
    pub action: String,
    /// Request-level context (IP, time, …). `Value::Null` if unused.
    #[serde(default)]
    pub context: Value,
}

/// The actor in an [`AuthzRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// Stable actor id (matches `casbin_rule.g.v0` / `users.id`).
    pub id: Uuid,
    /// Role keys held by the actor in `domain`. Ignored by the default
    /// (RBAC) impl of [`AuthorizationEngine::can_request`]; used by the
    /// Casbin ABAC matcher (B2').
    #[serde(default)]
    pub roles: Vec<String>,
    /// Free-form ABAC attributes (e.g. `{ "department": "engineering" }`).
    #[serde(default)]
    pub attrs: Value,
}

/// The resource in an [`AuthzRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Resource kind (`document`, `course`, …) — matches
    /// `casbin_rule.p.v2` / `permissions.resource`.
    pub kind: String,
    /// Instance id. `None` for create-flow (no instance yet).
    #[serde(default)]
    pub id: Option<Uuid>,
    /// Free-form ABAC attributes (`owner_id`, `status`, …). Populated by
    /// the caller from the fetched DB row, never trusted from the client.
    #[serde(default)]
    pub attrs: Value,
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

    /// Reload in-memory policy from the backing store.
    ///
    /// No-op for engines without in-memory state (AllowAll, DenyAll, …).
    ///
    /// # Breaking
    /// Trait method added in 0.3.0. All impls must implement it.
    ///
    /// # Phase B note (ADR-0010)
    /// Stays on `AuthorizationEngine` — Phase B is ABAC on Casbin; there
    /// is no `PolicyAdmin` (PAP) split.
    async fn reload_in_memory(&self) -> Result<(), AuthzError>;

    /// ABAC/ReBAC-aware decision (Phase B, ADR-0010).
    ///
    /// # Default implementation
    /// Falls back to RBAC via [`Self::can`]: `subject.id` is the actor,
    /// `resource.kind` is the resource type. `subject.roles`,
    /// `resource.id`, `resource.attrs`, and `context` are ignored.
    ///
    /// This is correct for RBAC-only deployments (`AllowAllAuthz`,
    /// `DenyAllAuthz`) and for pre-ABAC `CasbinAuthz`. `CasbinAuthz`
    /// overrides it in B2' with the real Casbin ABAC matcher.
    ///
    /// # Additive
    /// Trait method added in `0.4.0` with a default impl. Every existing
    /// impl compiles unchanged.
    async fn can_request(&self, req: &AuthzRequest) -> Result<bool, AuthzError> {
        self.can(req.subject.id, &req.domain, &req.resource.kind, &req.action)
            .await
    }

    /// Requires [`Self::can_request`].
    ///
    /// Returns [`AuthzError::Forbidden`] on `false`. Default impl delegates
    /// to [`Self::can_request`]; overridable by ABAC-aware engines if a
    /// richer error is needed.
    async fn require_request(&self, req: &AuthzRequest) -> Result<(), AuthzError> {
        if self.can_request(req).await? {
            Ok(())
        } else {
            Err(AuthzError::Forbidden)
        }
    }
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

        async fn reload_in_memory(&self) -> Result<(), AuthzError> {
            Ok(())
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

        async fn reload_in_memory(&self) -> Result<(), AuthzError> {
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
mod test_support_tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::test_support::{AllowAllAuthz, DenyAllAuthz};
    use super::{AuthorizationEngine, AuthzError, AuthzRequest, Resource, Subject};

    fn sample_request() -> AuthzRequest {
        AuthzRequest {
            domain: "workspace:00000000-0000-0000-0000-000000000001".into(),
            subject: Subject {
                id: Uuid::nil(),
                roles: vec!["editor".into()],
                attrs: json!({ "department": "engineering" }),
            },
            resource: Resource {
                kind: "document".into(),
                id: Some(Uuid::nil()),
                attrs: json!({ "owner_id": Uuid::nil(), "status": "draft" }),
            },
            action: "read".into(),
            context: json!({ "ip": "127.0.0.1" }),
        }
    }

    #[test]
    fn authz_request_serde_roundtrip() {
        let req = sample_request();
        let json = serde_json::to_string(&req).unwrap();
        let back: AuthzRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.domain, req.domain);
        assert_eq!(back.subject.id, req.subject.id);
        assert_eq!(back.subject.roles, req.subject.roles);
        assert_eq!(back.subject.attrs, req.subject.attrs);
        assert_eq!(back.resource.kind, req.resource.kind);
        assert_eq!(back.resource.id, req.resource.id);
        assert_eq!(back.resource.attrs, req.resource.attrs);
        assert_eq!(back.action, req.action);
        assert_eq!(back.context, req.context);
    }

    #[test]
    fn authz_request_defaults_context_to_null() {
        // context is `#[serde(default)]` — omitting it must deserialize to `Value::Null`.
        let json = r#"{
            "domain": "platform",
            "subject": { "id": "00000000-0000-0000-0000-000000000000" },
            "resource": { "kind": "document" },
            "action": "read"
        }"#;
        let req: AuthzRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.context, serde_json::Value::Null);
        assert!(req.subject.roles.is_empty());
        assert_eq!(req.subject.attrs, serde_json::Value::Null);
        assert!(req.resource.id.is_none());
        assert_eq!(req.resource.attrs, serde_json::Value::Null);
    }

    #[tokio::test]
    async fn allow_all_can_request_uses_rbac_fallback() {
        // Default impl → `can`, which `AllowAllAuthz` returns `Ok(true)`.
        let a = AllowAllAuthz;
        assert!(a.can_request(&sample_request()).await.unwrap());
        a.require_request(&sample_request()).await.unwrap();
    }

    #[tokio::test]
    async fn deny_all_can_request_uses_rbac_fallback() {
        let d = DenyAllAuthz;
        assert!(!d.can_request(&sample_request()).await.unwrap());
        let err = d.require_request(&sample_request()).await.unwrap_err();
        assert!(matches!(err, AuthzError::Forbidden));
    }

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
        a.grant_role(uid, "d", "editor", &[("document".into(), "read".into())])
            .await
            .unwrap();
        a.revoke_role(uid, "d", "editor").await.unwrap();
        a.purge_role("d", "editor").await.unwrap();
        a.reload_in_memory().await.unwrap();
    }
}
