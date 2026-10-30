//! Audit log abstraction (ADR-0004).
//!
//! Trait-only, no SQL: `audit` does not know about `sqlx`, `SaasState`,
//! `Authn`, or `AccessState`. A concrete implementation (for example
//! `audit-pg`) is plugged in separately and passed to business code as
//! `Arc<dyn AuditLogger>`.
//!
//! Symmetric to `authz` + `authz-casbin` (trait + impl in separate crates).
//!
//! Invariants (ADR-0004):
//! - `log` is called **synchronously after** the business transaction
//!   commits, in its own transaction. A failed `log` is logged via
//!   `tracing::warn!` and does not fail the business operation (§2.4).
//! - `event_type` is a free-form `String` from the [`events`] module — no
//!   enum, no migration needed to add a new event (§2.3, §3.8).
//! - `metadata` is a free-form `serde_json::Value`; per-event shape is
//!   documented in Appendix B, not enforced by the type (decision D).
//! - `NoopAuditLogger` is always available (no feature flag) for dev /
//!   tests / seed (§2.8).
//!
//! Event emission points and 21 constants live in [`events`]. In Stage 3e,
//! 19 events are emitted by `authn`/`access`/`saas`; `tenant.suspended` and
//! `tenant.activated` are declared here but only emitted in Stage 3f, once
//! `saas::platform::{suspend_tenant, activate_tenant}` exist.

use serde::Serialize;
use uuid::Uuid;

/// A single audit event.
///
/// `occurred_at` is not carried on the DTO — the writer (`audit-pg`) lets
/// the database set it via `DEFAULT now()` on insert (§2.3).
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Dot-case event name from [`events`] (`"user.login_succeeded"`).
    pub event_type: String,
    /// Actor user id; `None` for anonymous / system events
    /// (`user.login_failed` with an unknown email).
    pub actor_id: Option<Uuid>,
    /// Denormalized actor email (§2.3): survives `users` row deletion
    /// (`actor_id` becomes `NULL` via `ON DELETE SET NULL`; the email is
    /// kept).
    pub actor_email: Option<String>,
    /// Affected entity type: `"tenant"`, `"workspace"`, `"user"`, `"role"`,
    /// `"invitation"`. `None` for events without a target (`user.login_*`).
    pub target_type: Option<String>,
    /// Affected entity id.
    pub target_id: Option<Uuid>,
    /// Per-event metadata; free-form JSONB. Default is `{}`.
    pub metadata: serde_json::Value,
}

impl AuditEvent {
    /// Builds a minimal event with only `event_type` set; all other fields
    /// default to `None` / `{}`. Emission sites set the remaining fields by
    /// direct field assignment.
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            actor_id: None,
            actor_email: None,
            target_type: None,
            target_id: None,
            metadata: serde_json::json!({}),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit logger failed: {0}")]
    Internal(String),
}

/// Persists an [`AuditEvent`]. Implementations must be `Send + Sync` so that
/// they can be shared as `Arc<dyn AuditLogger>` across the business state.
///
/// Contract (§2.4):
/// - Callers invoke `log` **after** the business transaction commits, in a
///   separate transaction. Do **not** wrap mutations and `log` in one
///   transaction — that would extend ADR-0003's A-lite to audit.
/// - A failed `log` must not fail the business operation; callers log the
///   error via `tracing::warn!` and continue.
#[async_trait::async_trait]
pub trait AuditLogger: Send + Sync {
    async fn log(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

/// No-op logger: always returns `Ok(())`.
///
/// Used as the default in `Authn::new` / `AccessState::new` /
/// `SaasBuilder::build` when `with_audit` was not called (dev / tests /
/// seed bootstrap). Never a substitute for a real logger in production — a
/// consumer that forgets `with_audit` silently produces an empty
/// `audit_log`, visible in the smoke-checklist (§2.8).
pub struct NoopAuditLogger;

#[async_trait::async_trait]
impl AuditLogger for NoopAuditLogger {
    async fn log(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Event-type constants.
///
/// 21 events total (ADR-0004 §2.5). In Stage 3e, 19 are emitted
/// (`authn` 8; `access` 2 + `saas::access::delete_role` 1; `saas` 8);
/// `tenant.suspended` and `tenant.activated` are declared here and emitted
/// in Stage 3f by `saas::platform::{suspend_tenant, activate_tenant}`.
pub mod events {
    pub const USER_REGISTERED: &str = "user.registered";
    pub const USER_LOGIN_SUCCEEDED: &str = "user.login_succeeded";
    pub const USER_LOGIN_FAILED: &str = "user.login_failed";
    pub const USER_LOGOUT: &str = "user.logout";
    pub const USER_REFRESH_REUSED: &str = "user.refresh_reused";
    pub const USER_EMAIL_VERIFIED: &str = "user.email_verified";
    pub const USER_PASSWORD_RESET_REQUESTED: &str = "user.password_reset_requested";
    pub const USER_PASSWORD_RESET_COMPLETED: &str = "user.password_reset_completed";

    pub const TENANT_CREATED: &str = "tenant.created";
    pub const TENANT_SUSPENDED: &str = "tenant.suspended";
    pub const TENANT_ACTIVATED: &str = "tenant.activated";
    pub const WORKSPACE_CREATED: &str = "workspace.created";

    pub const MEMBER_ROLE_ASSIGNED: &str = "member.role_assigned";
    pub const MEMBER_ROLE_REVOKED: &str = "member.role_revoked";
    pub const MEMBER_ROLE_CHANGED: &str = "member.role_changed";

    pub const INVITATION_CREATED: &str = "invitation.created";
    pub const INVITATION_ACCEPTED: &str = "invitation.accepted";
    pub const INVITATION_REVOKED: &str = "invitation.revoked";

    pub const ROLE_CREATED: &str = "role.created";
    pub const ROLE_UPDATED: &str = "role.updated";
    pub const ROLE_DELETED: &str = "role.deleted";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_logger_returns_ok() {
        let logger = NoopAuditLogger;
        let mut ev = AuditEvent::new(events::USER_LOGOUT);
        ev.actor_id = Some(Uuid::new_v4());
        logger.log(&ev).await.expect("noop must succeed");
    }

    #[test]
    fn new_initializes_optional_fields() {
        let ev = AuditEvent::new(events::TENANT_CREATED);
        assert_eq!(ev.event_type, "tenant.created");
        assert!(ev.actor_id.is_none());
        assert!(ev.actor_email.is_none());
        assert!(ev.target_type.is_none());
        assert!(ev.target_id.is_none());
        assert_eq!(ev.metadata, serde_json::json!({}));
    }

    #[test]
    fn events_are_dot_case_and_unique() {
        let all = [
            events::USER_REGISTERED,
            events::USER_LOGIN_SUCCEEDED,
            events::USER_LOGIN_FAILED,
            events::USER_LOGOUT,
            events::USER_REFRESH_REUSED,
            events::USER_EMAIL_VERIFIED,
            events::USER_PASSWORD_RESET_REQUESTED,
            events::USER_PASSWORD_RESET_COMPLETED,
            events::TENANT_CREATED,
            events::TENANT_SUSPENDED,
            events::TENANT_ACTIVATED,
            events::WORKSPACE_CREATED,
            events::MEMBER_ROLE_ASSIGNED,
            events::MEMBER_ROLE_REVOKED,
            events::MEMBER_ROLE_CHANGED,
            events::INVITATION_CREATED,
            events::INVITATION_ACCEPTED,
            events::INVITATION_REVOKED,
            events::ROLE_CREATED,
            events::ROLE_UPDATED,
            events::ROLE_DELETED,
        ];
        assert_eq!(all.len(), 21, "21 events per ADR-0004 §2.5");
        let mut seen = std::collections::HashSet::new();
        for e in all {
            assert!(seen.insert(e), "duplicate event_type: {e}");
            assert!(
                e.contains('.') && !e.contains(' '),
                "event_type must be dot.case: {e}"
            );
        }
    }
}
