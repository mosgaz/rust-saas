//! Shared business types and authorization domain name helpers.
//!
//! This crate is a pure type layer: no SQL, no logic, no Casbin.
//! `sqlx::FromRow` / `sqlx::Type` derives are gated behind the `ssr` feature.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A customer organization (company) on the platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub status: TenantStatus,
    pub created_at: DateTime<Utc>,
}

/// Tenant lifecycle status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ssr", derive(sqlx::Type))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "ssr", sqlx(type_name = "text", rename_all = "snake_case"))]
pub enum TenantStatus {
    Active,
    Suspended,
}

/// A working area inside a tenant (team, department, project).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
pub struct Workspace {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// A business resource inside a workspace.
///
/// A `document` is `title: String` + `body: text`; it is not a file.
/// File attachments are a separate entity, out of MVP scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
pub struct Document {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub title: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

/// A global platform user (no `password_hash`; internal in `identity`).
///
/// `email_verified` is a **derived** boolean: `true` iff
/// `users.email_verified_at IS NOT NULL`. It is populated by SQL
/// (`email_verified_at IS NOT NULL AS email_verified`) in every `SELECT`
/// that maps a `users` row to `AuthUser`; see the `identity` crate. There is
/// no `email_verified_at` field on this DTO — the timestamp is an internal
/// concern of `identity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

/// Test-only constructors; enabled via the `test-support` feature (added to
/// `[dev-dependencies]` of the crates that need them). Production builds
/// must not enable this feature.
#[cfg(feature = "test-support")]
impl AuthUser {
    /// Test-only: an `AuthUser` with `email_verified = true`.
    pub fn test_verified() -> Self {
        Self {
            id: Uuid::new_v4(),
            email: format!("verified-{}@test.local", Uuid::new_v4()),
            email_verified: true,
            created_at: Utc::now(),
        }
    }

    /// Test-only: an `AuthUser` with `email_verified = false`.
    pub fn test_unverified() -> Self {
        Self {
            id: Uuid::new_v4(),
            email: format!("unverified-{}@test.local", Uuid::new_v4()),
            email_verified: false,
            created_at: Utc::now(),
        }
    }
}

/// An invitation row.
///
/// Exactly one of `tenant_id` / `workspace_id` is `Some` (enforced by the
/// `invitations` table CHECK constraint). `email IS NULL` means a reusable
/// link; `email IS NOT NULL` means an addressed invitation (until email
/// verification, Stage 3, addressed invitations are effectively links; see
/// handoff §16).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
pub struct Invitation {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub email: Option<String>,
    pub role: String,
    pub token_hash: String,
    pub created_by: Uuid,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<i32>,
    pub used_count: i32,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// The target scope of an invitation.
///
/// `saas::invitation::create_invitation` accepts this as a parameter; the
/// `Invitation` DTO stores the scope as two nullable columns
/// (`tenant_id` / `workspace_id`) for direct `sqlx::FromRow` mapping.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvitationTarget {
    Tenant(Uuid),
    Workspace(Uuid),
}

/// A membership entry: a user together with all `role_key`s they hold in a
/// scope (tenant or workspace).
///
/// `roles` holds raw `role_key` strings rather than `access::RoleKey` so
/// that `domain` does not depend on `access` (see the forbidden edges in
/// handoff §4). The `access::*` layer validates keys at write time; the
/// bookkeeping rows copied here are already validated.
///
/// No `sqlx::FromRow` derive: `roles` is an aggregate over `*_members` rows
/// and is assembled in `saas::member::list` from flat `(user_id, email,
/// role, created_at)` tuples grouped by `user_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub user_id: Uuid,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
}

pub const PLATFORM_DOMAIN: &str = "platform";

/// Casbin domain for a tenant.
pub fn tenant_domain(tenant_id: Uuid) -> String {
    format!("tenant:{tenant_id}")
}

/// Casbin domain for a workspace.
pub fn workspace_domain(workspace_id: Uuid) -> String {
    format!("workspace:{workspace_id}")
}
