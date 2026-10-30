//! SaaS business logic: platform, tenant, workspace, documents, invitations.
//!
//! This crate does not know about Leptos, Axum, concrete HTTP handlers,
//! `casbin::Enforcer`, JWT or Argon2. Authorization is delegated to an
//! `authz::AuthorizationEngine`; the actor is `domain::AuthUser` (resolved
//! by `authn` in the consumer).
//!
//! Stage 3c adds [`CoreError::EmailNotVerified`] for addressed invitations:
//! `invitation::accept_invitation` rejects an unverified actor when
//! `invitation.email IS NOT NULL` before comparing the address
//! (verified-first), and rejects a verified actor whose email does not match
//! the invitation address (case-insensitive) with [`CoreError::Forbidden`].
//!
//! Stage 3e (ADR-0004): [`SaasState`] carries an `Arc<dyn AuditLogger>`
//! (default [`NoopAuditLogger`]); [`SaasBuilder::with_audit`] plugs in a
//! real logger (`PgAuditLogger`). Emissions live in submodules:
//! - `platform::create_tenant` / `platform::provision_tenant` →
//!   `tenant.created`.
//! - `tenant::create_workspace` → `workspace.created`.
//! - `invitation::{create, accept, revoke}_invitation` →
//!   `invitation.{created, accepted, revoked}`.
//! - `access::{assign_role, revoke_role, delete_role}` →
//!   `member.role_assigned` / `member.role_revoked` / `role.deleted`.
//! - `member::change_role` → `member.role_changed` (in addition to the
//!   `member.role_assigned` / `member.role_revoked` emitted by its inner
//!   `saas::access::{assign_role, revoke_role}` calls — three events total).
//!
//! `tenant.suspended` / `tenant.activated` are declared in `audit::events`
//! but only emitted in Stage 3f once `suspend_tenant` / `activate_tenant`
//! exist (decision C).
//!
//! Audit is best-effort: a failed write is `tracing::warn!` and does not
//! fail the business operation (ADR-0004 §2.4).

use std::sync::Arc;

use ::access::{AccessError, AccessState, RoleKey};
use audit::{AuditEvent, AuditLogger, NoopAuditLogger};
use authz::{AuthorizationEngine, AuthzError};
use domain::{AuthUser, Document, Tenant, Workspace, PLATFORM_DOMAIN};
use sqlx::PgPool;
use uuid::Uuid;

pub mod access;
pub mod invitation;
pub mod member;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    /// Addressed invitation requires a verified email, but the actor's
    /// email is not verified (Stage 3c). Mapped to HTTP 403 in the
    /// example's `error.rs`, with a distinct message so the UI can offer
    /// "resend verification email" instead of a generic "forbidden".
    #[error("email not verified")]
    EmailNotVerified,
    #[error("not found")]
    NotFound,
    #[error("validation error: {0}")]
    Validation(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl From<AuthzError> for CoreError {
    fn from(e: AuthzError) -> Self {
        match e {
            AuthzError::Forbidden => CoreError::Forbidden,
            AuthzError::Internal(s) => CoreError::Internal(s),
        }
    }
}

impl From<AccessError> for CoreError {
    fn from(e: AccessError) -> Self {
        match e {
            AccessError::Forbidden => CoreError::Forbidden,
            AccessError::InvalidRoleKey(s) => CoreError::Validation(s),
            AccessError::RoleNotFound(_) => CoreError::NotFound,
            AccessError::PermissionNotFound(_, _) => CoreError::NotFound,
            AccessError::Protected => CoreError::Forbidden,
            AccessError::Immutable => CoreError::Forbidden,
            AccessError::Validation(s) => CoreError::Validation(s),
            AccessError::Internal(s) => CoreError::Internal(s),
            AccessError::Db(e) => CoreError::Db(e),
        }
    }
}

#[derive(Clone)]
pub struct SaasState {
    pub(crate) pool: PgPool,
    pub(crate) authz: Arc<dyn AuthorizationEngine>,
    pub(crate) access: Arc<AccessState>,
    pub(crate) audit: Arc<dyn AuditLogger>,
}

impl SaasState {
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn authz(&self) -> &Arc<dyn AuthorizationEngine> {
        &self.authz
    }

    pub fn access(&self) -> &AccessState {
        &self.access
    }

    pub fn audit(&self) -> &Arc<dyn AuditLogger> {
        &self.audit
    }

    /// Best-effort audit write: a failure is `tracing::warn!` and does
    /// **not** propagate (ADR-0004 §2.4). Used by this crate's modules
    /// (platform, tenant, invitation, access, member).
    pub(crate) async fn audit_or_warn(&self, event: AuditEvent) {
        let event_type = event.event_type.clone();
        let actor_id = event.actor_id;
        if let Err(e) = self.audit.log(&event).await {
            tracing::warn!(
                error = %e,
                event_type = %event_type,
                actor_id = ?actor_id,
                "audit log failed"
            );
        }
    }
}

pub struct SaasBuilder {
    pool: PgPool,
    authz: Option<Arc<dyn AuthorizationEngine>>,
    access: Option<Arc<AccessState>>,
    audit: Option<Arc<dyn AuditLogger>>,
}

impl SaasBuilder {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            authz: None,
            access: None,
            audit: None,
        }
    }

    pub fn with_authz(mut self, authz: Arc<dyn AuthorizationEngine>) -> Self {
        self.authz = Some(authz);
        self
    }

    pub fn with_access(mut self, access: Arc<AccessState>) -> Self {
        self.access = Some(access);
        self
    }

    /// Plugs in a real [`AuditLogger`] (`PgAuditLogger`). Without this
    /// call, [`NoopAuditLogger`] is used and no events are recorded
    /// (dev / tests / seed bootstrap — visible as an empty `audit_log`).
    pub fn with_audit(mut self, audit: Arc<dyn AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn build(self) -> Result<SaasState, CoreError> {
        let authz = self.authz.ok_or_else(|| {
            CoreError::Internal("SaasBuilder: authorization engine is required".into())
        })?;
        let access = self
            .access
            .ok_or_else(|| CoreError::Internal("SaasBuilder: access state is required".into()))?;
        let audit = self.audit.unwrap_or_else(|| Arc::new(NoopAuditLogger));
        Ok(SaasState {
            pool: self.pool,
            authz,
            access,
            audit,
        })
    }
}

pub mod platform {
    use super::*;
    use audit::events;

    /// Creates a tenant container. No side effects.
    ///
    /// Emits `tenant.created` (Stage 3e) after the row is committed.
    pub async fn create_tenant(
        state: &SaasState,
        actor: &AuthUser,
        name: String,
    ) -> Result<Tenant, CoreError> {
        state
            .authz
            .require(actor.id, PLATFORM_DOMAIN, "tenants", "create")
            .await?;

        let tenant = sqlx::query_as::<_, Tenant>(
            "insert into tenants (name) values ($1) returning id, name, status, created_at",
        )
        .bind(&name)
        .fetch_one(&state.pool)
        .await?;

        state
            .audit_or_warn(AuditEvent {
                event_type: events::TENANT_CREATED.into(),
                actor_id: Some(actor.id),
                actor_email: Some(actor.email.clone()),
                target_type: Some("tenant".into()),
                target_id: Some(tenant.id),
                metadata: serde_json::json!({ "name": name }),
            })
            .await;

        Ok(tenant)
    }

    /// Creates a tenant and assigns an explicit owner with `owner_role_key`.
    ///
    /// Emits `tenant.created` (Stage 3e) after the transaction commits;
    /// the target is the new tenant, the actor is `actor` (not `owner`).
    pub async fn provision_tenant(
        state: &SaasState,
        actor: &AuthUser,
        name: String,
        owner: &AuthUser,
        owner_role_key: &RoleKey,
    ) -> Result<Tenant, CoreError> {
        state
            .authz
            .require(actor.id, PLATFORM_DOMAIN, "tenants", "create")
            .await?;

        let mut tx = state.pool.begin().await?;

        let tenant = sqlx::query_as::<_, Tenant>(
            "insert into tenants (name) values ($1) returning id, name, status, created_at",
        )
        .bind(&name)
        .fetch_one(&mut *tx)
        .await?;

        let domain_str = domain::tenant_domain(tenant.id);

        ::access::create_owner_role(state.access(), &domain_str)
            .await
            .map_err(CoreError::from)?;

        let permissions =
            ::access::get_permissions_for_role(state.access(), &domain_str, owner_role_key)
                .await
                .map_err(CoreError::from)?;

        state
            .authz
            .grant_role(owner.id, &domain_str, owner_role_key.as_str(), &permissions)
            .await?;

        sqlx::query(
            r#"
            insert into tenant_members (tenant_id, user_id, role)
            values ($1, $2, $3)
            on conflict do nothing
            "#,
        )
        .bind(tenant.id)
        .bind(owner.id)
        .bind(owner_role_key.as_str())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        state
            .audit_or_warn(AuditEvent {
                event_type: events::TENANT_CREATED.into(),
                actor_id: Some(actor.id),
                actor_email: Some(actor.email.clone()),
                target_type: Some("tenant".into()),
                target_id: Some(tenant.id),
                metadata: serde_json::json!({
                    "name": name,
                    "owner_id": owner.id.to_string(),
                    "owner_role_key": owner_role_key.as_str(),
                }),
            })
            .await;

        Ok(tenant)
    }
}

pub mod tenant {
    use super::*;
    use audit::events;

    /// Creates a workspace inside a tenant and assigns the owner as `owner_role_key`.
    ///
    /// Emits `workspace.created` (Stage 3e) after the transaction commits.
    pub async fn create_workspace(
        state: &SaasState,
        actor: &AuthUser,
        tenant_id: Uuid,
        name: String,
        owner: &AuthUser,
        owner_role_key: &RoleKey,
    ) -> Result<Workspace, CoreError> {
        let domain_str = domain::tenant_domain(tenant_id);

        state
            .authz
            .require(actor.id, &domain_str, "workspaces", "create")
            .await?;

        let mut tx = state.pool.begin().await?;

        let workspace = sqlx::query_as::<_, Workspace>(
            r#"
            insert into workspaces (tenant_id, name)
            values ($1, $2)
            returning id, tenant_id, name, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(&name)
        .fetch_one(&mut *tx)
        .await?;

        let ws_domain = domain::workspace_domain(workspace.id);

        ::access::create_owner_role(state.access(), &ws_domain)
            .await
            .map_err(CoreError::from)?;

        let permissions =
            ::access::get_permissions_for_role(state.access(), &ws_domain, owner_role_key)
                .await
                .map_err(CoreError::from)?;

        state
            .authz
            .grant_role(owner.id, &ws_domain, owner_role_key.as_str(), &permissions)
            .await?;

        sqlx::query(
            r#"
            insert into workspace_members (workspace_id, user_id, role)
            values ($1, $2, $3)
            on conflict do nothing
            "#,
        )
        .bind(workspace.id)
        .bind(owner.id)
        .bind(owner_role_key.as_str())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        state
            .audit_or_warn(AuditEvent {
                event_type: events::WORKSPACE_CREATED.into(),
                actor_id: Some(actor.id),
                actor_email: Some(actor.email.clone()),
                target_type: Some("workspace".into()),
                target_id: Some(workspace.id),
                metadata: serde_json::json!({
                    "name": name,
                    "tenant_id": tenant_id.to_string(),
                    "owner_id": owner.id.to_string(),
                    "owner_role_key": owner_role_key.as_str(),
                }),
            })
            .await;

        Ok(workspace)
    }

    /// Lists tenants where the user has at least one role.
    pub async fn list_memberships(
        state: &SaasState,
        user: &AuthUser,
    ) -> Result<Vec<Tenant>, CoreError> {
        let tenants = sqlx::query_as::<_, Tenant>(
            r#"
            select t.id, t.name, t.status, t.created_at
            from tenants t
            where exists (
                select 1 from tenant_members tm
                where tm.tenant_id = t.id and tm.user_id = $1
            )
            order by t.created_at desc
            "#,
        )
        .bind(user.id)
        .fetch_all(state.pool())
        .await?;

        Ok(tenants)
    }
}

pub mod workspace {
    use super::*;

    pub async fn create_document(
        state: &SaasState,
        actor: &AuthUser,
        workspace_id: Uuid,
        title: String,
    ) -> Result<Document, CoreError> {
        let domain_str = domain::workspace_domain(workspace_id);

        state
            .authz
            .require(actor.id, &domain_str, "documents", "write")
            .await?;

        let document = sqlx::query_as::<_, Document>(
            r#"
            insert into documents (workspace_id, title)
            values ($1, $2)
            returning id, workspace_id, title, body, created_at
            "#,
        )
        .bind(workspace_id)
        .bind(title)
        .fetch_one(&state.pool)
        .await?;

        Ok(document)
    }

    pub async fn list_documents(
        state: &SaasState,
        actor: &AuthUser,
        workspace_id: Uuid,
    ) -> Result<Vec<Document>, CoreError> {
        let domain_str = domain::workspace_domain(workspace_id);

        state
            .authz
            .require(actor.id, &domain_str, "documents", "read")
            .await?;

        let documents = sqlx::query_as::<_, Document>(
            r#"
            select id, workspace_id, title, body, created_at
            from documents
            where workspace_id = $1
            order by created_at desc
            "#,
        )
        .bind(workspace_id)
        .fetch_all(&state.pool)
        .await?;

        Ok(documents)
    }

    pub async fn get_document(
        state: &SaasState,
        actor: &AuthUser,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> Result<Document, CoreError> {
        let domain_str = domain::workspace_domain(workspace_id);

        state
            .authz
            .require(actor.id, &domain_str, "documents", "read")
            .await?;

        let document = sqlx::query_as::<_, Document>(
            r#"
            select id, workspace_id, title, body, created_at
            from documents
            where id = $1 and workspace_id = $2
            "#,
        )
        .bind(document_id)
        .bind(workspace_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(CoreError::NotFound)?;

        Ok(document)
    }

    /// Lists workspaces where the user has at least one role.
    pub async fn list_memberships(
        state: &SaasState,
        user: &AuthUser,
    ) -> Result<Vec<Workspace>, CoreError> {
        let workspaces = sqlx::query_as::<_, Workspace>(
            r#"
            select w.id, w.tenant_id, w.name, w.created_at
            from workspaces w
            where exists (
                select 1 from workspace_members wm
                where wm.workspace_id = w.id and wm.user_id = $1
            )
            order by w.created_at desc
            "#,
        )
        .bind(user.id)
        .fetch_all(state.pool())
        .await?;

        Ok(workspaces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use chrono::Utc;
    use domain::InvitationTarget;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RequireCall {
        user_id: Uuid,
        domain: String,
        resource: String,
        action: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct GrantRoleCall {
        user_id: Uuid,
        domain: String,
        role_key: String,
        permissions: Vec<(String, String)>,
    }

    #[derive(Default)]
    struct MockAuthz {
        deny: bool,
        require_calls: Mutex<Vec<RequireCall>>,
        grant_role_calls: Mutex<Vec<GrantRoleCall>>,
        revoke_role_calls: Mutex<Vec<(Uuid, String, String)>>,
    }

    impl MockAuthz {
        fn denying() -> Self {
            Self {
                deny: true,
                ..Default::default()
            }
        }

        fn require_calls(&self) -> Vec<RequireCall> {
            self.require_calls.lock().unwrap().clone()
        }

        fn grant_role_calls(&self) -> Vec<GrantRoleCall> {
            self.grant_role_calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AuthorizationEngine for MockAuthz {
        async fn can(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _resource: &str,
            _action: &str,
        ) -> Result<bool, AuthzError> {
            Ok(!self.deny)
        }

        async fn require(
            &self,
            user_id: Uuid,
            domain: &str,
            resource: &str,
            action: &str,
        ) -> Result<(), AuthzError> {
            self.require_calls.lock().unwrap().push(RequireCall {
                user_id,
                domain: domain.to_string(),
                resource: resource.to_string(),
                action: action.to_string(),
            });
            if self.deny {
                Err(AuthzError::Forbidden)
            } else {
                Ok(())
            }
        }

        async fn grant_role(
            &self,
            user_id: Uuid,
            domain: &str,
            role_key: &str,
            permissions: &[(String, String)],
        ) -> Result<(), AuthzError> {
            self.grant_role_calls.lock().unwrap().push(GrantRoleCall {
                user_id,
                domain: domain.to_string(),
                role_key: role_key.to_string(),
                permissions: permissions.to_vec(),
            });
            Ok(())
        }

        async fn revoke_role(
            &self,
            user_id: Uuid,
            domain: &str,
            role_key: &str,
        ) -> Result<(), AuthzError> {
            self.revoke_role_calls.lock().unwrap().push((
                user_id,
                domain.to_string(),
                role_key.to_string(),
            ));
            Ok(())
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

    fn lazy_state(mock: Arc<MockAuthz>) -> SaasState {
        let pool = PgPool::connect_lazy("postgres://saas-test-host/saas_test")
            .expect("lazy pool must be constructible");
        let access = Arc::new(AccessState::new(
            pool.clone(),
            mock.clone() as Arc<dyn AuthorizationEngine>,
        ));
        SaasBuilder::new(pool)
            .with_authz(mock as Arc<dyn AuthorizationEngine>)
            .with_access(access)
            .build()
            .expect("builder must succeed")
    }

    fn actor() -> AuthUser {
        AuthUser {
            id: Uuid::new_v4(),
            email: "actor@example.test".to_string(),
            email_verified: true,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn create_tenant_requires_platform_tenants_create() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();

        let err = platform::create_tenant(&state, &actor, "Acme".into())
            .await
            .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, PLATFORM_DOMAIN);
        assert_eq!(call.resource, "tenants");
        assert_eq!(call.action, "create");

        assert!(mock.grant_role_calls().is_empty());
    }

    #[tokio::test]
    async fn provision_tenant_requires_platform_tenants_create() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let owner = self::actor();
        let role_key = RoleKey::parse("owner").unwrap();

        let err = platform::provision_tenant(&state, &actor, "Acme".into(), &owner, &role_key)
            .await
            .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, PLATFORM_DOMAIN);
        assert_eq!(call.resource, "tenants");
        assert_eq!(call.action, "create");

        assert!(mock.grant_role_calls().is_empty());
    }

    #[tokio::test]
    async fn create_workspace_requires_tenant_workspaces_create() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let tenant_id = Uuid::new_v4();
        let role_key = RoleKey::parse("owner").unwrap();

        let err = tenant::create_workspace(
            &state,
            &actor,
            tenant_id,
            "Marketing".into(),
            &actor,
            &role_key,
        )
        .await
        .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::tenant_domain(tenant_id));
        assert_eq!(call.resource, "workspaces");
        assert_eq!(call.action, "create");

        assert!(mock.grant_role_calls().is_empty());
    }

    #[tokio::test]
    async fn create_document_requires_workspace_documents_write() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let workspace_id = Uuid::new_v4();

        let err = workspace::create_document(&state, &actor, workspace_id, "Title".into())
            .await
            .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::workspace_domain(workspace_id));
        assert_eq!(call.resource, "documents");
        assert_eq!(call.action, "write");
    }

    #[tokio::test]
    async fn list_documents_requires_workspace_documents_read() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let workspace_id = Uuid::new_v4();

        let err = workspace::list_documents(&state, &actor, workspace_id)
            .await
            .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::workspace_domain(workspace_id));
        assert_eq!(call.resource, "documents");
        assert_eq!(call.action, "read");
    }

    #[tokio::test]
    async fn create_invitation_requires_tenant_invitations_create() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let tenant_id = Uuid::new_v4();

        let err = invitation::create_invitation(
            &state,
            &actor,
            InvitationTarget::Tenant(tenant_id),
            Some("invitee@example.test".into()),
            "owner".into(),
            None,
            Some(1),
        )
        .await
        .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::tenant_domain(tenant_id));
        assert_eq!(call.resource, "invitations");
        assert_eq!(call.action, "create");
    }

    #[tokio::test]
    async fn create_invitation_requires_workspace_invitations_create() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let workspace_id = Uuid::new_v4();

        let err = invitation::create_invitation(
            &state,
            &actor,
            InvitationTarget::Workspace(workspace_id),
            None,
            "editor".into(),
            None,
            None,
        )
        .await
        .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::workspace_domain(workspace_id));
        assert_eq!(call.resource, "invitations");
        assert_eq!(call.action, "create");
    }

    #[tokio::test]
    async fn revoke_invitation_requires_tenant_invitations_revoke() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let tenant_id = Uuid::new_v4();
        let invitation_id = Uuid::new_v4();

        let err = invitation::revoke_invitation(
            &state,
            &actor,
            InvitationTarget::Tenant(tenant_id),
            invitation_id,
        )
        .await
        .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::tenant_domain(tenant_id));
        assert_eq!(call.resource, "invitations");
        assert_eq!(call.action, "revoke");
    }

    #[tokio::test]
    async fn list_invitations_requires_workspace_invitations_list() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let workspace_id = Uuid::new_v4();

        let err =
            invitation::list_invitations(&state, &actor, InvitationTarget::Workspace(workspace_id))
                .await
                .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::workspace_domain(workspace_id));
        assert_eq!(call.resource, "invitations");
        assert_eq!(call.action, "list");
    }

    #[test]
    fn core_error_from_authz_error_forbidden() {
        let err: CoreError = AuthzError::Forbidden.into();
        assert!(matches!(err, CoreError::Forbidden));
    }

    #[test]
    fn core_error_from_authz_error_internal() {
        let err: CoreError = AuthzError::Internal("boom".into()).into();
        match err {
            CoreError::Internal(msg) => assert_eq!(msg, "boom"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}