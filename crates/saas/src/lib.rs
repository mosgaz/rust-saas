//! SaaS business logic: platform, tenant, workspace, documents, invitations.
//!
//! This crate does not know about Leptos, Axum, concrete HTTP handlers,
//! `casbin::Enforcer`, JWT or Argon2. Authorization is delegated to an
//! `authz::AuthorizationEngine`; the actor is `domain::AuthUser` (resolved
//! by `authn` in the consumer).
//!
//! **Invariant (§5 p.5):** every service calls `authz.require` first, with
//! two explicit exceptions:
//! - `invitation::accept_invitation` authorizes by the invitation token.
//! - `tenant::list_memberships` / `workspace::list_memberships` are
//!   membership queries (not protected actions): there is no domain to
//!   `require` before knowing the result. `*_members` is the authoritative
//!   source for "which tenants/workspaces am I a member of"; `casbin_rule`
//!   remains the source of truth for what can be done **inside** a tenant or
//!   workspace (Appendix B §2.10).

use std::sync::Arc;

use authz::{AuthzError, AuthorizationEngine, WorkspaceRole};
use domain::{AuthUser, Document, Tenant, Workspace, PLATFORM_DOMAIN};
use sqlx::PgPool;
use uuid::Uuid;

pub mod invitation;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
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

#[derive(Clone)]
pub struct SaasState {
    pool: PgPool,
    authz: Arc<dyn AuthorizationEngine>,
}

impl SaasState {
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn authz(&self) -> &Arc<dyn AuthorizationEngine> {
        &self.authz
    }
}

pub struct SaasBuilder {
    pool: PgPool,
    authz: Option<Arc<dyn AuthorizationEngine>>,
}

impl SaasBuilder {
    pub fn new(pool: PgPool) -> Self {
        Self { pool, authz: None }
    }

    pub fn with_authz(mut self, authz: Arc<dyn AuthorizationEngine>) -> Self {
        self.authz = Some(authz);
        self
    }

    pub fn build(self) -> Result<SaasState, CoreError> {
        let authz = self
            .authz
            .ok_or_else(|| CoreError::Internal("SaasBuilder: authorization engine is required".into()))?;
        Ok(SaasState {
            pool: self.pool,
            authz,
        })
    }
}

pub mod platform {
    use super::*;

    /// Creates a tenant container.
    ///
    /// Order:
    /// 1. `authz.require(actor.id, "platform", "tenants", "create")` — first.
    /// 2. `INSERT tenants` — no transaction, no side effects.
    ///
    /// The creator does **not** become a member of the new tenant. Owner
    /// assignment is a separate action: use [`provision_tenant`] when the
    /// owner already exists, or an invitation flow (Stage 2) when not.
    ///
    /// A tenant created with `create_tenant` has no owner until
    /// `provision_tenant` (or invitation-accept) is called; the resulting row
    /// is a valid container but is not accessible for tenant-scoped operations
    /// (no `tenant_owner` in `casbin_rule`). See handoff §16.
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
        .bind(name)
        .fetch_one(&state.pool)
        .await?;

        Ok(tenant)
    }

    /// Creates a tenant and explicitly assigns an owner.
    ///
    /// Order:
    /// 1. `authz.require(actor.id, "platform", "tenants", "create")` — first.
    /// 2. `tx.begin`.
    /// 3. `INSERT tenants` + `INSERT tenant_members(owner.id, 'owner')`.
    /// 4. `authz.grant_tenant_owner(owner.id, tenant.id)`.
    /// 5. `tx.commit`.
    ///
    /// `actor` and `owner` are different roles: `actor` acts in the `platform`
    /// domain (creates the container), `owner` receives `tenant_owner` in the
    /// new tenant. When `actor == owner`, the UI scenario "created → became
    /// owner" holds; when they differ, a platform admin provisions a tenant
    /// for someone else without becoming a member.
    ///
    /// `owner` is `&AuthUser`, not `owner_email: &str`: `saas` does not look
    /// up users by email (that is `identity` semantics).
    ///
    /// Residual limitation: `authz-casbin` writes to `casbin_rule` via its
    /// own pool, outside the `state.pool` transaction. See handoff §16.
    pub async fn provision_tenant(
        state: &SaasState,
        actor: &AuthUser,
        name: String,
        owner: &AuthUser,
    ) -> Result<Tenant, CoreError> {
        state
            .authz
            .require(actor.id, PLATFORM_DOMAIN, "tenants", "create")
            .await?;

        let mut tx = state.pool.begin().await?;

        let tenant = sqlx::query_as::<_, Tenant>(
            "insert into tenants (name) values ($1) returning id, name, status, created_at",
        )
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            insert into tenant_members (tenant_id, user_id, role)
            values ($1, $2, 'owner')
            on conflict (tenant_id, user_id) do update set role = excluded.role
            "#,
        )
        .bind(tenant.id)
        .bind(owner.id)
        .execute(&mut *tx)
        .await?;

        state
            .authz
            .grant_tenant_owner(owner.id, tenant.id)
            .await?;

        tx.commit().await?;

        Ok(tenant)
    }
}

pub mod tenant {
    use super::*;

    /// Creates a workspace inside a tenant and assigns the creator as
    /// `workspace_admin`.
    ///
    /// Order:
    /// 1. `authz.require(actor.id, "tenant:{id}", "workspaces", "create")` — first.
    /// 2. Transaction: `INSERT workspaces` + `INSERT workspace_members(role='admin')`.
    /// 3. `authz.grant_workspace_role(actor.id, workspace.id, WorkspaceRole::Admin)`.
    /// 4. `COMMIT`.
    ///
    /// The side-effect "creator becomes `workspace_admin`" is preserved
    /// (unlike `platform::create_tenant`): a workspace is a working unit, and
    /// its creator is by definition its admin.
    pub async fn create_workspace(
        state: &SaasState,
        actor: &AuthUser,
        tenant_id: Uuid,
        name: String,
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
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            insert into workspace_members (workspace_id, user_id, role)
            values ($1, $2, 'admin')
            on conflict (workspace_id, user_id) do update set role = excluded.role
            "#,
        )
        .bind(workspace.id)
        .bind(actor.id)
        .execute(&mut *tx)
        .await?;

        state
            .authz
            .grant_workspace_role(actor.id, workspace.id, WorkspaceRole::Admin)
            .await?;

        tx.commit().await?;

        Ok(workspace)
    }

    /// Lists tenants the given user is a member of, newest first.
    ///
    /// **Exception to §5 p.5** (`authz.require` first): this is a membership
    /// query, not a protected action. There is no domain to `require` before
    /// knowing the result. `tenant_members` is the authoritative source for
    /// "which tenants is this user a member of" (Appendix B §2.10);
    /// `casbin_rule` remains the authoritative source for what the user can
    /// do **inside** each tenant. A platform admin who provisioned a tenant
    /// for someone else (actor ≠ owner) is not a member and does not see it
    /// here — consistent with §2.13 (platform admin is not a superuser).
    pub async fn list_memberships(
        state: &SaasState,
        user: &AuthUser,
    ) -> Result<Vec<Tenant>, CoreError> {
        let tenants = sqlx::query_as::<_, Tenant>(
            r#"
            select t.id, t.name, t.status, t.created_at
            from tenants t
            join tenant_members tm on tm.tenant_id = t.id
            where tm.user_id = $1
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

    /// Creates a document inside a workspace.
    ///
    /// Authorization is checked first
    /// (`workspace:{id}`, `documents`, `write`), then the row is inserted.
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

    /// Lists documents in a workspace.
    ///
    /// Authorization is checked first
    /// (`workspace:{id}`, `documents`, `read`), then the rows are selected.
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

    /// Lists workspaces the given user is a member of, newest first.
    ///
    /// **Exception to §5 p.5** (`authz.require` first): see
    /// [`tenant::list_memberships`] for the rationale. `workspace_members` is
    /// the membership source of truth; `casbin_rule` remains the source of
    /// truth for actions **inside** the workspace.
    pub async fn list_memberships(
        state: &SaasState,
        user: &AuthUser,
    ) -> Result<Vec<Workspace>, CoreError> {
        let workspaces = sqlx::query_as::<_, Workspace>(
            r#"
            select w.id, w.tenant_id, w.name, w.created_at
            from workspaces w
            join workspace_members wm on wm.workspace_id = w.id
            where wm.user_id = $1
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
    //! Unit tests for `saas` without a real database.
    //!
    //! `PgPool::connect_lazy` creates a pool without opening a connection.
    //! The mock `AuthorizationEngine` is set to `deny` mode, so `authz.require`
    //! fails before `saas` touches the database.
    //!
    //! `accept_invitation` and `*::list_memberships` have no unit tests here:
    //! they do not call `authz.require` and go straight to SQL, which a lazy
    //! pool cannot serve. Covered by integration tests (`tests/integration.rs`).

    use super::*;
    use std::sync::Mutex;

    use authz::{AuthzError, AuthorizationEngine, WorkspaceRole};
    use chrono::Utc;
    use domain::{AuthUser, InvitationTarget};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RequireCall {
        user_id: Uuid,
        domain: String,
        object: String,
        action: String,
    }

    #[derive(Default)]
    struct MockAuthz {
        deny: bool,
        require_calls: Mutex<Vec<RequireCall>>,
        grant_tenant_owner_calls: Mutex<Vec<(Uuid, Uuid)>>,
        grant_workspace_role_calls: Mutex<Vec<(Uuid, Uuid, String)>>,
        grant_platform_admin_calls: Mutex<Vec<Uuid>>,
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

        fn grant_tenant_owner_calls(&self) -> Vec<(Uuid, Uuid)> {
            self.grant_tenant_owner_calls.lock().unwrap().clone()
        }

        fn grant_workspace_role_calls(&self) -> Vec<(Uuid, Uuid, String)> {
            self.grant_workspace_role_calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AuthorizationEngine for MockAuthz {
        async fn can(
            &self,
            _user_id: Uuid,
            _domain: &str,
            _object: &str,
            _action: &str,
        ) -> Result<bool, AuthzError> {
            Ok(!self.deny)
        }

        async fn require(
            &self,
            user_id: Uuid,
            domain: &str,
            object: &str,
            action: &str,
        ) -> Result<(), AuthzError> {
            self.require_calls.lock().unwrap().push(RequireCall {
                user_id,
                domain: domain.to_string(),
                object: object.to_string(),
                action: action.to_string(),
            });
            if self.deny {
                Err(AuthzError::Forbidden)
            } else {
                Ok(())
            }
        }

        async fn grant_platform_admin(&self, user_id: Uuid) -> Result<(), AuthzError> {
            self.grant_platform_admin_calls.lock().unwrap().push(user_id);
            Ok(())
        }

        async fn grant_tenant_owner(
            &self,
            user_id: Uuid,
            tenant_id: Uuid,
        ) -> Result<(), AuthzError> {
            self.grant_tenant_owner_calls
                .lock()
                .unwrap()
                .push((user_id, tenant_id));
            Ok(())
        }

        async fn grant_workspace_role(
            &self,
            user_id: Uuid,
            workspace_id: Uuid,
            role: WorkspaceRole,
        ) -> Result<(), AuthzError> {
            self.grant_workspace_role_calls.lock().unwrap().push((
                user_id,
                workspace_id,
                role.as_str().to_string(),
            ));
            Ok(())
        }
    }

    fn lazy_state(mock: Arc<MockAuthz>) -> SaasState {
        let pool = PgPool::connect_lazy("postgres://saas-test-host/saas_test")
            .expect("lazy pool must be constructible");
        SaasBuilder::new(pool)
            .with_authz(mock as Arc<dyn AuthorizationEngine>)
            .build()
            .expect("builder must succeed")
    }

    fn actor() -> AuthUser {
        AuthUser {
            id: Uuid::new_v4(),
            email: "actor@example.test".to_string(),
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
        assert_eq!(call.object, "tenants");
        assert_eq!(call.action, "create");

        assert!(
            mock.grant_tenant_owner_calls().is_empty(),
            "create_tenant must not call grant_tenant_owner"
        );
    }

    #[tokio::test]
    async fn provision_tenant_requires_platform_tenants_create() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let owner = self::actor();

        let err = platform::provision_tenant(&state, &actor, "Acme".into(), &owner)
            .await
            .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, PLATFORM_DOMAIN);
        assert_eq!(call.object, "tenants");
        assert_eq!(call.action, "create");

        assert!(mock.grant_tenant_owner_calls().is_empty());
    }

    #[tokio::test]
    async fn create_workspace_requires_tenant_workspaces_create() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let tenant_id = Uuid::new_v4();

        let err = tenant::create_workspace(&state, &actor, tenant_id, "Marketing".into())
            .await
            .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::tenant_domain(tenant_id));
        assert_eq!(call.object, "workspaces");
        assert_eq!(call.action, "create");

        assert!(mock.grant_workspace_role_calls().is_empty());
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
        assert_eq!(call.object, "documents");
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
        assert_eq!(call.object, "documents");
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
            "tenant_owner".into(),
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
        assert_eq!(call.object, "invitations");
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
        assert_eq!(call.object, "invitations");
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
        assert_eq!(call.object, "invitations");
        assert_eq!(call.action, "revoke");
    }

    #[tokio::test]
    async fn list_invitations_requires_workspace_invitations_list() {
        let mock = Arc::new(MockAuthz::denying());
        let state = lazy_state(mock.clone());
        let actor = actor();
        let workspace_id = Uuid::new_v4();

        let err = invitation::list_invitations(
            &state,
            &actor,
            InvitationTarget::Workspace(workspace_id),
        )
        .await
        .expect_err("require must deny");
        assert!(matches!(err, CoreError::Forbidden));

        let calls = mock.require_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, domain::workspace_domain(workspace_id));
        assert_eq!(call.object, "invitations");
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