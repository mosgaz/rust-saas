//! Бизнес-логика SaaS: platform, tenant, workspace, документы.
//!
//! Крейт не знает о Leptos, Axum, конкретных HTTP handlers, `casbin::Enforcer`,
//! JWT и Argon2. Авторизация — через `authz::AuthorizationEngine`;
//! actor — `domain::AuthUser` (приходит от `authn` в `app`).

use std::sync::Arc;

use authz::{AuthzError, AuthorizationEngine, WorkspaceRole};
use domain::{AuthUser, Document, Tenant, Workspace, PLATFORM_DOMAIN};
use sqlx::PgPool;
use uuid::Uuid;

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

    /// Создаёт tenant и назначает создателя `tenant_owner`.
    ///
    /// Порядок:
    /// 1. `authz.require(actor.id, "platform", "tenants", "create")` — первым шагом.
    /// 2. Транзакция: `INSERT tenants` + `INSERT tenant_members (role='owner')`.
    /// 3. `authz.grant_tenant_owner(actor.id, tenant.id)` — политики в `casbin_rule`.
    /// 4. `COMMIT`.
    ///
    /// Если `grant_*` вернёт ошибку, транзакция откатится и tenant не будет создан.
    /// `authz-casbin` пишет в `casbin_rule` вне транзакции `state.pool`; возможен
    /// частичный след в `casbin_rule` (g без p) для несуществующего tenant —
    /// известное ограничение, см. handoff §16.
    pub async fn create_tenant(
        state: &SaasState,
        actor: &AuthUser,
        name: String,
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
        .bind(actor.id)
        .execute(&mut *tx)
        .await?;

        state.authz.grant_tenant_owner(actor.id, tenant.id).await?;

        tx.commit().await?;

        Ok(tenant)
    }
}

pub mod tenant {
    use super::*;

    /// Создаёт workspace в tenant и назначает создателя `workspace_admin`.
    ///
    /// Порядок:
    /// 1. `authz.require(actor.id, "tenant:{id}", "workspaces", "create")` — первым шагом.
    /// 2. Транзакция: `INSERT workspaces` + `INSERT workspace_members (role='admin')`.
    /// 3. `authz.grant_workspace_role(actor.id, workspace.id, WorkspaceRole::Admin)`.
    /// 4. `COMMIT`.
    ///
    /// Если `grant_*` вернёт ошибку, транзакция откатится и workspace не будет создан.
    /// Возможный частичный след в `casbin_rule` — см. `platform::create_tenant`.
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
}

#[cfg(test)]
mod tests {
    //! Unit-тесты `saas` без реальной БД.
    //!
    //! Идея: `PgPool::connect_lazy` создаёт пул без установления соединения.
    //! Мок `AuthorizationEngine` настроен на `deny` — `authz.require` падает
    //! раньше, чем `saas` пытается обратиться к БД. Это позволяет проверить:
    //!   - `require` вызывается с правильными `(domain, object, action)`;
    //!   - `grant_*` не вызывается, если `require` запретил действие.
    //!
    //! Успешный flow (реальный INSERT + `grant_*`) — integration-тест,
    //! требует БД (см. handoff §17, шаг 7/8).

    use super::*;
    use std::sync::Mutex;

    use authz::{AuthzError, AuthorizationEngine, WorkspaceRole};
    use chrono::Utc;
    use domain::AuthUser;

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
        // connect_lazy не открывает соединение; при deny до SQL не доходит.
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
        assert_eq!(calls.len(), 1, "exactly one require call expected");
        let call = &calls[0];
        assert_eq!(call.user_id, actor.id);
        assert_eq!(call.domain, PLATFORM_DOMAIN);
        assert_eq!(call.object, "tenants");
        assert_eq!(call.action, "create");

        assert!(
            mock.grant_tenant_owner_calls().is_empty(),
            "grant_tenant_owner must not run when require denies"
        );
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

        assert!(
            mock.grant_workspace_role_calls().is_empty(),
            "grant_workspace_role must not run when require denies"
        );
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