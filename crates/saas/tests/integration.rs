//! Integration tests for `saas` against a real PostgreSQL + `authz-casbin`.
//!
//! `#[sqlx::test]` creates an isolated database per test, applies
//! `crates/db/migrations` (including `casbin_rule`, `roles`, `permissions`,
//! and `invitations`), and drops it afterwards.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use access::{AccessState, RoleKey};
use authz::{AuthorizationEngine, AuthzError};
use authz_casbin::CasbinAuthz;
use domain::{AuthUser, InvitationTarget};
use saas::member::MemberScope;
use saas::{
    access as saas_access, invitation, member, platform, tenant, workspace, CoreError, SaasBuilder,
    SaasState,
};
use sqlx::PgPool;
use uuid::Uuid;

/// Builds a `SaasState` with an arbitrary `AuthorizationEngine` sharing the
/// test pool. Used by `setup` (real `CasbinAuthz`) and by tests that need a
/// wrapped engine with controlled failures (Stage 2d).
async fn setup_with(pool: &PgPool, authz: Arc<dyn AuthorizationEngine>) -> SaasState {
    let access = Arc::new(AccessState::new(pool.clone(), authz.clone()));
    SaasBuilder::new(pool.clone())
        .with_authz(authz)
        .with_access(access)
        .build()
        .expect("saas builder")
}

/// Builds a `CasbinAuthz` + `AccessState` + `SaasState` sharing the test pool.
async fn setup(pool: &PgPool) -> SaasState {
    let casbin = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    setup_with(pool, casbin as Arc<dyn AuthorizationEngine>).await
}

/// Creates a user with a random email and a known password.
async fn make_user(pool: &PgPool, label: &str) -> AuthUser {
    let email = format!("{label}-{}@test.local", Uuid::new_v4());
    let hash = authn::hash_password("Password123!").expect("hash");
    identity::create_user(pool, &email, &hash)
        .await
        .expect("user must be created")
}

/// Grants `platform` owner to the given user.
async fn grant_platform_admin(state: &SaasState, user: &AuthUser) {
    let owner_key = RoleKey::parse("owner").unwrap();
    let perms = ::access::get_permissions_for_role(state.access(), "platform", &owner_key)
        .await
        .unwrap();
    state
        .authz()
        .grant_role(user.id, "platform", "owner", &perms)
        .await
        .unwrap();
}

/// Random tenant/workspace name so parallel tests within one database do not
/// collide on `unique (tenant_id, name)`.
fn unique_name(label: &str) -> String {
    format!("{label}-{}", Uuid::new_v4())
}

// ─── Tenant provisioning / workspace ────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn create_tenant_creates_row_without_membership(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let tenant = platform::create_tenant(&saas, &admin, unique_name("Acme"))
        .await
        .expect("create_tenant must succeed");

    let member: Option<String> =
        sqlx::query_scalar("select role from tenant_members where tenant_id = $1 and user_id = $2")
            .bind(tenant.id)
            .bind(admin.id)
            .fetch_optional(&pool)
            .await
            .expect("query tenant_members");
    assert!(
        member.is_none(),
        "create_tenant must not write tenant_members"
    );

    let can = saas
        .authz()
        .can(
            admin.id,
            &domain::tenant_domain(tenant.id),
            "workspaces",
            "create",
        )
        .await
        .expect("casbin can");
    assert!(
        !can,
        "creator must not have owner on a container-only tenant"
    );
}

#[sqlx::test(migrations = "../db/migrations")]
async fn provision_tenant_grants_owner_and_membership(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .expect("provision_tenant must succeed");

    let owner_role: Option<String> =
        sqlx::query_scalar("select role from tenant_members where tenant_id = $1 and user_id = $2")
            .bind(tenant.id)
            .bind(owner.id)
            .fetch_optional(&pool)
            .await
            .expect("query tenant_members for owner");
    assert_eq!(owner_role.as_deref(), Some("owner"));

    let actor_role: Option<String> =
        sqlx::query_scalar("select role from tenant_members where tenant_id = $1 and user_id = $2")
            .bind(tenant.id)
            .bind(admin.id)
            .fetch_optional(&pool)
            .await
            .expect("query tenant_members for actor");
    assert!(
        actor_role.is_none(),
        "platform admin must not become a tenant member by provisioning"
    );

    let owner_can = saas
        .authz()
        .can(
            owner.id,
            &domain::tenant_domain(tenant.id),
            "workspaces",
            "create",
        )
        .await
        .expect("casbin can (owner)");
    assert!(owner_can, "owner must be able to create workspaces");

    let actor_can = saas
        .authz()
        .can(
            admin.id,
            &domain::tenant_domain(tenant.id),
            "workspaces",
            "create",
        )
        .await
        .expect("casbin can (actor)");
    assert!(
        !actor_can,
        "platform admin must not gain tenant owner via provision_tenant"
    );
}

#[sqlx::test(migrations = "../db/migrations")]
async fn create_workspace_grants_owner_and_membership(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();

    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .expect("create_workspace must succeed");

    let role: Option<String> = sqlx::query_scalar(
        "select role from workspace_members where workspace_id = $1 and user_id = $2",
    )
    .bind(ws.id)
    .bind(admin.id)
    .fetch_optional(&pool)
    .await
    .expect("query workspace_members");
    assert_eq!(role.as_deref(), Some("owner"));

    let can = saas
        .authz()
        .can(
            admin.id,
            &domain::workspace_domain(ws.id),
            "documents",
            "write",
        )
        .await
        .expect("casbin can");
    assert!(can, "workspace owner must be able to write documents");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn platform_admin_cannot_create_document_without_workspace_role(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "pa").await;
    grant_platform_admin(&saas, &admin).await;

    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let ws = tenant::create_workspace(
        &saas,
        &owner,
        tenant.id,
        unique_name("Eng"),
        &owner,
        &owner_key,
    )
    .await
    .unwrap();

    let err = workspace::create_document(&saas, &admin, ws.id, "doc".into())
        .await
        .expect_err("platform admin must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn cross_workspace_isolation(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();

    let ws1 = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("ws1"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();
    let ws2 = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("ws2"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    workspace::create_document(&saas, &admin, ws1.id, "private".into())
        .await
        .unwrap();

    let outsider = make_user(&pool, "outsider").await;

    let read_err = workspace::list_documents(&saas, &outsider, ws2.id)
        .await
        .expect_err("outsider must be forbidden");
    assert!(matches!(read_err, CoreError::Forbidden), "got {read_err:?}");

    let write_err = workspace::create_document(&saas, &outsider, ws2.id, "x".into())
        .await
        .expect_err("outsider must be forbidden");
    assert!(
        matches!(write_err, CoreError::Forbidden),
        "got {write_err:?}"
    );

    let docs = workspace::list_documents(&saas, &admin, ws1.id)
        .await
        .expect("admin can read");
    assert_eq!(docs.len(), 1);
}

// ─── Membership lists ───────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn list_memberships_returns_only_member_tenants(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let a = make_user(&pool, "a").await;
    let b = make_user(&pool, "b").await;
    let outsider = make_user(&pool, "outsider").await;

    let tenant_a = platform::provision_tenant(&saas, &admin, unique_name("A"), &a, &owner_key)
        .await
        .unwrap();
    let tenant_b = platform::provision_tenant(&saas, &admin, unique_name("B"), &b, &owner_key)
        .await
        .unwrap();

    let a_list = tenant::list_memberships(&saas, &a).await.unwrap();
    assert_eq!(a_list.len(), 1, "a must see exactly one tenant");
    assert_eq!(a_list[0].id, tenant_a.id);

    let b_list = tenant::list_memberships(&saas, &b).await.unwrap();
    assert_eq!(b_list.len(), 1, "b must see exactly one tenant");
    assert_eq!(b_list[0].id, tenant_b.id);

    let admin_list = tenant::list_memberships(&saas, &admin).await.unwrap();
    assert!(
        admin_list.is_empty(),
        "platform admin is not a member of tenants it provisioned"
    );

    let outsider_list = tenant::list_memberships(&saas, &outsider).await.unwrap();
    assert!(outsider_list.is_empty(), "outsider must see no tenants");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn list_memberships_returns_only_member_workspaces(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();

    let ws1 = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("ws1"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();
    let ws2 = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("ws2"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let editor = make_user(&pool, "editor").await;
    let editor_key = RoleKey::parse("editor").unwrap();
    let ws_domain = domain::workspace_domain(ws1.id);

    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[("documents".to_string(), "read".to_string())],
    )
    .await
    .unwrap();

    saas_access::assign_role(&saas, &admin, editor.id, &ws_domain, &editor_key)
        .await
        .unwrap();

    let outsider = make_user(&pool, "outsider").await;

    let admin_list = workspace::list_memberships(&saas, &admin).await.unwrap();
    let admin_ids: Vec<Uuid> = admin_list.iter().map(|w| w.id).collect();
    assert_eq!(admin_ids.len(), 2, "admin created both workspaces");
    assert!(admin_ids.contains(&ws1.id));
    assert!(admin_ids.contains(&ws2.id));

    let editor_list = workspace::list_memberships(&saas, &editor).await.unwrap();
    assert_eq!(
        editor_list.len(),
        1,
        "editor must see exactly one workspace"
    );
    assert_eq!(editor_list[0].id, ws1.id);

    let outsider_list = workspace::list_memberships(&saas, &outsider).await.unwrap();
    assert!(outsider_list.is_empty(), "outsider must see no workspaces");
}

// ─── Invitations ────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn create_tenant_invitation_persists_row_and_returns_token(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let invitee_email = format!("invitee-{}@test.local", Uuid::new_v4());
    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        Some(invitee_email.clone()),
        "owner".into(),
        None,
        Some(1),
    )
    .await
    .expect("create tenant invitation");

    assert_eq!(inv.tenant_id, Some(tenant.id));
    assert_eq!(inv.workspace_id, None);
    assert_eq!(inv.email.as_deref(), Some(invitee_email.as_str()));
    assert_eq!(inv.role, "owner");
    assert_eq!(inv.used_count, 0);
    assert_eq!(inv.max_uses, Some(1));
    assert!(inv.revoked_at.is_none());

    assert_eq!(token.len(), 64, "2 × uuid simple hex");
    assert_eq!(inv.token_hash.len(), 64, "sha-256 hex");
    assert_ne!(inv.token_hash, token);

    let count: i64 = sqlx::query_scalar("select count(*) from invitations where token_hash = $1")
        .bind(&inv.token_hash)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    let alive: bool =
        sqlx::query_scalar("select expires_at > now() from invitations where id = $1")
            .bind(inv.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(alive, "default TTL must put expires_at in the future");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn create_workspace_invitation_persists_row_and_returns_token(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let editor_key = RoleKey::parse("editor").unwrap();
    let ws_domain = domain::workspace_domain(ws.id);
    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[("documents".to_string(), "read".to_string())],
    )
    .await
    .unwrap();

    let (inv, token) = invitation::create_invitation(
        &saas,
        &admin,
        InvitationTarget::Workspace(ws.id),
        None,
        "editor".into(),
        None,
        None,
    )
    .await
    .expect("create workspace invitation");

    assert_eq!(inv.workspace_id, Some(ws.id));
    assert_eq!(inv.tenant_id, None);
    assert_eq!(inv.email, None);
    assert_eq!(inv.role, "editor");
    assert_eq!(inv.max_uses, None);
    assert_eq!(token.len(), 64);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn accept_tenant_invitation_grants_owner_and_membership(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "owner".into(),
        None,
        None,
    )
    .await
    .unwrap();

    let invitee = make_user(&pool, "invitee").await;

    let accepted = invitation::accept_invitation(&saas, &invitee, &token)
        .await
        .expect("accept must succeed");
    assert_eq!(accepted.id, inv.id);

    let role: Option<String> =
        sqlx::query_scalar("select role from tenant_members where tenant_id = $1 and user_id = $2")
            .bind(tenant.id)
            .bind(invitee.id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(role.as_deref(), Some("owner"));

    let can = saas
        .authz()
        .can(
            invitee.id,
            &domain::tenant_domain(tenant.id),
            "workspaces",
            "create",
        )
        .await
        .unwrap();
    assert!(can, "accepted owner must be able to create workspaces");

    let used: i32 = sqlx::query_scalar("select used_count from invitations where id = $1")
        .bind(inv.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(used, 1, "used_count must increment on accept");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn accept_workspace_invitation_grants_role_and_membership(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let editor_key = RoleKey::parse("editor").unwrap();
    let ws_domain = domain::workspace_domain(ws.id);
    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[("documents".to_string(), "write".to_string())],
    )
    .await
    .unwrap();

    let (_, token) = invitation::create_invitation(
        &saas,
        &admin,
        InvitationTarget::Workspace(ws.id),
        None,
        "editor".into(),
        None,
        None,
    )
    .await
    .unwrap();

    let invitee = make_user(&pool, "invitee").await;
    invitation::accept_invitation(&saas, &invitee, &token)
        .await
        .expect("accept must succeed");

    let role: Option<String> = sqlx::query_scalar(
        "select role from workspace_members where workspace_id = $1 and user_id = $2",
    )
    .bind(ws.id)
    .bind(invitee.id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(role.as_deref(), Some("editor"));

    let can_write = saas
        .authz()
        .can(
            invitee.id,
            &domain::workspace_domain(ws.id),
            "documents",
            "write",
        )
        .await
        .unwrap();
    assert!(can_write, "accepted editor must be able to write documents");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn accept_invitation_after_exhaustion_returns_not_found(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let (_, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "owner".into(),
        None,
        Some(1),
    )
    .await
    .unwrap();

    let first = make_user(&pool, "first").await;
    invitation::accept_invitation(&saas, &first, &token)
        .await
        .expect("first accept must succeed");

    let second = make_user(&pool, "second").await;
    let err = invitation::accept_invitation(&saas, &second, &token)
        .await
        .expect_err("exhausted invitation must be rejected");
    assert!(matches!(err, CoreError::NotFound), "got {err:?}");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn accept_invitation_after_revoke_returns_not_found(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "owner".into(),
        None,
        None,
    )
    .await
    .unwrap();

    invitation::revoke_invitation(&saas, &owner, InvitationTarget::Tenant(tenant.id), inv.id)
        .await
        .expect("revoke must succeed");

    let invitee = make_user(&pool, "invitee").await;
    let err = invitation::accept_invitation(&saas, &invitee, &token)
        .await
        .expect_err("revoked invitation must be rejected");
    assert!(matches!(err, CoreError::NotFound), "got {err:?}");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn accept_invitation_after_expiry_returns_not_found(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;
    let owner = make_user(&pool, "owner").await;
    let owner_key = RoleKey::parse("owner").unwrap();

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "owner".into(),
        None,
        None,
    )
    .await
    .unwrap();

    sqlx::query("update invitations set expires_at = now() - interval '1 hour' where id = $1")
        .bind(inv.id)
        .execute(&pool)
        .await
        .expect("force expiry");

    let invitee = make_user(&pool, "invitee").await;
    let err = invitation::accept_invitation(&saas, &invitee, &token)
        .await
        .expect_err("expired invitation must be rejected");
    assert!(matches!(err, CoreError::NotFound), "got {err:?}");
}

// ─── Members (Stage 2c) ─────────────────────────────────────────────────────

/// Tenant member listing groups multiple roles per user and requires
/// `(members, list)`.
#[sqlx::test(migrations = "../db/migrations")]
async fn member_list_tenant_groups_roles_and_requires_list(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let owner = make_user(&pool, "owner").await;
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner, &owner_key)
        .await
        .unwrap();

    let tenant_domain = domain::tenant_domain(tenant.id);

    // Custom role `auditor` in the tenant domain.
    let auditor_key = RoleKey::parse("auditor").unwrap();
    saas_access::create_role(
        &saas,
        &owner,
        &tenant_domain,
        &auditor_key,
        "Auditor".to_string(),
        "".to_string(),
        &[("members".to_string(), "list".to_string())],
    )
    .await
    .unwrap();

    // `auditor` is also added to the owner so that `owner` holds two roles.
    saas_access::assign_role(&saas, &owner, owner.id, &tenant_domain, &auditor_key)
        .await
        .unwrap();

    let members = member::list(&saas, &owner, MemberScope::Tenant(tenant.id))
        .await
        .expect("list must succeed");
    assert_eq!(members.len(), 1, "only the owner is a member");
    let entry = &members[0];
    assert_eq!(entry.user_id, owner.id);
    assert_eq!(entry.email, owner.email);
    assert_eq!(entry.roles.len(), 2);
    assert!(entry.roles.iter().any(|r| r == "owner"));
    assert!(entry.roles.iter().any(|r| r == "auditor"));

    // Non-member is forbidden.
    let outsider = make_user(&pool, "outsider").await;
    let err = member::list(&saas, &outsider, MemberScope::Tenant(tenant.id))
        .await
        .expect_err("outsider must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

/// Workspace member listing includes users holding a workspace role and
/// rejects `(members, list)` when the actor has no roles in the workspace.
#[sqlx::test(migrations = "../db/migrations")]
async fn member_list_workspace_requires_list_permission(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let editor_key = RoleKey::parse("editor").unwrap();
    let editor = make_user(&pool, "editor").await;
    let ws_domain = domain::workspace_domain(ws.id);
    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[("documents".to_string(), "read".to_string())],
    )
    .await
    .unwrap();
    saas_access::assign_role(&saas, &admin, editor.id, &ws_domain, &editor_key)
        .await
        .unwrap();

    let members = member::list(&saas, &admin, MemberScope::Workspace(ws.id))
        .await
        .expect("list must succeed");
    assert_eq!(members.len(), 2, "owner and editor");
    let emails: Vec<&str> = members.iter().map(|m| m.email.as_str()).collect();
    assert!(emails.contains(&admin.email.as_str()));
    assert!(emails.contains(&editor.email.as_str()));

    // Actor with no workspace role — forbidden.
    let outsider = make_user(&pool, "outsider").await;
    let err = member::list(&saas, &outsider, MemberScope::Workspace(ws.id))
        .await
        .expect_err("outsider must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

/// `change_role` replaces the old role with the new one in both
/// `*_members` and `casbin_rule`.
#[sqlx::test(migrations = "../db/migrations")]
async fn member_change_role_replaces_role(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let ws_domain = domain::workspace_domain(ws.id);
    let editor_key = RoleKey::parse("editor").unwrap();
    let viewer_key = RoleKey::parse("viewer").unwrap();
    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[("documents".to_string(), "write".to_string())],
    )
    .await
    .unwrap();
    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &viewer_key,
        "Viewer".to_string(),
        "".to_string(),
        &[("documents".to_string(), "read".to_string())],
    )
    .await
    .unwrap();

    let user = make_user(&pool, "user").await;
    saas_access::assign_role(&saas, &admin, user.id, &ws_domain, &editor_key)
        .await
        .unwrap();

    member::change_role(
        &saas,
        &admin,
        MemberScope::Workspace(ws.id),
        user.id,
        &editor_key,
        &viewer_key,
    )
    .await
    .expect("change_role must succeed");

    let can_write = saas
        .authz()
        .can(user.id, &ws_domain, "documents", "write")
        .await
        .unwrap();
    let can_read = saas
        .authz()
        .can(user.id, &ws_domain, "documents", "read")
        .await
        .unwrap();
    assert!(!can_write, "editor rights must be gone");
    assert!(can_read, "viewer rights must be present");

    let members = member::list(&saas, &admin, MemberScope::Workspace(ws.id))
        .await
        .unwrap();
    let entry = members
        .iter()
        .find(|m| m.user_id == user.id)
        .expect("user must be listed");
    assert_eq!(entry.roles, vec!["viewer".to_string()]);
}

/// `change_role` with identical keys is a no-op (no `require`, no SQL).
#[sqlx::test(migrations = "../db/migrations")]
async fn member_change_role_same_key_is_noop(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    // Actor is an outsider; if `require` were called, it would fail. The
    // no-op path returns before `require`.
    let outsider = make_user(&pool, "outsider").await;
    member::change_role(
        &saas,
        &outsider,
        MemberScope::Workspace(ws.id),
        admin.id,
        &owner_key,
        &owner_key,
    )
    .await
    .expect("no-op must not call require");
}

/// `remove_role` deletes the role from `*_members` and `casbin_rule`.
#[sqlx::test(migrations = "../db/migrations")]
async fn member_remove_role_removes_from_members_and_casbin(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let ws_domain = domain::workspace_domain(ws.id);
    let editor_key = RoleKey::parse("editor").unwrap();
    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[("documents".to_string(), "write".to_string())],
    )
    .await
    .unwrap();

    let user = make_user(&pool, "user").await;
    saas_access::assign_role(&saas, &admin, user.id, &ws_domain, &editor_key)
        .await
        .unwrap();

    member::remove_role(
        &saas,
        &admin,
        MemberScope::Workspace(ws.id),
        user.id,
        &editor_key,
    )
    .await
    .expect("remove_role must succeed");

    let can_write = saas
        .authz()
        .can(user.id, &ws_domain, "documents", "write")
        .await
        .unwrap();
    assert!(!can_write, "removed role must not grant documents:write");

    let members = member::list(&saas, &admin, MemberScope::Workspace(ws.id))
        .await
        .unwrap();
    assert!(
        members.iter().all(|m| m.user_id != user.id),
        "user must no longer appear in member list"
    );
}

// ─── my_permissions (Stage 2c) ──────────────────────────────────────────────

/// Owner sees the full reference table; a non-member sees an empty list;
/// an editor sees exactly the two `documents:*` pairs.
#[sqlx::test(migrations = "../db/migrations")]
async fn my_permissions_owner_editor_and_non_member(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let ws_domain = domain::workspace_domain(ws.id);

    // Owner — all permissions from the reference table.
    let owner_perms = saas_access::my_permissions(&saas, &admin, &ws_domain)
        .await
        .unwrap();
    let reference = ::access::list_permissions(saas.access()).await.unwrap();
    assert_eq!(owner_perms.len(), reference.len());
    assert!(owner_perms
        .iter()
        .any(|(r, a)| r == "members" && a == "list"));

    // Editor — exactly `documents:read` + `documents:write`.
    let editor_key = RoleKey::parse("editor").unwrap();
    let editor = make_user(&pool, "editor").await;
    saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[
            ("documents".to_string(), "read".to_string()),
            ("documents".to_string(), "write".to_string()),
        ],
    )
    .await
    .unwrap();
    saas_access::assign_role(&saas, &admin, editor.id, &ws_domain, &editor_key)
        .await
        .unwrap();

    let editor_perms = saas_access::my_permissions(&saas, &editor, &ws_domain)
        .await
        .unwrap();
    assert_eq!(editor_perms.len(), 2);
    assert!(editor_perms
        .iter()
        .any(|(r, a)| r == "documents" && a == "read"));
    assert!(editor_perms
        .iter()
        .any(|(r, a)| r == "documents" && a == "write"));

    // Non-member — empty.
    let outsider = make_user(&pool, "outsider").await;
    let outsider_perms = saas_access::my_permissions(&saas, &outsider, &ws_domain)
        .await
        .unwrap();
    assert!(
        outsider_perms.is_empty(),
        "non-member must see no permissions"
    );
}

// ─── Stage 2d: owner guard, flip order, delete_role cleanup ────────────────

/// Removing the last `protected` holder of a role is rejected; the user
/// remains a holder and retains the effective permissions of the role.
#[sqlx::test(migrations = "../db/migrations")]
async fn remove_role_last_protected_holder_is_rejected(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let ws_domain = domain::workspace_domain(ws.id);
    let holders = saas
        .authz()
        .count_users_with_role(&ws_domain, "owner")
        .await
        .unwrap();
    assert_eq!(holders, 1, "admin must be the sole owner of the workspace");

    let err = member::remove_role(
        &saas,
        &admin,
        MemberScope::Workspace(ws.id),
        admin.id,
        &owner_key,
    )
    .await
    .expect_err("removing the last protected holder must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");

    // Still a holder — the guard runs before any mutation.
    let can = saas
        .authz()
        .can(admin.id, &ws_domain, "documents", "write")
        .await
        .unwrap();
    assert!(can, "admin must still be able to write documents");
    let holders_after = saas
        .authz()
        .count_users_with_role(&ws_domain, "owner")
        .await
        .unwrap();
    assert_eq!(holders_after, 1, "owner count must not have changed");
}

/// Simulates a `revoke_role` failure after `assign_role` succeeded.
///
/// Verifies the Stage 2d flip order (`assign` then `revoke`):
/// - after the failure the user is over-permissioned (new role assigned,
///   old role still grants rights in `casbin_rule`);
/// - the `*_members` bookkeeping row for the old role was already deleted
///   (the SQL `DELETE` inside `revoke_role` runs before `authz.revoke_role`);
/// - a repeated `change_role` (with the failing engine no longer failing)
///   recovers to a consistent state.
#[sqlx::test(migrations = "../db/migrations")]
async fn change_role_partial_failure_leaves_over_permissioned_and_retry_recovers(pool: PgPool) {
    /// Wraps a real `CasbinAuthz` and fails `revoke_role` while the flag is
    /// set. Other methods delegate to the inner engine.
    struct FailingRevokeAuthz {
        inner: Arc<CasbinAuthz>,
        fail_revoke: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl AuthorizationEngine for FailingRevokeAuthz {
        async fn can(
            &self,
            user_id: Uuid,
            domain: &str,
            resource: &str,
            action: &str,
        ) -> Result<bool, AuthzError> {
            self.inner.can(user_id, domain, resource, action).await
        }

        async fn require(
            &self,
            user_id: Uuid,
            domain: &str,
            resource: &str,
            action: &str,
        ) -> Result<(), AuthzError> {
            self.inner.require(user_id, domain, resource, action).await
        }

        async fn grant_role(
            &self,
            user_id: Uuid,
            domain: &str,
            role_key: &str,
            permissions: &[(String, String)],
        ) -> Result<(), AuthzError> {
            self.inner
                .grant_role(user_id, domain, role_key, permissions)
                .await
        }

        async fn revoke_role(
            &self,
            user_id: Uuid,
            domain: &str,
            role_key: &str,
        ) -> Result<(), AuthzError> {
            if self.fail_revoke.load(Ordering::SeqCst) {
                return Err(AuthzError::Internal("simulated revoke failure".into()));
            }
            self.inner.revoke_role(user_id, domain, role_key).await
        }

        async fn has_role(
            &self,
            user_id: Uuid,
            domain: &str,
            role_key: &str,
        ) -> Result<bool, AuthzError> {
            self.inner.has_role(user_id, domain, role_key).await
        }

        async fn count_users_with_role(
            &self,
            domain: &str,
            role_key: &str,
        ) -> Result<i64, AuthzError> {
            self.inner.count_users_with_role(domain, role_key).await
        }

        async fn purge_role(&self, domain: &str, role_key: &str) -> Result<u64, AuthzError> {
            self.inner.purge_role(domain, role_key).await
        }
    }

    let casbin = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let fail_revoke = Arc::new(AtomicBool::new(false));
    let failing = Arc::new(FailingRevokeAuthz {
        inner: casbin.clone(),
        fail_revoke: fail_revoke.clone(),
    });
    let ok_state = setup_with(&pool, casbin.clone() as Arc<dyn AuthorizationEngine>).await;
    let failing_state = setup_with(&pool, failing as Arc<dyn AuthorizationEngine>).await;

    // Setup through the working state.
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&ok_state, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant =
        platform::provision_tenant(&ok_state, &admin, unique_name("Acme"), &admin, &owner_key)
            .await
            .unwrap();
    let ws = tenant::create_workspace(
        &ok_state,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let ws_domain = domain::workspace_domain(ws.id);
    let editor_key = RoleKey::parse("editor").unwrap();
    let viewer_key = RoleKey::parse("viewer").unwrap();
    saas_access::create_role(
        &ok_state,
        &admin,
        &ws_domain,
        &editor_key,
        "Editor".to_string(),
        "".to_string(),
        &[("documents".to_string(), "write".to_string())],
    )
    .await
    .unwrap();
    saas_access::create_role(
        &ok_state,
        &admin,
        &ws_domain,
        &viewer_key,
        "Viewer".to_string(),
        "".to_string(),
        &[("documents".to_string(), "read".to_string())],
    )
    .await
    .unwrap();

    let user = make_user(&pool, "user").await;
    saas_access::assign_role(&ok_state, &admin, user.id, &ws_domain, &editor_key)
        .await
        .unwrap();

    // First attempt through the failing engine: `assign(viewer)` succeeds,
    // `revoke(editor)` fails.
    fail_revoke.store(true, Ordering::SeqCst);
    let err = member::change_role(
        &failing_state,
        &admin,
        MemberScope::Workspace(ws.id),
        user.id,
        &editor_key,
        &viewer_key,
    )
    .await
    .expect_err("simulated revoke failure must propagate");
    assert!(matches!(err, CoreError::Internal(_)), "got {err:?}");
    fail_revoke.store(false, Ordering::SeqCst);

    // Over-permissioned: new role (viewer) grants read; old role (editor)
    // still grants write because `authz.revoke_role` never ran.
    let can_read = casbin
        .can(user.id, &ws_domain, "documents", "read")
        .await
        .unwrap();
    let can_write = casbin
        .can(user.id, &ws_domain, "documents", "write")
        .await
        .unwrap();
    assert!(can_read, "viewer rights must be granted");
    assert!(
        can_write,
        "editor rights must still be granted after simulated revoke failure"
    );

    // Bookkeeping is already consistent with the *intended* end state for
    // the new role but not for the old one: `*_members` shows `viewer` only.
    let members = member::list(&ok_state, &admin, MemberScope::Workspace(ws.id))
        .await
        .unwrap();
    let entry = members
        .iter()
        .find(|m| m.user_id == user.id)
        .expect("user must be listed");
    assert_eq!(
        entry.roles,
        vec!["viewer".to_string()],
        "old role must already be removed from *_members (SQL before authz)"
    );

    // Recovery: repeat `change_role` with the working engine.
    member::change_role(
        &ok_state,
        &admin,
        MemberScope::Workspace(ws.id),
        user.id,
        &editor_key,
        &viewer_key,
    )
    .await
    .expect("retry must recover");

    let can_write_after = casbin
        .can(user.id, &ws_domain, "documents", "write")
        .await
        .unwrap();
    let can_read_after = casbin
        .can(user.id, &ws_domain, "documents", "read")
        .await
        .unwrap();
    assert!(!can_write_after, "editor rights must be gone after retry");
    assert!(can_read_after, "viewer rights must remain after retry");
}

/// `saas::access::delete_role` removes the role row, its `g`/`p` rows in
/// `casbin_rule`, and its `*_members` bookkeeping rows.
#[sqlx::test(migrations = "../db/migrations")]
async fn delete_role_purges_casbin_and_members(pool: PgPool) {
    let saas = setup(&pool).await;
    let admin = make_user(&pool, "admin").await;
    grant_platform_admin(&saas, &admin).await;

    let owner_key = RoleKey::parse("owner").unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin, &owner_key)
        .await
        .unwrap();
    let ws = tenant::create_workspace(
        &saas,
        &admin,
        tenant.id,
        unique_name("Eng"),
        &admin,
        &owner_key,
    )
    .await
    .unwrap();

    let ws_domain = domain::workspace_domain(ws.id);
    let temp_key = RoleKey::parse("temp").unwrap();
    let role = saas_access::create_role(
        &saas,
        &admin,
        &ws_domain,
        &temp_key,
        "Temp".to_string(),
        "".to_string(),
        &[("documents".to_string(), "read".to_string())],
    )
    .await
    .unwrap();

    let user = make_user(&pool, "user").await;
    saas_access::assign_role(&saas, &admin, user.id, &ws_domain, &temp_key)
        .await
        .unwrap();

    // Preconditions: role, g-row, p-row, *_members row are all present.
    assert!(saas
        .authz()
        .has_role(user.id, &ws_domain, "temp")
        .await
        .unwrap());
    let g_rows: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype='g' and v1='temp' and v2=$1",
    )
    .bind(&ws_domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(g_rows, 1);
    let p_rows: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype='p' and v0='temp' and v1=$1",
    )
    .bind(&ws_domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(p_rows, 1);
    let member_rows: i64 = sqlx::query_scalar(
        "select count(*) from workspace_members where workspace_id=$1 and user_id=$2 and role='temp'",
    )
    .bind(ws.id)
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(member_rows, 1);

    // Delete.
    saas_access::delete_role(&saas, &admin, role.id)
        .await
        .expect("delete_role must succeed");

    // Role row gone.
    let role_row: Option<Uuid> = sqlx::query_scalar("select id from roles where id=$1")
        .bind(role.id)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(role_row.is_none(), "roles row must be gone");

    // Casbin cleaned.
    let g_after: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype='g' and v1='temp' and v2=$1",
    )
    .bind(&ws_domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(g_after, 0, "g-rows must be purged");
    let p_after: i64 = sqlx::query_scalar(
        "select count(*) from casbin_rule where ptype='p' and v0='temp' and v1=$1",
    )
    .bind(&ws_domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(p_after, 0, "p-rows must be purged");

    // Members cleaned.
    let member_after: i64 = sqlx::query_scalar(
        "select count(*) from workspace_members where workspace_id=$1 and user_id=$2 and role='temp'",
    )
    .bind(ws.id)
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(member_after, 0, "*_members rows must be cleaned");

    // Effective permissions gone.
    let can_read = saas
        .authz()
        .can(user.id, &ws_domain, "documents", "read")
        .await
        .unwrap();
    assert!(!can_read, "temp role no longer grants documents:read");
}
