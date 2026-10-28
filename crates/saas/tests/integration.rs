//! Integration tests for `saas` against a real PostgreSQL + `authz-casbin`.
//!
//! `#[sqlx::test]` creates an isolated database per test, applies
//! `crates/db/migrations` (including `casbin_rule` and `invitations`), and
//! drops it afterwards. `CasbinAuthz::from_pool` uses the same pool, so
//! policies live in that test database.
//!
//! No manual `createdb` is required. `DATABASE_URL` must point at a server
//! where the user has the `CREATE DATABASE` privilege.

use std::sync::Arc;

use authz::AuthorizationEngine;
use authz_casbin::CasbinAuthz;
use domain::{AuthUser, InvitationTarget};
use saas::{invitation, platform, tenant, workspace, CoreError, SaasBuilder, SaasState};
use sqlx::PgPool;
use uuid::Uuid;

/// Builds a `CasbinAuthz` + `SaasState` sharing the test pool.
async fn setup(pool: &PgPool) -> (Arc<CasbinAuthz>, SaasState) {
    let casbin = Arc::new(
        CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let saas = SaasBuilder::new(pool.clone())
        .with_authz(casbin.clone() as Arc<dyn AuthorizationEngine>)
        .build()
        .expect("saas builder");
    (casbin, saas)
}

/// Creates a user with a random email and a known password.
async fn make_user(pool: &PgPool, label: &str) -> AuthUser {
    let email = format!("{label}-{}@test.local", Uuid::new_v4());
    let hash = authn::hash_password("Password123!").expect("hash");
    identity::create_user(pool, &email, &hash)
        .await
        .expect("user must be created")
}

/// Random tenant/workspace name so parallel tests within one database do not
/// collide on `unique (tenant_id, name)`.
fn unique_name(label: &str) -> String {
    format!("{label}-{}", Uuid::new_v4())
}

// ─── Tenant provisioning / workspace ────────────────────────────────────────

/// `create_tenant` is a container-only operation: it inserts a `tenants` row
/// but does not assign an owner, does not write `tenant_members`, and does not
/// grant any Casbin policy.
#[sqlx::test(migrations = "../db/migrations")]
async fn create_tenant_creates_row_without_membership(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin
        .grant_platform_admin(admin.id)
        .await
        .expect("grant platform admin");

    let tenant = platform::create_tenant(&saas, &admin, unique_name("Acme"))
        .await
        .expect("create_tenant must succeed");

    let member: Option<String> = sqlx::query_scalar(
        "select role from tenant_members where tenant_id = $1 and user_id = $2",
    )
    .bind(tenant.id)
    .bind(admin.id)
    .fetch_optional(&pool)
    .await
    .expect("query tenant_members");
    assert!(
        member.is_none(),
        "create_tenant must not write tenant_members"
    );

    let can = casbin
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
        "creator must not have tenant_owner on a container-only tenant"
    );

    let row: (String, String) =
        sqlx::query_as("select name, status from tenants where id = $1")
            .bind(tenant.id)
            .fetch_one(&pool)
            .await
            .expect("tenant row");
    assert_eq!(row.0, tenant.name);
    assert_eq!(row.1, "active");
}

/// `provision_tenant` creates the tenant and explicitly assigns an owner.
#[sqlx::test(migrations = "../db/migrations")]
async fn provision_tenant_grants_owner_and_membership(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();

    let owner = make_user(&pool, "owner").await;

    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner)
        .await
        .expect("provision_tenant must succeed");

    let owner_role: Option<String> = sqlx::query_scalar(
        "select role from tenant_members where tenant_id = $1 and user_id = $2",
    )
    .bind(tenant.id)
    .bind(owner.id)
    .fetch_optional(&pool)
    .await
    .expect("query tenant_members for owner");
    assert_eq!(owner_role.as_deref(), Some("owner"));

    let actor_role: Option<String> = sqlx::query_scalar(
        "select role from tenant_members where tenant_id = $1 and user_id = $2",
    )
    .bind(tenant.id)
    .bind(admin.id)
    .fetch_optional(&pool)
    .await
    .expect("query tenant_members for actor");
    assert!(
        actor_role.is_none(),
        "platform admin must not become a tenant member by provisioning"
    );

    let owner_can = casbin
        .can(
            owner.id,
            &domain::tenant_domain(tenant.id),
            "workspaces",
            "create",
        )
        .await
        .expect("casbin can (owner)");
    assert!(owner_can, "owner must be able to create workspaces");

    let actor_can = casbin
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
        "platform admin must not gain tenant_owner via provision_tenant"
    );
}

/// `create_workspace` keeps the side effect "creator becomes
/// `workspace_admin`".
#[sqlx::test(migrations = "../db/migrations")]
async fn create_workspace_grants_admin_and_membership(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin)
        .await
        .unwrap();

    let ws = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("Eng"))
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
    assert_eq!(role.as_deref(), Some("admin"));

    let can = casbin
        .can(
            admin.id,
            &domain::workspace_domain(ws.id),
            "documents",
            "write",
        )
        .await
        .expect("casbin can");
    assert!(can, "workspace admin must be able to write documents");
}

/// A platform admin who provisioned a tenant for someone else, and who has no
/// workspace role in that tenant's workspace, cannot create documents there.
#[sqlx::test(migrations = "../db/migrations")]
async fn platform_admin_cannot_create_document_without_workspace_role(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "pa").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();

    let owner = make_user(&pool, "owner").await;
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner)
        .await
        .unwrap();

    let ws = tenant::create_workspace(&saas, &owner, tenant.id, unique_name("Eng"))
        .await
        .unwrap();

    let err = workspace::create_document(&saas, &admin, ws.id, "doc".into())
        .await
        .expect_err("platform admin must be forbidden");
    assert!(matches!(err, CoreError::Forbidden), "got {err:?}");
}

/// Users of one workspace cannot read or write documents in another
/// workspace, even inside the same tenant.
#[sqlx::test(migrations = "../db/migrations")]
async fn cross_workspace_isolation(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin)
        .await
        .unwrap();

    let ws1 = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("ws1"))
        .await
        .unwrap();
    let ws2 = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("ws2"))
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
    assert!(matches!(write_err, CoreError::Forbidden), "got {write_err:?}");

    let docs = workspace::list_documents(&saas, &admin, ws1.id)
        .await
        .expect("admin can read");
    assert_eq!(docs.len(), 1);
}

// ─── Membership lists (Stage 2a) ────────────────────────────────────────────

/// `tenant::list_memberships` returns only the tenants where the user is in
/// `tenant_members`. A platform admin who provisioned tenant A for user `a`
/// and tenant B for user `b` is not a member of either and sees an empty list;
/// `a` sees only tenant A, `b` sees only tenant B, `outsider` sees nothing.
#[sqlx::test(migrations = "../db/migrations")]
async fn list_memberships_returns_only_member_tenants(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();

    let a = make_user(&pool, "a").await;
    let b = make_user(&pool, "b").await;
    let outsider = make_user(&pool, "outsider").await;

    let tenant_a = platform::provision_tenant(&saas, &admin, unique_name("A"), &a)
        .await
        .unwrap();
    let tenant_b = platform::provision_tenant(&saas, &admin, unique_name("B"), &b)
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
        "platform admin is not a member of tenants it provisioned (see §2.13)"
    );

    let outsider_list = tenant::list_memberships(&saas, &outsider).await.unwrap();
    assert!(outsider_list.is_empty(), "outsider must see no tenants");
}

/// `workspace::list_memberships` returns only the workspaces where the user
/// is in `workspace_members`. `admin` creates `ws1` (becomes
/// `workspace_admin`), `editor` is granted `Editor` on `ws1`; `outsider` has
/// no role and sees nothing. `ws2` created by `admin` is not seen by `editor`.
#[sqlx::test(migrations = "../db/migrations")]
async fn list_memberships_returns_only_member_workspaces(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin)
        .await
        .unwrap();

    let ws1 = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("ws1"))
        .await
        .unwrap();
    let ws2 = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("ws2"))
        .await
        .unwrap();

    let editor = make_user(&pool, "editor").await;
    casbin
        .grant_workspace_role(editor.id, ws1.id, authz::WorkspaceRole::Editor)
        .await
        .unwrap();
    sqlx::query(
        r#"
        insert into workspace_members (workspace_id, user_id, role)
        values ($1, $2, 'editor')
        on conflict do nothing
        "#,
    )
    .bind(ws1.id)
    .bind(editor.id)
    .execute(&pool)
    .await
    .unwrap();

    let outsider = make_user(&pool, "outsider").await;

    let admin_list = workspace::list_memberships(&saas, &admin).await.unwrap();
    let admin_ids: Vec<Uuid> = admin_list.iter().map(|w| w.id).collect();
    assert_eq!(admin_ids.len(), 2, "admin created both workspaces");
    assert!(admin_ids.contains(&ws1.id));
    assert!(admin_ids.contains(&ws2.id));

    let editor_list = workspace::list_memberships(&saas, &editor).await.unwrap();
    assert_eq!(editor_list.len(), 1, "editor must see exactly one workspace");
    assert_eq!(editor_list[0].id, ws1.id);

    let outsider_list = workspace::list_memberships(&saas, &outsider).await.unwrap();
    assert!(
        outsider_list.is_empty(),
        "outsider must see no workspaces"
    );
}

// ─── Invitations (Stage 2a) ─────────────────────────────────────────────────

/// `create_invitation` for a tenant target inserts a row with
/// `tenant_id = Some`, `workspace_id = None`, and returns the raw token
/// alongside the row. The raw token is not persisted; only its SHA-256 hash
/// is stored in `token_hash`.
#[sqlx::test(migrations = "../db/migrations")]
async fn create_tenant_invitation_persists_row_and_returns_token(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let owner = make_user(&pool, "owner").await;
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner)
        .await
        .unwrap();

    let invitee_email = format!("invitee-{}@test.local", Uuid::new_v4());
    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        Some(invitee_email.clone()),
        "tenant_owner".into(),
        None,
        Some(1),
    )
    .await
    .expect("create tenant invitation");

    assert_eq!(inv.tenant_id, Some(tenant.id));
    assert_eq!(inv.workspace_id, None);
    assert_eq!(inv.email.as_deref(), Some(invitee_email.as_str()));
    assert_eq!(inv.role, "tenant_owner");
    assert_eq!(inv.used_count, 0);
    assert_eq!(inv.max_uses, Some(1));
    assert!(inv.revoked_at.is_none());

    assert_eq!(token.len(), 64, "2 × uuid simple hex");
    assert_eq!(inv.token_hash.len(), 64, "sha-256 hex");
    assert_ne!(inv.token_hash, token);

    let count: i64 =
        sqlx::query_scalar("select count(*) from invitations where token_hash = $1")
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

/// `create_invitation` for a workspace target inserts a row with
/// `workspace_id = Some`, `tenant_id = None`, `email = None` (link), and
/// `max_uses = None` (unlimited).
#[sqlx::test(migrations = "../db/migrations")]
async fn create_workspace_invitation_persists_row_and_returns_token(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin)
        .await
        .unwrap();
    let ws = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("Eng"))
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

/// Accepting a tenant invitation writes `tenant_members(role='owner')`,
/// grants `tenant_owner` in `casbin_rule`, and increments `used_count`.
#[sqlx::test(migrations = "../db/migrations")]
async fn accept_tenant_invitation_grants_owner_and_membership(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let owner = make_user(&pool, "owner").await;
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner)
        .await
        .unwrap();

    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "tenant_owner".into(),
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

    let role: Option<String> = sqlx::query_scalar(
        "select role from tenant_members where tenant_id = $1 and user_id = $2",
    )
    .bind(tenant.id)
    .bind(invitee.id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(role.as_deref(), Some("owner"));

    let can = casbin
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

/// Accepting a workspace invitation writes `workspace_members(role)` and
/// grants the corresponding `WorkspaceRole` in `casbin_rule`.
#[sqlx::test(migrations = "../db/migrations")]
async fn accept_workspace_invitation_grants_role_and_membership(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &admin)
        .await
        .unwrap();
    let ws = tenant::create_workspace(&saas, &admin, tenant.id, unique_name("Eng"))
        .await
        .unwrap();

    let (_, token) = invitation::create_invitation(
        &saas,
        &admin,
        InvitationTarget::Workspace(ws.id),
        None,
        "admin".into(),
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
    assert_eq!(role.as_deref(), Some("admin"));

    let can_write = casbin
        .can(
            invitee.id,
            &domain::workspace_domain(ws.id),
            "documents",
            "write",
        )
        .await
        .unwrap();
    assert!(can_write, "accepted admin must be able to write documents");
}

/// When `max_uses = 1` and the invitation has already been used once, a
/// second accept returns `NotFound`.
#[sqlx::test(migrations = "../db/migrations")]
async fn accept_invitation_after_exhaustion_returns_not_found(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let owner = make_user(&pool, "owner").await;
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner)
        .await
        .unwrap();

    let (_, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "tenant_owner".into(),
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

/// After `revoke_invitation` sets `revoked_at`, `accept_invitation` returns
/// `NotFound`.
#[sqlx::test(migrations = "../db/migrations")]
async fn accept_invitation_after_revoke_returns_not_found(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let owner = make_user(&pool, "owner").await;
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner)
        .await
        .unwrap();

    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "tenant_owner".into(),
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

/// When `expires_at` is in the past, `accept_invitation` returns `NotFound`.
#[sqlx::test(migrations = "../db/migrations")]
async fn accept_invitation_after_expiry_returns_not_found(pool: PgPool) {
    let (casbin, saas) = setup(&pool).await;

    let admin = make_user(&pool, "admin").await;
    casbin.grant_platform_admin(admin.id).await.unwrap();
    let owner = make_user(&pool, "owner").await;
    let tenant = platform::provision_tenant(&saas, &admin, unique_name("Acme"), &owner)
        .await
        .unwrap();

    let (inv, token) = invitation::create_invitation(
        &saas,
        &owner,
        InvitationTarget::Tenant(tenant.id),
        None,
        "tenant_owner".into(),
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