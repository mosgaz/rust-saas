#![allow(dead_code)]
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use http_body_util::BodyExt;
use rust_saas::access::{ResourceType, RoleKey};
use rust_saas::db;
use rust_saas::domain::AuthUser;
use rust_saas::saas::{access as saas_access, platform, tenant};
use rust_saas::{AxumAppState, BindingScope, RouteBinding};
use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

static MY_MIG: Migrator = sqlx::migrate!("./migrations");

async fn setup(pool: PgPool) -> (Router, Arc<AxumAppState>) {
    db::migrate_composed(&pool, &[&MY_MIG]).await.unwrap();
    let state = AxumAppState::builder(pool, "test-jwt")
        .with_resource_types(&[
            ResourceType::workspace("course", &["read", "write", "publish"]),
            ResourceType::workspace("assignment", &["read", "grade"]),
            ResourceType::tenant("batch", &["read", "manage"]),
            ResourceType::tenant("file", &["read", "write", "delete"]),
        ])
        .with_bindings([
            RouteBinding::read(
                Method::GET,
                "/workspaces/{workspace_id}/courses",
                BindingScope::WorkspaceFromPath("workspace_id"),
                "course",
                "read",
            ),
            RouteBinding::mutating(
                Method::POST,
                "/workspaces/{workspace_id}/courses",
                BindingScope::WorkspaceFromPath("workspace_id"),
                "course",
                "write",
            ),
            RouteBinding::read(
                Method::GET,
                "/tenants/{tenant_id}/files",
                BindingScope::TenantFromPath("tenant_id"),
                "file",
                "read",
            ),
            RouteBinding::mutating(
                Method::POST,
                "/tenants/{tenant_id}/batches",
                BindingScope::TenantFromPath("tenant_id"),
                "batch",
                "manage",
            ),
        ])
        .build()
        .await
        .unwrap();
    let state = Arc::new(state);
    (minimal_lms::build_app(state.clone()), state)
}

fn parse_cookies(resp: &Response) -> Vec<(String, String)> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .filter_map(|s| {
            let first = s.split(";").next()?;
            let (n, v) = first.split_once("=")?;
            let is_rm = s.contains("Max-Age=0") || s.contains("max-age=0");
            (!is_rm).then(|| (n.trim().to_string(), v.to_string()))
        })
        .collect()
}

fn find_cookie<'a>(jar: &'a [(String, String)], name: &str) -> &'a str {
    &jar.iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no cookie {name}"))
        .1
}

async fn json_body(resp: Response) -> serde_json::Value {
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null)
}

async fn register(router: &Router, email: &str) -> (Vec<(String, String)>, AuthUser) {
    let body = serde_json::json!({"email": email, "password": "Password123!"}).to_string();
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register must succeed");
    let jar = parse_cookies(&resp);
    let user: AuthUser = serde_json::from_value(json_body(resp).await["user"].clone()).unwrap();
    (jar, user)
}

async fn post_json(
    router: &Router,
    uri: &str,
    jar: &[(String, String)],
    body: serde_json::Value,
) -> Response {
    let cookie = jar
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let csrf = find_cookie(jar, "csrf").to_string();
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", csrf)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn grant_platform_admin(state: &AxumAppState, uid: Uuid) {
    let k = RoleKey::parse("owner").unwrap();
    let perms =
        rust_saas::access::get_permissions_for_role(state.saas.access().unwrap(), "platform", &k)
            .await
            .unwrap();
    state
        .saas
        .authz()
        .grant_role(uid, "platform", "owner", &perms)
        .await
        .unwrap();
}

async fn bootstrap_owner(
    state: &AxumAppState,
    router: &Router,
    email: &str,
) -> (Vec<(String, String)>, AuthUser, Uuid, Uuid) {
    let (jar, user) = register(router, email).await;
    grant_platform_admin(state, user.id).await;
    let k = RoleKey::parse("owner").unwrap();
    let t = platform::provision_tenant(&state.saas, &user, format!("T-{email}"), &user, &k)
        .await
        .unwrap();
    let ws = tenant::create_workspace_with_owner(
        &state.saas,
        &user,
        t.id,
        format!("W-{email}"),
        &user,
        &k,
    )
    .await
    .unwrap();
    (jar, user, t.id, ws.id)
}

#[sqlx::test(migrations = false)]
async fn course_editor_creates_course(pool: PgPool) {
    let (router, state) = setup(pool).await;
    let (jar, _u, _t, ws) = bootstrap_owner(&state, &router, "owner@a.test").await;
    let resp = post_json(
        &router,
        &format!("/workspaces/{ws}/courses"),
        &jar,
        serde_json::json!({"title": "Rust 101"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "owner has course:write");
    assert_eq!(json_body(resp).await["title"], "Rust 101");
}

#[sqlx::test(migrations = false)]
async fn viewer_reads_course(pool: PgPool) {
    let (router, state) = setup(pool).await;
    let (_oj, owner, _t, ws) = bootstrap_owner(&state, &router, "owner@a.test").await;
    let (jar, viewer) = register(&router, "viewer@a.test").await;
    let k = RoleKey::parse("viewer").unwrap();
    let dom = rust_saas::domain::workspace_domain(ws);
    saas_access::create_role(
        &state.saas,
        &owner,
        &dom,
        &k,
        "Viewer".into(),
        "".into(),
        &[],
    )
    .await
    .unwrap();
    saas_access::assign_role(&state.saas, &owner, viewer.id, &dom, &k)
        .await
        .unwrap();
    let resp = post_json(
        &router,
        &format!("/workspaces/{ws}/courses"),
        &jar,
        serde_json::json!({"title": "x"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "viewer has no course:write"
    );
}

#[sqlx::test(migrations = false)]
async fn batch_requires_tenant_manage(pool: PgPool) {
    let (router, state) = setup(pool).await;
    let (_oj, owner, tid, _w) = bootstrap_owner(&state, &router, "owner@a.test").await;
    let (jar, member) = register(&router, "member@a.test").await;
    let k = RoleKey::parse("viewer").unwrap();
    let dom = rust_saas::domain::tenant_domain(tid);
    saas_access::create_role(
        &state.saas,
        &owner,
        &dom,
        &k,
        "Viewer".into(),
        "".into(),
        &[],
    )
    .await
    .unwrap();
    saas_access::assign_role(&state.saas, &owner, member.id, &dom, &k)
        .await
        .unwrap();
    let resp = post_json(
        &router,
        &format!("/tenants/{tid}/batches"),
        &jar,
        serde_json::json!({"name": "B1"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "member has no batch:manage"
    );
}
