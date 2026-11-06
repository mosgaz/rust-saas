//! E2E tests for the ABAC-on-Casbin example.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use minimal_lms_abac::{build_app, MIGRATOR};
use rust_saas::access::registry::ResourceType;
use rust_saas::domain::workspace_domain;
use rust_saas::{db, AxumAppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup_app(pool: PgPool) -> (Router, Arc<AxumAppState>) {
    db::migrate_composed(&pool, &[&MIGRATOR])
        .await
        .expect("migrate_composed");

    let state = AxumAppState::builder(pool, "test-secret")
        .with_resource_types(&[
            ResourceType::workspace("course", &["read", "write"]),
            ResourceType::workspace("course_type_a", &["create"]),
            ResourceType::workspace("course_type_b", &["create"]),
        ])
        .build()
        .await
        .expect("build state");

    let state = Arc::new(state);
    let app = build_app(state.clone());
    (app, state)
}

async fn register_user(app: &Router, email: &str) -> (String, rust_saas::domain::AuthUser) {
    let body = json!({ "email": email, "password": "Test123!" });
    let req = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let cookie_header = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    // Parse AuthUser directly from the JSON response
    let user: rust_saas::domain::AuthUser = serde_json::from_value(json["user"].clone()).unwrap();

    (cookie_header, user)
}

fn csrf_from_cookie(cookie: &str) -> String {
    parse_cookies(cookie)
        .get("csrf")
        .cloned()
        .unwrap_or_default()
}

fn parse_cookies(cookie: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

async fn create_workspace(
    pool: &PgPool,
    state: &AxumAppState,
    actor: &rust_saas::domain::AuthUser,
    name: &str,
) -> Uuid {
    let tenant_id: Uuid =
        sqlx::query_scalar("INSERT INTO tenants (name, status) VALUES ($1, 'active') RETURNING id")
            .bind(name)
            .fetch_one(pool)
            .await
            .unwrap();

    let ws_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workspaces (tenant_id, name) VALUES ($1, 'ws') RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .unwrap();

    add_member(pool, tenant_id, ws_id, actor.id, "owner").await;

    let domain = workspace_domain(ws_id);

    // Grant owner all required permissions in workspace domain
    state
        .authz
        .grant_role(
            actor.id,
            &domain,
            "owner",
            &[
                ("course".into(), "read".into()),
                ("course".into(), "write".into()),
                ("course_type_a".into(), "create".into()),
                ("course_type_b".into(), "create".into()),
            ],
        )
        .await
        .unwrap();

    ws_id
}

async fn add_member(pool: &PgPool, tenant_id: Uuid, workspace_id: Uuid, user_id: Uuid, role: &str) {
    sqlx::query("INSERT INTO tenant_members (tenant_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(tenant_id).bind(user_id).bind(role).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(workspace_id).bind(user_id).bind(role).execute(pool).await.unwrap();
}

async fn get_tenant_id(pool: &PgPool, ws_id: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT tenant_id FROM workspaces WHERE id = $1")
        .bind(ws_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn add_cookie(mut req: Request<Body>, cookie: &str) -> Request<Body> {
    req.headers_mut().insert(
        header::COOKIE,
        header::HeaderValue::from_str(cookie).unwrap(),
    );
    req
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = false)]
async fn read_own_course_allowed_other_forbidden(pool: PgPool) {
    let (app, state) = setup_app(pool.clone()).await;
    let (cookie1, user1) = register_user(&app, "owner@test.com").await;
    let ws_id = create_workspace(&pool, &state, &user1, "tenant1").await;

    let course_id: Uuid = sqlx::query_scalar(
        "INSERT INTO courses (workspace_id, title, owner_id) VALUES ($1, 'test', $2) RETURNING id",
    )
    .bind(ws_id)
    .bind(user1.id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // 1. User1 (owner) reads -> 200 OK
    let req = Request::builder()
        .uri(format!("/courses/{}", course_id))
        .body(Body::empty())
        .unwrap();
    let req = add_cookie(req, &cookie1);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 2. User2 (non-owner) reads -> 403 Forbidden
    let (cookie2, user2) = register_user(&app, "other@test.com").await;
    let tenant_id = get_tenant_id(&pool, ws_id).await;
    add_member(&pool, tenant_id, ws_id, user2.id, "member").await;

    let req = Request::builder()
        .uri(format!("/courses/{}", course_id))
        .body(Body::empty())
        .unwrap();
    let req = add_cookie(req, &cookie2);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = false)]
async fn create_course_type_enforced(pool: PgPool) {
    let (app, state) = setup_app(pool.clone()).await;
    let (cookie1, user1) = register_user(&app, "owner@test.com").await;
    let ws_id = create_workspace(&pool, &state, &user1, "tenant1").await;
    let domain = workspace_domain(ws_id);
    let tenant_id = get_tenant_id(&pool, ws_id).await;

    // 1. User1 (owner) creates type_a -> 201 Created
    let body = json!({"title": "course1", "kind": "type_a"});
    let req = Request::builder()
        .method("POST")
        .uri(format!("/workspaces/{}/courses", ws_id))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf_from_cookie(&cookie1))
        .body(Body::from(body.to_string()))
        .unwrap();
    let req = add_cookie(req, &cookie1);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 2. User2 has no permissions yet -> tries type_a -> 403
    let (cookie2, user2) = register_user(&app, "user2@test.com").await;
    add_member(&pool, tenant_id, ws_id, user2.id, "member").await;

    let body = json!({"title": "course2", "kind": "type_a"});
    let req = Request::builder()
        .method("POST")
        .uri(format!("/workspaces/{}/courses", ws_id))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf_from_cookie(&cookie2))
        .body(Body::from(body.to_string()))
        .unwrap();
    let req = add_cookie(req, &cookie2);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 3. Grant user2 custom role with course_type_b:create directly in Casbin
    // (creates both g-row and p-row)
    state
        .authz
        .grant_role(
            user2.id,
            &domain,
            "editor_b",
            &[("course_type_b".to_string(), "create".to_string())],
        )
        .await
        .unwrap();

    // 4. User2 tries type_a -> still 403
    let body = json!({"title": "course3", "kind": "type_a"});
    let req = Request::builder()
        .method("POST")
        .uri(format!("/workspaces/{}/courses", ws_id))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf_from_cookie(&cookie2))
        .body(Body::from(body.to_string()))
        .unwrap();
    let req = add_cookie(req, &cookie2);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 5. User2 tries type_b -> 201 Created
    let body = json!({"title": "course4", "kind": "type_b"});
    let req = Request::builder()
        .method("POST")
        .uri(format!("/workspaces/{}/courses", ws_id))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf_from_cookie(&cookie2))
        .body(Body::from(body.to_string()))
        .unwrap();
    let req = add_cookie(req, &cookie2);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[sqlx::test(migrations = false)]
async fn update_course_status_gated(pool: PgPool) {
    let (app, state) = setup_app(pool.clone()).await;
    let (cookie1, user1) = register_user(&app, "owner@test.com").await;
    let ws_id = create_workspace(&pool, &state, &user1, "tenant1").await;

    let course_id: Uuid = sqlx::query_scalar(
        "INSERT INTO courses (workspace_id, title, owner_id, status) VALUES ($1, 'test', $2, 'draft') RETURNING id"
    ).bind(ws_id).bind(user1.id).fetch_one(&pool).await.unwrap();

    // 1. Draft status -> update allowed (200 OK)
    let body = json!({"title": "new title"});
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/courses/{}", course_id))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf_from_cookie(&cookie1))
        .body(Body::from(body.to_string()))
        .unwrap();
    let req = add_cookie(req, &cookie1);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 2. Archived status -> update denied (403 Forbidden)
    sqlx::query("UPDATE courses SET status = 'archived' WHERE id = $1")
        .bind(course_id)
        .execute(&pool)
        .await
        .unwrap();

    let body = json!({"title": "try again"});
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/courses/{}", course_id))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CSRF-Token", csrf_from_cookie(&cookie1))
        .body(Body::from(body.to_string()))
        .unwrap();
    let req = add_cookie(req, &cookie1);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
