#![allow(dead_code)]

use std::sync::Arc;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use axum_minimal::build_app;
use http_body_util::BodyExt;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use rust_saas::access::RoleKey;
use rust_saas::AxumAppState;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();

fn prometheus_handle() -> PrometheusHandle {
    PROMETHEUS
        .get_or_init(|| {
            let recorder = PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            let _ = metrics::set_global_recorder(recorder);
            handle
        })
        .clone()
}

async fn setup(pool: PgPool) -> (Router, Arc<AxumAppState>) {
    let state = AxumAppState::builder(pool, "test-jwt-secret-not-for-prod")
        .with_prometheus(prometheus_handle())
        .build()
        .await
        .expect("build must succeed");
    let state = Arc::new(state);
    let router = build_app(state.clone());
    (router, state)
}

async fn grant_platform_admin(state: &AxumAppState, user_id: Uuid) {
    let owner_key = RoleKey::parse("owner").expect("owner key");
    let perms = rust_saas::access::get_permissions_for_role(
        state.saas.access().expect("access"),
        "platform",
        &owner_key,
    )
    .await
    .expect("platform perms");
    state
        .saas
        .authz()
        .grant_role(user_id, "platform", "owner", &perms)
        .await
        .expect("grant platform owner");
}

fn parse_set_cookies(resp: &Response) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for hv in resp.headers().get_all(header::SET_COOKIE) {
        if let Ok(s) = hv.to_str() {
            let first = s.split(';').next().unwrap_or("");
            let Some((name, value)) = first.split_once('=') else {
                continue;
            };
            let is_removal = s.contains("Max-Age=0") || s.contains("max-age=0");
            if !is_removal {
                out.push((name.trim().to_string(), value.to_string()));
            }
        }
    }
    out
}

fn cookie_header(jar: &[(String, String)]) -> String {
    jar.iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn find_cookie<'a>(jar: &'a [(String, String)], name: &str) -> Option<&'a str> {
    jar.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

async fn body_json(resp: Response) -> serde_json::Value {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn body_string(resp: Response) -> String {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn unique_email() -> String {
    format!("test-{}@test.local", Uuid::new_v4())
}

async fn register_and_get_jar(router: &Router, email: &str) -> (Vec<(String, String)>, Uuid) {
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
        .expect("register oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "register must succeed");
    let jar = parse_set_cookies(&resp);
    let json = body_json(resp).await;
    let uid = json["user"]["id"]
        .as_str()
        .expect("user.id")
        .parse::<Uuid>()
        .expect("uuid");
    (jar, uid)
}

async fn post_json_with_csrf(
    router: &Router,
    uri: &str,
    jar: &[(String, String)],
    body: serde_json::Value,
) -> Response {
    let cookie = cookie_header(jar);
    let csrf = find_cookie(jar, "csrf").expect("csrf cookie").to_string();
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("post_json_with_csrf oneshot")
}

async fn get_with_jar(router: &Router, uri: &str, jar: &[(String, String)]) -> Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie_header(jar))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("get_with_jar oneshot")
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn healthz_returns_200(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await, serde_json::json!({"status": "ok"}));
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn protected_route_requires_auth(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/tenants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({"error": "unauthorized"})
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn register_sets_auth_cookies(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let email = unique_email();
    let body = serde_json::json!({"email": email, "password": "Password123!"}).to_string();
    let resp = router
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
    assert_eq!(resp.status(), StatusCode::OK);
    let jar = parse_set_cookies(&resp);
    assert!(
        find_cookie(&jar, "access_token").is_some(),
        "access_token missing: {jar:?}"
    );
    assert!(
        find_cookie(&jar, "refresh_token").is_some(),
        "refresh_token missing: {jar:?}"
    );
    assert!(find_cookie(&jar, "csrf").is_some(), "csrf missing: {jar:?}");
    let json = body_json(resp).await;
    assert_eq!(json["user"]["email"].as_str(), Some(email.as_str()));
    assert_eq!(json["user"]["email_verified"].as_bool(), Some(false));
    assert_eq!(json["email_result"], "Disabled");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn refresh_returns_current_user(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let email = unique_email();
    let (jar, _) = register_and_get_jar(&router, &email).await;
    let csrf = find_cookie(&jar, "csrf").expect("csrf").to_string();
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header(header::COOKIE, cookie_header(&jar))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["email"].as_str(), Some(email.as_str()));
    assert_eq!(json["email_verified"].as_bool(), Some(false));
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn logout_clears_cookies(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let email = unique_email();
    let (jar, _) = register_and_get_jar(&router, &email).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header(header::COOKIE, cookie_header(&jar))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let set_cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok().map(String::from))
        .collect();
    let is_removal = |name: &str| {
        set_cookies.iter().any(|s| {
            s.starts_with(&format!("{name}="))
                && (s.contains("Max-Age=0") || s.contains("max-age=0"))
        })
    };
    assert!(
        is_removal("access_token"),
        "no access_token removal in {set_cookies:?}"
    );
    assert!(
        is_removal("refresh_token"),
        "no refresh_token removal in {set_cookies:?}"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn tenant_and_workspace_flow(pool: PgPool) {
    let (router, state) = setup(pool).await;
    let email = unique_email();
    let (jar, uid) = register_and_get_jar(&router, &email).await;
    grant_platform_admin(&state, uid).await;
    let resp = post_json_with_csrf(
        &router,
        "/tenants",
        &jar,
        serde_json::json!({"name": "Acme"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "POST /tenants must succeed");
    let tenant = body_json(resp).await;
    let tenant_id = tenant["id"].as_str().expect("tenant.id").to_string();
    assert_eq!(tenant["name"], "Acme");
    assert_eq!(tenant["status"], "active");
    let resp = post_json_with_csrf(
        &router,
        "/workspaces",
        &jar,
        serde_json::json!({"tenant_id": tenant_id, "name": "Engineering"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST /workspaces must succeed"
    );
    let ws = body_json(resp).await;
    assert_eq!(ws["name"], "Engineering");
    assert_eq!(ws["tenant_id"], tenant_id);
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn post_tenants_requires_platform_permission(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let email = unique_email();
    let (jar, _) = register_and_get_jar(&router, &email).await;
    let resp = post_json_with_csrf(
        &router,
        "/tenants",
        &jar,
        serde_json::json!({"name": "Acme"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({"error": "forbidden"})
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn post_tenants_without_csrf_token_is_rejected(pool: PgPool) {
    let (router, state) = setup(pool).await;
    let email = unique_email();
    let (jar, uid) = register_and_get_jar(&router, &email).await;
    grant_platform_admin(&state, uid).await;
    let body = serde_json::json!({"name": "Acme"}).to_string();
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tenants")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie_header(&jar))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({"error": "csrf token mismatch"})
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn suspended_tenant_blocks_workspace_creation(pool: PgPool) {
    let (router, state) = setup(pool.clone()).await;
    let email = unique_email();
    let (jar, uid) = register_and_get_jar(&router, &email).await;
    grant_platform_admin(&state, uid).await;
    let resp = post_json_with_csrf(
        &router,
        "/tenants",
        &jar,
        serde_json::json!({"name": "Acme"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let tenant = body_json(resp).await;
    let tenant_id = tenant["id"].as_str().unwrap().to_string();
    sqlx::query("update tenants set status = 'suspended' where id = $1")
        .bind(Uuid::parse_str(&tenant_id).unwrap())
        .execute(&pool)
        .await
        .expect("suspend tenant");
    let resp = post_json_with_csrf(
        &router,
        "/workspaces",
        &jar,
        serde_json::json!({"tenant_id": tenant_id, "name": "Engineering"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({"error": "tenant is suspended"})
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn audit_requires_platform_audit_read(pool: PgPool) {
    let (router, state) = setup(pool).await;
    let email = unique_email();
    let (jar, uid) = register_and_get_jar(&router, &email).await;
    let resp = get_with_jar(&router, "/audit?limit=10", &jar).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({"error": "forbidden"})
    );
    grant_platform_admin(&state, uid).await;
    let resp = get_with_jar(&router, "/audit?limit=10", &jar).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "platform admin must see audit"
    );
    let json = body_json(resp).await;
    assert!(
        json["items"].is_array(),
        "audit body must be a Page with items array: {json:?}"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn register_rate_limited_at_4_per_hour(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let email = unique_email();
    let body = serde_json::json!({"email": email, "password": "Password123!"}).to_string();
    for i in 0..3 {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        assert!(
            status == StatusCode::OK || status == StatusCode::CONFLICT,
            "attempt {i}: expected 200 or 409, got {status}"
        );
    }
    let resp = router
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
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = resp
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After")
        .to_str()
        .expect("ascii");
    let n: u64 = retry_after.parse().expect("integer");
    assert!(n > 0 && n <= 3600, "Retry-After out of range: {n}");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn pagination_limits_and_offsets_tenants(pool: PgPool) {
    let (router, state) = setup(pool).await;
    let email = unique_email();
    let (jar, uid) = register_and_get_jar(&router, &email).await;
    grant_platform_admin(&state, uid).await;
    for i in 0..2 {
        let resp = post_json_with_csrf(
            &router,
            "/tenants",
            &jar,
            serde_json::json!({"name": format!("Acme {}", i)}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = get_with_jar(&router, "/tenants?limit=1&offset=0", &jar).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page1 = body_json(resp).await;
    assert_eq!(page1["total"], 2);
    assert_eq!(page1["items"].as_array().unwrap().len(), 1);
    let id1 = page1["items"][0]["id"].as_str().unwrap().to_string();
    let resp = get_with_jar(&router, "/tenants?limit=1&offset=1", &jar).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page2 = body_json(resp).await;
    let id2 = page2["items"][0]["id"].as_str().unwrap().to_string();
    assert_ne!(id1, id2, "items on different pages must be distinct");
    let resp = get_with_jar(&router, "/tenants?limit=1000", &jar).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page3 = body_json(resp).await;
    assert_eq!(page3["limit"], 200);
    assert_eq!(page3["total"], 2);
    assert_eq!(page3["items"].as_array().unwrap().len(), 2);
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn readyz_returns_200(pool: PgPool) {
    let (router, _) = setup(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["checks"]["db"], "ok");
    let redis = json["checks"]["redis"].as_str().unwrap_or("");
    assert!(
        redis == "ok" || redis == "not_configured",
        "redis must be ok/not_configured, got: {redis:?}"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn metrics_returns_prometheus_format(pool: PgPool) {
    let (router, _) = setup(pool).await;
    metrics::counter!("e2e_axum_minimal_marker").increment(1);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("e2e_axum_minimal_marker"),
        "expected marker, got: {}",
        &body[..body.len().min(300)]
    );
    assert!(
        body.contains("# TYPE"),
        "expected Prometheus exposition format"
    );
}
