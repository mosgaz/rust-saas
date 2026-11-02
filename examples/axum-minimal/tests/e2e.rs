//! Stage 4.7: E2E HTTP tests for `axum-minimal`.
//!
//! **In-process.** No TCP port, no `hyper::Server`. Tests drive the same
//! `axum::Router` that `main.rs` serves via `tower::ServiceExt::oneshot`.
//!
//! **Isolated DB per test.** `#[sqlx::test]` creates a fresh database per
//! test from `DATABASE_URL`, applies `crates/db/migrations`, drops it after.
//!
//! **Cookie jar, manually.** No `reqwest` — cookies are parsed from
//! `Set-Cookie` and re-sent via `Cookie:`.
//!
//! **CSRF.** Mutating non-auth paths require `X-CSRF-Token` == `csrf` cookie.
//! The `csrf` cookie is issued by `csrf_issue` on the first request.
//!
//! **Coverage (Stage 4.7, plan `Приблизительный план` §3):**
//! 1. Smoke — `/healthz` public; protected route → 401 anon.
//! 2. Auth flow — register / refresh / logout.
//! 3. Tenant & workspace flow with CSRF.
//! 4. Tenant suspension → 403 for tenant user.
//! 5. Audit access — platform admin 200, regular user 403.
//! 6. Rate limiting — 4th register → 429 + `Retry-After`.

#![allow(dead_code)] // Some helpers are used by later steps.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use axum_minimal::build_app;
use axum_minimal::cookie::CookieConfig;
use axum_minimal::email::NoopEmailSender;
use axum_minimal::rate_limit::SimpleRateLimiter;
use axum_minimal::state::AppState;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

// ─── Setup ─────────────────────────────────────────────────────────────────

fn test_cookie_config() -> Arc<CookieConfig> {
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("static SocketAddr");
    Arc::new(CookieConfig::from_env(&bind))
}

/// Builds `(Router, AppState)` with the same wiring as `main.rs`.
///
/// Tests that need to seed authorization (`grant_platform_admin`) use
/// `state.saas.authz()` to reach the live enforcer — direct SQL would not
/// update the in-memory cache.
async fn setup_app(pool: PgPool) -> (Router, Arc<AppState>) {
    let authz: Arc<dyn authz::AuthorizationEngine> = Arc::new(
        authz_casbin::CasbinAuthz::from_pool(pool.clone())
            .await
            .expect("casbin init"),
    );
    let audit: Arc<dyn audit::AuditLogger> =
        Arc::new(audit_pg::PgAuditLogger::from_pool(pool.clone()));
    let access = Arc::new(
        access::AccessState::new(pool.clone(), authz.clone()).with_audit(audit.clone()),
    );
    let authn = Arc::new(
        authn::Authn::with_ttl(
            pool.clone(),
            "test-jwt-secret-not-for-prod",
            chrono::Duration::minutes(15),
            chrono::Duration::days(30),
        )
        .with_audit(audit.clone()),
    );
    let saas = Arc::new(
        saas::SaasBuilder::new(pool)
            .with_authz(authz)
            .with_access(access)
            .with_audit(audit)
            .build()
            .expect("saas builder"),
    );
    let email: Arc<dyn axum_minimal::email::EmailSender> = Arc::new(NoopEmailSender);
    let rate_limit = Arc::new(SimpleRateLimiter::new());
    let cookie = test_cookie_config();

    let state = Arc::new(AppState {
        authn,
        saas,
        email,
        rate_limit,
        cookie,
    });
    let router = build_app(state.clone());
    (router, state)
}

async fn grant_platform_admin(state: &AppState, user_id: Uuid) {
    let owner_key = access::RoleKey::parse("owner").expect("role key");
    let perms = access::get_permissions_for_role(state.saas.access(), "platform", &owner_key)
        .await
        .expect("platform owner perms");
    state
        .saas
        .authz()
        .grant_role(user_id, "platform", "owner", &perms)
        .await
        .expect("grant platform owner");
}

// ─── Cookie helpers ────────────────────────────────────────────────────────

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

fn unique_email() -> String {
    format!("test-{}@test.local", Uuid::new_v4())
}

async fn register_and_get_jar(router: &Router, email: &str) -> (Vec<(String, String)>, Uuid) {
    let body = serde_json::json!({
        "email": email,
        "password": "Password123!",
    })
    .to_string();
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
    let user_id = json["user"]["id"]
        .as_str()
        .expect("register body must carry user.id")
        .parse::<Uuid>()
        .expect("user.id is a UUID");
    (jar, user_id)
}

async fn post_json_with_csrf(
    router: &Router,
    uri: &str,
    jar: &[(String, String)],
    body: serde_json::Value,
) -> Response {
    let cookie = cookie_header(jar);
    let csrf = find_cookie(jar, "csrf").expect("csrf cookie in jar").to_string();
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

// ─── Smoke ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn healthz_returns_200(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "status": "ok" })
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn protected_route_requires_auth(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/tenants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "unauthorized" })
    );
}

// ─── Auth flow ─────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn register_sets_auth_cookies(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let email = unique_email();
    let body = serde_json::json!({
        "email": email,
        "password": "Password123!",
    })
    .to_string();

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
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let jar = parse_set_cookies(&resp);
    assert!(find_cookie(&jar, "access_token").is_some(), "access_token missing: {jar:?}");
    assert!(find_cookie(&jar, "refresh_token").is_some(), "refresh_token missing: {jar:?}");
    assert!(find_cookie(&jar, "csrf").is_some(), "csrf cookie must be issued: {jar:?}");

    let json = body_json(resp).await;
    assert_eq!(json["user"]["email"].as_str(), Some(email.as_str()));
    assert_eq!(json["user"]["email_verified"].as_bool(), Some(false));
    assert_eq!(json["email_result"], "Disabled");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn refresh_returns_current_user(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let email = unique_email();
    let (jar, _) = register_and_get_jar(&router, &email).await;
    let cookie_hdr = cookie_header(&jar);
    let csrf = find_cookie(&jar, "csrf").expect("csrf cookie").to_string();

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header(header::COOKIE, &cookie_hdr)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["email"].as_str(), Some(email.as_str()));
    assert_eq!(json["email_verified"].as_bool(), Some(false));
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn logout_clears_cookies(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let email = unique_email();
    let (jar, _) = register_and_get_jar(&router, &email).await;
    let cookie_hdr = cookie_header(&jar);

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header(header::COOKIE, &cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let set_cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|hv| hv.to_str().ok().map(String::from))
        .collect();
    let is_removal = |name: &str| {
        set_cookies.iter().any(|s| {
            s.starts_with(&format!("{name}="))
                && (s.contains("Max-Age=0") || s.contains("max-age=0"))
        })
    };
    assert!(is_removal("access_token"), "no access_token removal in {set_cookies:?}");
    assert!(is_removal("refresh_token"), "no refresh_token removal in {set_cookies:?}");
}

// ─── Tenant & workspace flow ───────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn tenant_and_workspace_flow(pool: PgPool) {
    let (router, state) = setup_app(pool).await;
    let email = unique_email();
    let (jar, user_id) = register_and_get_jar(&router, &email).await;
    grant_platform_admin(&state, user_id).await;

    let resp = post_json_with_csrf(
        &router,
        "/tenants",
        &jar,
        serde_json::json!({ "name": "Acme" }),
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
        serde_json::json!({ "tenant_id": tenant_id, "name": "Engineering" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "POST /workspaces must succeed");
    let ws = body_json(resp).await;
    assert_eq!(ws["name"], "Engineering");
    assert_eq!(ws["tenant_id"], tenant_id);
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn post_tenants_requires_platform_permission(pool: PgPool) {
    let (router, _state) = setup_app(pool).await;
    let email = unique_email();
    let (jar, _) = register_and_get_jar(&router, &email).await;

    let resp = post_json_with_csrf(
        &router,
        "/tenants",
        &jar,
        serde_json::json!({ "name": "Acme" }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "forbidden" })
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn post_tenants_without_csrf_token_is_rejected(pool: PgPool) {
    let (router, state) = setup_app(pool).await;
    let email = unique_email();
    let (jar, user_id) = register_and_get_jar(&router, &email).await;
    grant_platform_admin(&state, user_id).await;

    let body = serde_json::json!({ "name": "Acme" }).to_string();
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
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "csrf token mismatch" })
    );
}

// ─── Tenant suspension ─────────────────────────────────────────────────────

/// `POST /workspaces` calls `resolve_active_tenant` in the handler. A
/// suspended tenant must yield `403 {"error": "tenant is suspended"}` —
/// this asserts the wiring between `main.rs` and `saas::platform`, not just
/// the library function in isolation.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn suspended_tenant_blocks_workspace_creation(pool: PgPool) {
    let (router, state) = setup_app(pool.clone()).await;
    let email = unique_email();
    let (jar, user_id) = register_and_get_jar(&router, &email).await;
    grant_platform_admin(&state, user_id).await;

    // Create a tenant (caller becomes its owner + member).
    let resp = post_json_with_csrf(
        &router,
        "/tenants",
        &jar,
        serde_json::json!({ "name": "Acme" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let tenant = body_json(resp).await;
    let tenant_id = tenant["id"].as_str().unwrap().to_string();

    // Suspend via direct SQL — axum-minimal has no /suspend endpoint.
    sqlx::query("update tenants set status = 'suspended' where id = $1")
        .bind(Uuid::parse_str(&tenant_id).unwrap())
        .execute(&pool)
        .await
        .expect("suspend tenant");

    // POST /workspaces → 403 "tenant is suspended".
    let resp = post_json_with_csrf(
        &router,
        "/workspaces",
        &jar,
        serde_json::json!({ "tenant_id": tenant_id, "name": "Engineering" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "tenant is suspended" })
    );
}

// ─── Audit access ──────────────────────────────────────────────────────────

/// `GET /audit` requires `(audit, read)` in `PLATFORM_DOMAIN`. A regular
/// user (valid session, no platform role) is rejected by `auth_layer`
/// **before** the handler — 403. After `grant_platform_admin`, the same
/// request returns 200 + a JSON array (possibly empty; we assert only the
/// shape, not rows — `list_audit` returns most recent N).
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn audit_requires_platform_audit_read(pool: PgPool) {
    let (router, state) = setup_app(pool).await;
    let email = unique_email();
    let (jar, user_id) = register_and_get_jar(&router, &email).await;

    // 1. Regular user: 403.
    let resp = get_with_jar(&router, "/audit?limit=10", &jar).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "forbidden" })
    );

    // 2. Grant platform admin → 200 + array.
    grant_platform_admin(&state, user_id).await;
    let resp = get_with_jar(&router, "/audit?limit=10", &jar).await;
    assert_eq!(resp.status(), StatusCode::OK, "platform admin must see audit");
    let json = body_json(resp).await;
    assert!(json.is_array(), "audit body must be a JSON array: {json:?}");
}

// ─── Rate limiting ─────────────────────────────────────────────────────────

/// `SimpleRateLimiter` in `register` is per-email, 3 per hour. The counter
/// is incremented on **every** call to `try_acquire`, regardless of whether
/// `authn.register` succeeds — so 3 attempts (200 or 409) consume the quota,
/// the 4th → 429 with `Retry-After`.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn register_rate_limited_at_4_per_hour(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let email = unique_email();
    let body = serde_json::json!({ "email": email, "password": "Password123!" }).to_string();

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
            .expect("oneshot");
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
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let retry_after = resp
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After header on 429")
        .to_str()
        .expect("Retry-After is ASCII");
    let n: u64 = retry_after
        .parse()
        .expect("Retry-After is an integer number of seconds");
    assert!(n > 0 && n <= 3600, "Retry-After out of range: {n}");
}
