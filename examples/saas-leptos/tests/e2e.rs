//! Stage 4.7: E2E tests for `saas-leptos`.
//!
//! **SSR + CSRF via HTTP, business logic via `AppState`.** This is the
//! `saas-leptos`-specific compromise that `axum-minimal` does not need:
//!
//! - `axum-minimal` has real `axum` handlers — every scenario is driven
//!   by HTTP (cookies, `X-CSRF-Token`, JSON body).
//! - `saas-leptos` server logic lives in Leptos `#[server]` functions,
//!   reachable only at `/_server/{hash}` where the hash is computed by the
//!   `#[server]` macro from the qualified function name. Without
//!   reimplementing that hash (fragile against `server_fn` version bumps)
//!   or requiring `#[server(endpoint = "...")]` (changes to example code),
//!   the HTTP surface of `#[server]` is not reliably addressable from tests.
//!
//! So the split:
//! - **HTTP (this file)**: SSR rendering of public + guarded pages, and
//!   `same_origin_guard` (Origin/Host CSRF) on a protected router.
//! - **`state.authn.*` / `state.saas.*`**: register → rotate refresh,
//!   `provision_tenant` → `create_workspace`, `suspend_tenant` →
//!   `resolve_active_tenant`, `my_permissions` for audit, `rate_limit`.
//!   These are the exact library calls the `#[server]` handlers make; the
//!   coverage difference is Leptos's HTTP marshalling (framework code,
//!   tested by Leptos upstream) and cookie plumbing (already exercised in
//!   `axum-minimal`).
//!
//! **Coverage (Stage 4.7, plan `Приблизительный план` §3):**
//! 1. Smoke — `/healthz` 200, `/` SSR HTML, `/tenants` SSR placeholder.
//! 2. Auth flow — register → rotate refresh; login → can rotate.
//! 3. Tenant & workspace flow — `provision_tenant` → `create_workspace`.
//! 4. Tenant suspension — `suspend_tenant` → `resolve_active_tenant` 403.
//! 5. Audit access — `(audit, read)` via `my_permissions`.
//! 6. Rate limiting — 4th `try_acquire` → `Err`.
//! 7. CSRF — `same_origin_guard` 403 on Origin mismatch.

#![allow(dead_code)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use saas_leptos::build_app;
use saas_leptos::cookie::CookieConfig;
use saas_leptos::email::NoopEmailSender;
use rate_limiter::RateLimiter;
use saas_leptos::state::AppState;

// ─── Setup ─────────────────────────────────────────────────────────────────

fn test_cookie_config() -> Arc<CookieConfig> {
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("static SocketAddr");
    Arc::new(CookieConfig::from_env(&bind))
}

fn test_leptos_options() -> leptos::prelude::LeptosOptions {
    leptos::config::get_configuration(None)
        .expect("leptos config from [package.metadata.leptos]")
        .leptos_options
}

async fn setup_app(pool: PgPool) -> (Router, AppState) {
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
    let email: Arc<dyn saas_leptos::email::EmailSender> = Arc::new(NoopEmailSender);
    let rate_limit: Arc<dyn RateLimiter> = Arc::new(rate_limiter::InMemoryRateLimiter::new());
    let cookie = test_cookie_config();

    let state = AppState {
        authn,
        saas,
        leptos_options: test_leptos_options(),
        email,
        rate_limit,
        cookie,
    };
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

// ─── Helpers ───────────────────────────────────────────────────────────────

async fn body_string(resp: Response) -> String {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
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

const TEST_HOST: &str = "127.0.0.1:3395";

// ─── Smoke ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn healthz_returns_200(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header(header::HOST, TEST_HOST)
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
async fn root_renders_ssr_html(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::HOST, TEST_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.starts_with("text/html"), "expected text/html, got {ct:?}");
    let html = body_string(resp).await;
    assert!(
        html.contains("Multitenant MVP"),
        "SSR of `/` must contain the HomePage headline"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn guarded_route_renders_ssr_content(pool: PgPool) {
    let (router, state) = setup_app(pool).await;

    // Register an authenticated user
    let email = format!("user-{}@test.local", Uuid::new_v4());
    let user = state.authn.register(&email, "Password123!").await.expect("register");
    let access = state.authn.issue_access_token(&user).expect("issue token");
    let refresh = state.authn.issue_refresh_token(&user).await.expect("issue refresh");

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/tenants")
                .header(header::HOST, TEST_HOST)
                .header(header::COOKIE, format!("access_token={access}; refresh_token={refresh}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    // Stage 4.9: `GuardRoute` uses `Resource`/`Suspense`. For an authenticated
    // request on a guarded route, SSR must render the actual page content,
    // *not* the "Loading..." placeholder.
    assert!(
        html.contains("My tenants"),
        "guarded SSR page must render content, got: {}",
        &html[..html.len().min(500)]
    );
    assert!(
        !html.contains("Loading..."),
        "guarded SSR page must not render the loading placeholder"
    );
}

// ─── CSRF: same_origin_guard ───────────────────────────────────────────────

/// `Origin` mismatch → 403 with `"cross-origin request rejected"`. The
/// guard sits on the protected router (`route_layer`), so even a request
/// that would not match a real handler still gets rejected before routing.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn post_with_cross_origin_is_forbidden(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tenants")
                .header(header::HOST, TEST_HOST)
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "cross-origin request rejected" })
    );
}

/// No `Origin` (non-browser client) → pass-through. The request may not
/// match a real route (Leptos returns 404 / 405 — we only assert "not 403").
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn post_without_origin_passes_guard(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tenants")
                .header(header::HOST, TEST_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

/// Matching `Origin`/`Host` (same authority) → pass-through. Non-mutating
/// methods are already exempt but `POST` is not.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn post_with_same_origin_passes_guard(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tenants")
                .header(header::HOST, TEST_HOST)
                .header(header::ORIGIN, format!("http://{TEST_HOST}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── Auth flow (via `state.authn` — same calls `#[server]` makes) ─────────

/// `register` → `rotate_refresh_token` returns a fresh pair. Covers the
/// auth primitives end-to-end at the library boundary.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn register_and_rotate_refresh_token(pool: PgPool) {
    let (_, state) = setup_app(pool).await;
    let email = format!("auth-{}@test.local", Uuid::new_v4());

    let user = state
        .authn
        .register(&email, "Password123!")
        .await
        .expect("register");
    assert_eq!(user.email, email);
    assert!(!user.email_verified);

    let refresh = state
        .authn
        .issue_refresh_token(&user)
        .await
        .expect("issue refresh");
    let (rotated, rotated_user) = state
        .authn
        .rotate_refresh_token(&refresh)
        .await
        .expect("rotate");
    assert_ne!(rotated, refresh);
    assert_eq!(rotated_user.id, user.id);
}

/// `login` → `issue_access_token` produces a three-part JWT.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn login_issues_access_token(pool: PgPool) {
    let (_, state) = setup_app(pool).await;
    let email = format!("auth-{}@test.local", Uuid::new_v4());
    state
        .authn
        .register(&email, "Password123!")
        .await
        .expect("register");

    let user = state
        .authn
        .login(&email, "Password123!")
        .await
        .expect("login");
    let token = state
        .authn
        .issue_access_token(&user)
        .expect("issue access");
    assert_eq!(token.split('.').count(), 3, "JWT must have 3 parts");
}

// ─── Tenant & workspace flow (via `state.saas`) ───────────────────────────

/// `provision_tenant` (actor becomes owner) → `create_workspace` (actor
/// becomes workspace owner). Mirrors `#[server] create_tenant` +
/// `#[server] create_workspace`.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn provision_tenant_and_create_workspace(pool: PgPool) {
    let (_, state) = setup_app(pool).await;
    let admin_email = format!("admin-{}@test.local", Uuid::new_v4());
    let admin = state
        .authn
        .register(&admin_email, "Password123!")
        .await
        .expect("register admin");
    grant_platform_admin(&state, admin.id).await;

    let owner_email = format!("owner-{}@test.local", Uuid::new_v4());
    let owner = state
        .authn
        .register(&owner_email, "Password123!")
        .await
        .expect("register owner");
    let owner_key = access::RoleKey::parse("owner").unwrap();

    let tenant = saas::platform::provision_tenant(
        &state.saas,
        &admin,
        format!("Acme-{}", Uuid::new_v4()),
        &owner,
        &owner_key,
    )
    .await
    .expect("provision_tenant");

    let workspace = saas::tenant::create_workspace(
        &state.saas,
        &owner,
        tenant.id,
        format!("Eng-{}", Uuid::new_v4()),
        &owner,
        &owner_key,
    )
    .await
    .expect("create_workspace");

    assert_eq!(workspace.tenant_id, tenant.id);
}

// ─── Tenant suspension ─────────────────────────────────────────────────────

/// `suspend_tenant` (platform admin) → `resolve_active_tenant` for the
/// tenant's owner returns `CoreError::TenantSuspended`. This is the exact
/// check every mutation-path `#[server]` runs.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn suspended_tenant_blocks_resolve_active_tenant(pool: PgPool) {
    let (_, state) = setup_app(pool).await;
    let admin_email = format!("admin-{}@test.local", Uuid::new_v4());
    let admin = state
        .authn
        .register(&admin_email, "Password123!")
        .await
        .expect("register admin");
    grant_platform_admin(&state, admin.id).await;

    let owner_email = format!("owner-{}@test.local", Uuid::new_v4());
    let owner = state
        .authn
        .register(&owner_email, "Password123!")
        .await
        .expect("register owner");
    let owner_key = access::RoleKey::parse("owner").unwrap();

    let tenant = saas::platform::provision_tenant(
        &state.saas,
        &admin,
        format!("Acme-{}", Uuid::new_v4()),
        &owner,
        &owner_key,
    )
    .await
    .expect("provision_tenant");

    // Precondition: owner resolves fine when active.
    saas::platform::resolve_active_tenant(&state.saas, &owner, tenant.id)
        .await
        .expect("active tenant must resolve");

    saas::platform::suspend_tenant(&state.saas, &admin, tenant.id)
        .await
        .expect("suspend_tenant");

    let err = saas::platform::resolve_active_tenant(&state.saas, &owner, tenant.id)
        .await
        .expect_err("suspended tenant must be rejected");
    assert!(matches!(err, saas::CoreError::TenantSuspended), "got {err:?}");
}

// ─── Audit access ──────────────────────────────────────────────────────────

/// `(audit, read)` is granted to `platform` `owner` only. Platform admin
/// sees it; a regular user does not. This is what `#[server] list_audit`
/// checks before reading `audit_log`.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn audit_permission_gated_by_platform_owner(pool: PgPool) {
    let (_, state) = setup_app(pool).await;
    let admin_email = format!("admin-{}@test.local", Uuid::new_v4());
    let admin = state
        .authn
        .register(&admin_email, "Password123!")
        .await
        .expect("register admin");
    grant_platform_admin(&state, admin.id).await;

    let regular_email = format!("user-{}@test.local", Uuid::new_v4());
    let regular = state
        .authn
        .register(&regular_email, "Password123!")
        .await
        .expect("register regular");

    let has_audit_read = |perms: &[(String, String)]| {
        perms
            .iter()
            .any(|(r, a)| r == "audit" && a == "read")
    };

    let admin_perms = saas::access::my_permissions(&state.saas, &admin, domain::PLATFORM_DOMAIN)
        .await
        .expect("admin perms");
    assert!(
        has_audit_read(&admin_perms),
        "platform admin must hold `(audit, read)`"
    );

    let regular_perms = saas::access::my_permissions(&state.saas, &regular, domain::PLATFORM_DOMAIN)
        .await
        .expect("regular perms");
    assert!(
        !has_audit_read(&regular_perms),
        "regular user must NOT hold `(audit, read)`"
    );
}

// ─── Rate limiting ─────────────────────────────────────────────────────────

/// `SimpleRateLimiter` in `AppState` — `3 / hour` on register,
/// `5 / hour` on request_password_reset. The 4th `try_acquire` on the
/// register quota returns `Err(retry_after_secs)`.
#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn register_rate_limiter_blocks_after_three(pool: PgPool) {
    let (_, state) = setup_app(pool).await;
    let email = format!("rate-{}@test.local", Uuid::new_v4());
    let window = std::time::Duration::from_secs(3600);

    for i in 0..3 {
        state
            .rate_limit
            .try_acquire(&email, 3, window).await
            .unwrap_or_else(|_| panic!("attempt {i} must be under the limit"));
    }
    let retry_after = state
        .rate_limit
        .try_acquire(&email, 3, window).await
        .expect_err("4th attempt must be rejected");
    assert!(retry_after > 0 && retry_after <= 3600);
}

// ─── Pagination (Stage 4.8) ────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn pagination_via_state(pool: PgPool) {
    let (_, state) = setup_app(pool).await;
    let admin_email = format!("admin-{}@test.local", Uuid::new_v4());
    let admin = state.authn.register(&admin_email, "Password123!").await.unwrap();
    grant_platform_admin(&state, admin.id).await;

    let owner_email = format!("owner-{}@test.local", Uuid::new_v4());
    let owner = state.authn.register(&owner_email, "Password123!").await.unwrap();
    let owner_key = access::RoleKey::parse("owner").unwrap();

    // Create 3 tenants
    for i in 0..3 {
        saas::platform::provision_tenant(
            &state.saas,
            &admin,
            format!("Acme-{}-{}", Uuid::new_v4(), i),
            &owner,
            &owner_key,
        ).await.unwrap();
    }

    // Page 1: limit 2, offset 0
    let page1 = saas::platform::list_tenants_paged(&state.saas, &admin, 2, 0).await.unwrap();
    assert_eq!(page1.total, 3);
    assert_eq!(page1.items.len(), 2);

    // Page 2: limit 2, offset 2
    let page2 = saas::platform::list_tenants_paged(&state.saas, &admin, 2, 2).await.unwrap();
    assert_eq!(page2.total, 3);
    assert_eq!(page2.items.len(), 1);

    // Audit pagination: limit 1, offset 0
    let logger = audit_pg::PgAuditLogger::from_pool(state.saas.pool().clone());
    let audit_page = logger.list_paged(1, 0).await.unwrap();
    assert!(audit_page.total >= 3);
    assert_eq!(audit_page.items.len(), 1);
}

// ─── Stage 4.9: AuthLayer ──────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn auth_layer_blocks_unauthorized_ssr(pool: PgPool) {
    let (router, _) = setup_app(pool).await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/platform")
                .header(header::HOST, TEST_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_string(resp).await;
    assert!(
        body.contains("unauthorized"),
        "AuthLayer must return JSON error, got: {body}"
    );
    assert!(
        !body.contains("<html"),
        "AuthLayer must short-circuit before HTML rendering"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn auth_layer_blocks_forbidden_ssr(pool: PgPool) {
    let (router, state) = setup_app(pool).await;

    // Register a regular user (no platform role).
    let email = format!("user-{}@test.local", Uuid::new_v4());
    let user = state
        .authn
        .register(&email, "Password123!")
        .await
        .expect("register");

    let access = state.authn.issue_access_token(&user).expect("issue token");
    let refresh = state.authn.issue_refresh_token(&user).await.expect("issue refresh");

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/platform")
                .header(header::HOST, TEST_HOST)
                .header(header::COOKIE, format!("access_token={access}; refresh_token={refresh}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_string(resp).await;
    assert!(
        body.contains("forbidden"),
        "AuthLayer must return JSON error, got: {body}"
    );
    assert!(
        !body.contains("<html"),
        "AuthLayer must short-circuit before HTML rendering"
    );
}
