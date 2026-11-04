//! Tests for `saas-axum`.
//!
//! Covers the A4.0–A4.3a surface:
//!
//! 1. `builder_defaults` — minimal `build()` works with a real DB.
//! 2. `builder_with_resource_types_bootstraps` — custom types reach
//!    `resource_types`.
//! 3. `builder_with_binding_stores_verbatim` — user bindings are stored
//!    (6 built-ins + 1 user binding, no fail-fast because resource/action
//!    are declared).
//! 4. `builder_auth_only_binding_stored` — `auth_only` constructs without
//!    a permission check.
//! 5. `build_app_smoke` — `GET /healthz` → 200.
//! 6. `build_app_unknown_path_404` — `GET /nonexistent` → 404.
//! 7. `without_rbac_access_is_none` — `.without_rbac()` leaves
//!    `state.access = None` and skips `bootstrap_all_core`.
//! 8. `prometheus_optional` — `/metrics` 404 without `with_prometheus`,
//!    200 with.
//!
//! A4.3a adds:
//! 9. `builder_rejects_unknown_binding_resource_type` — fail-fast.
//! 10. `builder_rejects_unknown_binding_action` — fail-fast.
//!
//! Each test gets its own isolated DB via `#[sqlx::test]`, applies
//! `crates/db/migrations`, and drops the DB afterwards.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use access::registry::ResourceType;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use http_body_util::BodyExt;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use saas_axum::{
    build_app, build_app_full, build_app_with_protected, AxumAppState, AxumAppStateBuilder,
    BindingScope, OwnedAuthzTarget, PathPermissions, RouteBinding,
};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

// ─── Prometheus (process-wide; `#[sqlx::test]` runs in one process) ───────

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

// ─── Helpers ─────────────────────────────────────────────────────────────

fn builder(pool: PgPool) -> AxumAppStateBuilder {
    AxumAppState::builder(pool, "test-jwt-secret-not-for-prod")
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

fn unique_name(label: &str) -> String {
    format!("{label}-{}", Uuid::new_v4())
}

/// Built-in bindings are 6 (A4.3a): `/healthz`, `/readyz`, `/metrics`,
/// `/auth/{register,login,logout}`.
const BUILT_IN_COUNT: usize = 6;

// ─── 1. builder_defaults ────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_defaults(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");

    assert!(state.access.is_some(), "default build has AccessState");
    assert!(
        state.prometheus.is_none(),
        "default build has no Prometheus"
    );
    assert!(
        state.path_permissions.is_none(),
        "default build has no PathPermissions"
    );
    assert_eq!(
        state.bindings.iter().count(),
        BUILT_IN_COUNT,
        "default build has only the {} built-in bindings",
        BUILT_IN_COUNT
    );
    assert!(
        state.extensions.is_empty(),
        "default build has empty extensions"
    );
    assert_eq!(state.cookie.access_ttl, chrono::TimeDelta::minutes(15));
    assert_eq!(state.cookie.refresh_ttl, chrono::TimeDelta::days(30));
}

// ─── 2. builder_with_resource_types_bootstraps ──────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_with_resource_types_bootstraps(pool: PgPool) {
    let course = ResourceType::workspace("course", &["read", "write"]);
    let state = builder(pool)
        .with_resource_types(&[course])
        .build()
        .await
        .expect("build must succeed");

    let exists: bool =
        sqlx::query_scalar("select exists(select 1 from resource_types where name = 'course')")
            .fetch_one(state.saas.pool())
            .await
            .expect("query resource_types");
    assert!(exists, "bootstrap must register `course`");

    let perm_exists: bool = sqlx::query_scalar(
        "select exists(select 1 from permissions \
         where resource = 'course' and action = 'read')",
    )
    .fetch_one(state.saas.pool())
    .await
    .expect("query permissions");
    assert!(perm_exists, "bootstrap must add `(course, read)`");
}

// ─── 3. builder_with_binding_stores_verbatim ────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_with_binding_stores_verbatim(pool: PgPool) {
    let path = "/tenants/{tenant_id}/roles";
    let state = builder(pool)
        .with_binding(RouteBinding::read(
            Method::GET,
            path,
            BindingScope::TenantFromPath("tenant_id"),
            "role",
            "list",
        ))
        .build()
        .await
        .expect("build must succeed");

    assert_eq!(
        state.bindings.iter().count(),
        BUILT_IN_COUNT + 1,
        "built-ins + one user binding"
    );
    let b = state
        .bindings
        .iter()
        .find(|b| b.path == path)
        .expect("user binding must be present");
    assert_eq!(b.resource_type, "role");
    assert_eq!(b.action, "list");
    assert!(!b.require_active);
}

// ─── 4. builder_auth_only_binding_stored ────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_auth_only_binding_stored(pool: PgPool) {
    let state = builder(pool)
        .with_binding(RouteBinding::auth_only(Method::GET, "/whoami"))
        .build()
        .await
        .expect("build must succeed");

    let b = state
        .bindings
        .iter()
        .find(|b| b.path == "/whoami")
        .expect("user binding must be present");
    assert!(matches!(b.scope, BindingScope::AuthenticatedOnly));
    assert_eq!(b.resource_type, "");
    assert_eq!(b.action, "");
    assert!(!b.require_active);
}

// ─── 5. build_app_smoke ─────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_smoke(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app(Arc::new(state));

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
    assert_eq!(body_json(resp).await, serde_json::json!({ "status": "ok" }));
}

// ─── 6. build_app_unknown_path_404 ──────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_unknown_path_404(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app(Arc::new(state));

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "not found" })
    );
}

// ─── 7. without_rbac_access_is_none ─────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn without_rbac_access_is_none(pool: PgPool) {
    let state = builder(pool)
        .without_rbac()
        .build()
        .await
        .expect("without_rbac build must succeed");

    assert!(
        state.access.is_none(),
        "access must be None on without_rbac"
    );
    assert!(
        state.saas.access().is_err(),
        "saas::access() must return Err on without_rbac"
    );

    let exists: bool =
        sqlx::query_scalar("select exists(select 1 from resource_types where name = $1)")
            .bind(unique_name("never_bootstrapped"))
            .fetch_one(state.saas.pool())
            .await
            .expect("query resource_types");
    assert!(!exists, "without_rbac skips bootstrap; nothing inserted");
}

// ─── 8. prometheus_optional ─────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn prometheus_optional(pool: PgPool) {
    let state_no = builder(pool.clone())
        .build()
        .await
        .expect("build must succeed");
    let router_no = build_app(Arc::new(state_no));
    let resp = router_no
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "`/metrics` must be 404 without with_prometheus"
    );

    static MARKER_COUNT: AtomicUsize = AtomicUsize::new(0);
    let tag = format!(
        "saas_axum_test_marker_{}",
        MARKER_COUNT.fetch_add(1, Ordering::SeqCst)
    );

    let state_yes = builder(pool)
        .with_prometheus(prometheus_handle())
        .build()
        .await
        .expect("build must succeed");
    let router_yes = build_app(Arc::new(state_yes));

    metrics::counter!(tag.clone()).increment(1);

    let resp = router_yes
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(header::ACCEPT, "text/plain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = String::from_utf8_lossy(
        &resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes(),
    )
    .into_owned();
    assert!(
        body.contains(&tag),
        "`/metrics` body must contain the `{tag}` counter (found: {} bytes)",
        body.len()
    );
}

// ─── 9. A4.3a fail-fast: unknown resource_type ─────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_rejects_unknown_binding_resource_type(pool: PgPool) {
    let err = match builder(pool)
        .with_binding(RouteBinding::read(
            Method::GET,
            "/x",
            BindingScope::Platform,
            "nope", // ← not in resource_types
            "read",
        ))
        .build()
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("build must fail on unknown resource_type"),
    };

    let msg = format!("{err}");
    assert!(msg.contains("unknown resource_type `nope`"), "got: {msg}");
}

// ─── 10. A4.3a fail-fast: unknown action ────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_rejects_unknown_binding_action(pool: PgPool) {
    let err = match builder(pool)
        .with_binding(RouteBinding::read(
            Method::GET,
            "/x",
            BindingScope::Platform,
            "role", // ← in resource_types
            "nope", // ← not in permissions
        ))
        .build()
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("build must fail on unknown action"),
    };

    let msg = format!("{err}");
    assert!(msg.contains("unknown permission `role:nope`"), "got: {msg}");
}

// ─── A4.3b: routing + middleware wiring (8 tests) ─────────────────────

async fn noop_handler() -> &'static str {
    "ok"
}

fn extract_csrf_cookie(resp: &Response) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|s| {
            let first = s.split(';').next()?;
            first.strip_prefix("csrf=").map(String::from)
        })
}

async fn bootstrap_csrf(router: &Router) -> String {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    extract_csrf_cookie(&resp).expect("csrf cookie must be set on fallback")
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_readyz_ok(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app(Arc::new(state));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["checks"]["db"], "ok");
    // Redis depends on env (`REDIS_URL`); accept both `not_configured`
    // (dev/CI without Redis) and `ok` (with `REDIS_URL`). Only `down`
    // would be a bug here.
    let redis = json["checks"]["redis"].as_str().unwrap_or("");
    assert!(
        redis == "not_configured" || redis == "ok",
        "redis must be ok/not_configured, got: {redis}"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_healthz_no_csrf_cookie(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app(Arc::new(state));
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
    assert!(
        extract_csrf_cookie(&resp).is_none(),
        "`/healthz` must not set a `csrf` cookie (csrf_issue skips probes)"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_fallback_sets_csrf_cookie(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app(Arc::new(state));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(
        extract_csrf_cookie(&resp).is_some(),
        "404 fallback must set a `csrf` cookie (csrf_issue bootstraps it)"
    );
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_with_protected_anonymous_no_csrf_403(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "csrf token mismatch");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_with_protected_anonymous_with_csrf_401(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let csrf = bootstrap_csrf(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x")
                .header("cookie", format!("csrf={csrf}"))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_with_protected_auth_ok_200(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let email = format!("u-{}@test.local", Uuid::new_v4());
    let user = state
        .authn
        .register(&email, "Password123!")
        .await
        .expect("register");
    let access = state.authn.issue_access_token(&user).expect("access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let csrf = bootstrap_csrf(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x")
                .header("cookie", format!("csrf={csrf}; access_token={access}"))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_with_protected_permission_denied_403(pool: PgPool) {
    let binding =
        RouteBinding::mutating(Method::POST, "/x", BindingScope::Platform, "tenant", "list");
    let state = builder(pool)
        .with_binding(binding)
        .build()
        .await
        .expect("build must succeed");

    let email = format!("u-{}@test.local", Uuid::new_v4());
    let user = state
        .authn
        .register(&email, "Password123!")
        .await
        .expect("register");
    let access = state.authn.issue_access_token(&user).expect("access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let csrf = bootstrap_csrf(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x")
                .header("cookie", format!("csrf={csrf}; access_token={access}"))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "forbidden");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_with_protected_tenant_member_ok_200(pool: PgPool) {
    let binding = RouteBinding::mutating(
        Method::POST,
        "/x/{tenant_id}",
        BindingScope::TenantFromPath("tenant_id"),
        "workspace",
        "create",
    );
    let state = builder(pool)
        .with_binding(binding)
        .build()
        .await
        .expect("build must succeed");

    // Platform admin (to provision a tenant)
    let admin_email = format!("admin-{}@test.local", Uuid::new_v4());
    let admin = state
        .authn
        .register(&admin_email, "Password123!")
        .await
        .expect("register admin");
    let owner_key = access::RoleKey::parse("owner").unwrap();
    let perms = access::get_permissions_for_role(
        state.saas.access().expect("access"),
        "platform",
        &owner_key,
    )
    .await
    .expect("platform perms");
    state
        .saas
        .authz()
        .grant_role(admin.id, "platform", "owner", &perms)
        .await
        .expect("grant platform owner");

    // Owner of a new tenant (becomes tenant owner via provision_tenant)
    let owner_email = format!("owner-{}@test.local", Uuid::new_v4());
    let owner = state
        .authn
        .register(&owner_email, "Password123!")
        .await
        .expect("register owner");
    let tenant = saas::platform::provision_tenant(
        &state.saas,
        &admin,
        "Acme".to_string(),
        &owner,
        &owner_key,
    )
    .await
    .expect("provision_tenant");

    let owner_access = state
        .authn
        .issue_access_token(&owner)
        .expect("owner access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x/{tenant_id}", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let csrf = bootstrap_csrf(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/x/{}", tenant.id))
                .header(
                    "cookie",
                    format!("csrf={csrf}; access_token={owner_access}"),
                )
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── A4.3a depth: suspended tenant + PathPermissions (6 tests) ────────

/// Grants `platform` owner to `admin`, provisions a tenant with `owner` as
/// its `owner`, then suspends it. Returns the tenant id.
async fn provision_suspended_tenant(
    state: &AxumAppState,
    admin: &domain::AuthUser,
    owner: &domain::AuthUser,
) -> Uuid {
    let owner_key = access::RoleKey::parse("owner").unwrap();
    let perms = access::get_permissions_for_role(
        state.saas.access().expect("access"),
        "platform",
        &owner_key,
    )
    .await
    .expect("platform perms");
    state
        .saas
        .authz()
        .grant_role(admin.id, "platform", "owner", &perms)
        .await
        .expect("grant platform owner");

    let tenant = saas::platform::provision_tenant(
        &state.saas,
        admin,
        format!("SuspAcme-{}", Uuid::new_v4()),
        owner,
        &owner_key,
    )
    .await
    .expect("provision_tenant");

    saas::platform::suspend_tenant(&state.saas, admin, tenant.id)
        .await
        .expect("suspend_tenant");

    tenant.id
}

/// Minimal `PathPermissions` impl used by the depth tests. Two paths:
/// `/public-custom` — `is_public = true`; `/protected-custom` —
/// `path_permission = (platform, tenant, manage)`. Everything else falls
/// through.
struct TestPathPerms;

impl PathPermissions for TestPathPerms {
    fn is_public(&self, _method: &Method, path: &str) -> bool {
        path == "/public-custom"
    }

    fn path_permission(&self, _method: &Method, path: &str) -> Option<OwnedAuthzTarget> {
        if path == "/protected-custom" {
            Some(OwnedAuthzTarget {
                domain: domain::PLATFORM_DOMAIN.to_string(),
                resource: "tenant".to_string(),
                action: "manage".to_string(),
            })
        } else {
            None
        }
    }
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn auth_layer_suspended_tenant_require_active_403(pool: PgPool) {
    let binding = RouteBinding::mutating(
        Method::POST,
        "/x/{tenant_id}",
        BindingScope::TenantFromPath("tenant_id"),
        "workspace",
        "create",
    );
    let state = builder(pool)
        .with_binding(binding)
        .build()
        .await
        .expect("build must succeed");

    let admin = state
        .authn
        .register(
            &format!("adm-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register admin");
    let owner = state
        .authn
        .register(
            &format!("own-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register owner");

    let tenant_id = provision_suspended_tenant(&state, &admin, &owner).await;
    let owner_access = state
        .authn
        .issue_access_token(&owner)
        .expect("owner access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x/{tenant_id}", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let csrf = bootstrap_csrf(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/x/{}", tenant_id))
                .header(
                    "cookie",
                    format!("csrf={csrf}; access_token={owner_access}"),
                )
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "tenant is suspended");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn auth_layer_suspended_tenant_read_only_200(pool: PgPool) {
    // Same as above but `read` (require_active=false): a suspended tenant
    // must remain readable (ADR-0002 rev.2 §2.4).
    let binding = RouteBinding::read(
        Method::GET,
        "/x/{tenant_id}",
        BindingScope::TenantFromPath("tenant_id"),
        "workspace",
        "create",
    );
    let state = builder(pool)
        .with_binding(binding)
        .build()
        .await
        .expect("build must succeed");

    let admin = state
        .authn
        .register(
            &format!("adm-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register admin");
    let owner = state
        .authn
        .register(
            &format!("own-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register owner");

    let tenant_id = provision_suspended_tenant(&state, &admin, &owner).await;
    let owner_access = state
        .authn
        .issue_access_token(&owner)
        .expect("owner access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x/{tenant_id}", axum::routing::get(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/x/{}", tenant_id))
                .header("cookie", format!("access_token={owner_access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn auth_layer_non_member_require_active_403(pool: PgPool) {
    let binding = RouteBinding::mutating(
        Method::POST,
        "/x/{tenant_id}",
        BindingScope::TenantFromPath("tenant_id"),
        "workspace",
        "create",
    );
    let state = builder(pool)
        .with_binding(binding)
        .build()
        .await
        .expect("build must succeed");

    let admin = state
        .authn
        .register(
            &format!("adm-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register admin");
    let owner = state
        .authn
        .register(
            &format!("own-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register owner");
    let outsider = state
        .authn
        .register(
            &format!("out-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register outsider");

    // Tenant stays active — outsider is rejected on membership alone.
    let owner_key = access::RoleKey::parse("owner").unwrap();
    let perms = access::get_permissions_for_role(
        state.saas.access().expect("access"),
        "platform",
        &owner_key,
    )
    .await
    .expect("platform perms");
    state
        .saas
        .authz()
        .grant_role(admin.id, "platform", "owner", &perms)
        .await
        .expect("grant platform owner");
    let tenant = saas::platform::provision_tenant(
        &state.saas,
        &admin,
        format!("ActiveAcme-{}", Uuid::new_v4()),
        &owner,
        &owner_key,
    )
    .await
    .expect("provision_tenant");

    let out_access = state
        .authn
        .issue_access_token(&outsider)
        .expect("outsider access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x/{tenant_id}", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let csrf = bootstrap_csrf(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/x/{}", tenant.id))
                .header("cookie", format!("csrf={csrf}; access_token={out_access}"))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "forbidden");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn path_permissions_is_public_passes_through(pool: PgPool) {
    let state = builder(pool)
        .with_path_permissions(Arc::new(TestPathPerms))
        .build()
        .await
        .expect("build must succeed");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/public-custom", axum::routing::get(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);

    // No auth cookie → normally 401; `is_public=true` bypasses auth_layer.
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/public-custom")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn path_permissions_path_permission_applied(pool: PgPool) {
    let state = builder(pool)
        .with_path_permissions(Arc::new(TestPathPerms))
        .build()
        .await
        .expect("build must succeed");

    // Authenticated user without `(tenant, manage)` in `platform`.
    let regular = state
        .authn
        .register(
            &format!("reg-{}@test.local", Uuid::new_v4()),
            "Password123!",
        )
        .await
        .expect("register regular");
    let access = state.authn.issue_access_token(&regular).expect("access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/protected-custom", axum::routing::get(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/protected-custom")
                .header("cookie", format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "forbidden");
}

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn auth_layer_invalid_uuid_param_400(pool: PgPool) {
    let binding = RouteBinding::mutating(
        Method::POST,
        "/x/{tenant_id}",
        BindingScope::TenantFromPath("tenant_id"),
        "workspace",
        "create",
    );
    let state = builder(pool)
        .with_binding(binding)
        .build()
        .await
        .expect("build must succeed");

    let user = state
        .authn
        .register(&format!("u-{}@test.local", Uuid::new_v4()), "Password123!")
        .await
        .expect("register");
    let access = state.authn.issue_access_token(&user).expect("access");

    let protected: Router<Arc<AxumAppState>> =
        Router::new().route("/x/{tenant_id}", axum::routing::post(noop_handler));
    let router = build_app_with_protected(Arc::new(state), protected);
    let csrf = bootstrap_csrf(&router).await;
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/x/not-a-uuid")
                .header("cookie", format!("csrf={csrf}; access_token={access}"))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error"], "invalid path parameter");
}

// ─── A4.4: `build_app_full` endpoints (9 tests) ────────────────────────
//
// The endpoints added in step 6 are now mounted by `build_app_full`
// (step 7). These tests pin:
// - the public/protected split (`/auth/{register,login,logout}` public;
//   `/auth/refresh`, `/my_permissions*`, `/resource_types` protected);
// - CSRF (mutations require the double-submit token);
// - auth cookies (`access_token`, `refresh_token`, `csrf`);
// - `/my_permissions` flat `Vec<String>` (`"document:read"`) + grouped
//   object — divergence from `saas-leptos` (`Vec<(String, String)>`)
//   is documented in `endpoints/my_permissions.rs`, tracked as Phase D §D9;
// - `/resource_types` DTO shape (`{ name, scope, default_actions }`);
// - `bootstrap_all_core` in `AxumAppStateBuilder::build()`.

// ─── Helpers (A4.4-only; existing tests have their own) ──

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

fn find_cookie<'a>(jar: &'a [(String, String)], name: &str) -> Option<&'a str> {
    jar.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

async fn register_authenticated(router: &Router, email: &str) -> (Vec<(String, String)>, Uuid) {
    let body = serde_json::json!({ "email": email, "password": "Password123!" }).to_string();
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
        .expect("user.id must be present")
        .parse()
        .expect("user.id must be UUID");
    (jar, uid)
}

async fn grant_platform_admin(state: &AxumAppState, user_id: Uuid) {
    let owner_key = access::RoleKey::parse("owner").expect("owner key");
    let perms = access::get_permissions_for_role(
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

// ─── 1. register sets auth cookies (public, rate-limited) ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn register_sets_auth_cookies(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app_full(Arc::new(state));
    let email = format!("reg-{}@test.local", Uuid::new_v4());

    let body = serde_json::json!({ "email": email, "password": "Password123!" }).to_string();
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

// ─── 2. refresh returns the current user (protected, CSRF-checked) ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn refresh_returns_current_user(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app_full(Arc::new(state));
    let email = format!("ref-{}@test.local", Uuid::new_v4());
    let (jar, _uid) = register_authenticated(&router, &email).await;

    let access = find_cookie(&jar, "access_token").expect("access_token");
    let csrf = find_cookie(&jar, "csrf").expect("csrf");
    let cookie_hdr = format!("csrf={csrf}; access_token={access}");

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header(header::COOKIE, &cookie_hdr)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["email"].as_str(), Some(email.as_str()));
}

// ─── 3. `/my_permissions` requires auth ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn my_permissions_requires_auth(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app_full(Arc::new(state));

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/my_permissions?domain=platform")
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

// ─── 4. flat list: `Vec<String>` (`"document:read"`), sorted ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn my_permissions_returns_flat_list_singular(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let state_arc = Arc::new(state);
    let router = build_app_full(state_arc.clone());
    let email = format!("pm-{}@test.local", Uuid::new_v4());
    let (jar, uid) = register_authenticated(&router, &email).await;
    grant_platform_admin(&state_arc, uid).await;

    let access = find_cookie(&jar, "access_token").expect("access_token");
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/my_permissions?domain=platform")
                .header(header::COOKIE, format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let arr = json.as_array().expect("must be an array");
    assert!(
        !arr.is_empty(),
        "platform owner must have a non-empty permission list"
    );

    for item in arr {
        let s = item.as_str().expect("items must be strings");
        assert!(
            s.contains(':'),
            "flat item must be `resource:action`, got {s:?}"
        );
    }

    let items: Vec<&str> = arr.iter().map(|v| v.as_str().unwrap()).collect();
    let mut sorted = items.clone();
    sorted.sort();
    assert_eq!(items, sorted, "flat list must be sorted lexicographically");
}

// ─── 5. grouped: JSON object `{ "resource": ["action", …] }` ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn my_permissions_grouped_returns_hashmap_singular(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let state_arc = Arc::new(state);
    let router = build_app_full(state_arc.clone());
    let email = format!("pmg-{}@test.local", Uuid::new_v4());
    let (jar, uid) = register_authenticated(&router, &email).await;
    grant_platform_admin(&state_arc, uid).await;

    let access = find_cookie(&jar, "access_token").expect("access_token");
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/my_permissions/grouped?domain=platform")
                .header(header::COOKIE, format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let obj = json.as_object().expect("must be an object");
    assert!(
        !obj.is_empty(),
        "platform owner must have a non-empty grouped map"
    );

    let audit = obj
        .get("audit")
        .expect("platform owner must hold `audit` permissions")
        .as_array()
        .expect("values must be arrays");
    assert!(
        audit.iter().any(|v| v.as_str() == Some("read")),
        "`audit` must contain `read`"
    );

    for (_, v) in obj {
        let arr = v.as_array().expect("values must be arrays");
        for item in arr {
            assert!(item.is_string(), "actions must be strings");
        }
    }
}

// ─── 6. invalid domain → 200 `[]` (documented; not a 4xx) ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn my_permissions_invalid_domain(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app_full(Arc::new(state));
    let email = format!("pmi-{}@test.local", Uuid::new_v4());
    let (jar, _uid) = register_authenticated(&router, &email).await;

    let access = find_cookie(&jar, "access_token").expect("access_token");
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/my_permissions?domain=garbage-format")
                .header(header::COOKIE, format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await, serde_json::json!([]));
}

// ─── 7. `/resource_types` requires auth ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn resource_types_requires_auth(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app_full(Arc::new(state));

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/resource_types")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── 8. `/resource_types`: list of `{ name, scope, default_actions }` ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn resource_types_returns_list_singular(pool: PgPool) {
    let state = builder(pool).build().await.expect("build must succeed");
    let router = build_app_full(Arc::new(state));
    let email = format!("rt-{}@test.local", Uuid::new_v4());
    let (jar, _uid) = register_authenticated(&router, &email).await;

    let access = find_cookie(&jar, "access_token").expect("access_token");
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/resource_types")
                .header(header::COOKIE, format!("access_token={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let arr = json.as_array().expect("must be an array");
    assert!(
        arr.len() >= 8,
        "must include at least the 8 core types, got {}",
        arr.len()
    );

    let names: Vec<&str> = arr
        .iter()
        .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
        .collect();
    for expected in ["tenant", "workspace", "document", "member", "role"] {
        assert!(
            names.contains(&expected),
            "missing core type {expected:?}; got {names:?}"
        );
    }

    for item in arr {
        assert!(
            item.get("scope").and_then(|v| v.as_str()).is_some(),
            "each item must have `scope: String`"
        );
        assert!(
            item.get("default_actions")
                .and_then(|v| v.as_array())
                .is_some(),
            "each item must have `default_actions: [String]`"
        );
    }
}

// ─── 9. `bootstrap_all_core` runs in `build()` ──

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn resource_types_available_immediately_after_startup(pool: PgPool) {
    // No HTTP request is served — this pins the builder contract:
    // `AxumAppStateBuilder::build()` calls `bootstrap_all_core`, so the 8
    // core types are already in the DB when the process starts listening.
    let state = builder(pool).build().await.expect("build must succeed");
    let count: i64 = sqlx::query_scalar("select count(*) from resource_types")
        .fetch_one(state.saas.pool())
        .await
        .expect("count query");
    assert_eq!(
        count, 8,
        "bootstrap_all_core must create the 8 core types during build()"
    );
}
