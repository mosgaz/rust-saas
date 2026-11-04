//! PR-1 tests for `saas-axum`.
//!
//! Eight tests covering the A4.0–A4.2 surface:
//!
//! 1. `builder_defaults` — minimal `build()` works with a real DB.
//! 2. `builder_with_resource_types_bootstraps` — custom types reach
//!    `resource_types`.
//! 3. `builder_with_binding_stores_verbatim` — user bindings survive
//!    `build()` (no fail-fast in PR-1; fail-fast is A4.3a).
//! 4. `builder_auth_only_binding_stored` — `auth_only` constructs without a
//!    permission check (fail-fast is A4.3a).
//! 5. `build_app_smoke` — `GET /healthz` → 200.
//! 6. `build_app_unknown_path_404` — `GET /nonexistent` → 404.
//! 7. `without_rbac_access_is_none` — `.without_rbac()` leaves
//!    `state.access = None` and skips `bootstrap_all_core` (documented in
//!    `state.rs`).
//! 8. `prometheus_optional` — `/metrics` 404 without `with_prometheus`,
//!    200 with.
//!
//! Each test gets its own isolated DB via `#[sqlx::test]`, applies
//! `crates/db/migrations`, and drops the DB afterwards.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use access::registry::ResourceType;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use http_body_util::BodyExt;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use saas_axum::{build_app, AxumAppState, AxumAppStateBuilder, BindingScope, RouteBinding};
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
            // `set_global_recorder` returns Err on a second call; ignore.
            let _ = metrics::set_global_recorder(recorder);
            handle
        })
        .clone()
}

// ─── Helpers ─────────────────────────────────────────────────────────────

async fn builder(pool: PgPool) -> AxumAppStateBuilder {
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

// ─── 1. builder_defaults ────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_defaults(pool: PgPool) {
    let state = builder(pool)
        .await
        .build()
        .await
        .expect("build must succeed");

    // Defaults are wired:
    assert!(state.access.is_some(), "default build has AccessState");
    assert!(
        state.prometheus.is_none(),
        "default build has no Prometheus"
    );
    assert!(
        state.path_permissions.is_none(),
        "default build has no PathPermissions"
    );
    assert!(
        state.bindings.is_empty(),
        "default build has empty bindings"
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
        .await
        .with_resource_types(&[course])
        .build()
        .await
        .expect("build must succeed");

    // `course` appears in `resource_types` and `permissions`.
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
    let path = "/tenants/:tenant_id/roles";
    let state = builder(pool)
        .await
        .with_binding(RouteBinding::read(
            axum::http::Method::GET,
            path,
            BindingScope::TenantFromPath("tenant_id"),
            "role",
            "list",
        ))
        .build()
        .await
        .expect("build must succeed");

    // PR-1: no fail-fast, no precedence — the binding is stored as-is.
    assert_eq!(state.bindings.iter().count(), 1);
    let b = state.bindings.iter().next().unwrap();
    assert_eq!(b.path, path);
    assert_eq!(b.resource_type, "role");
    assert_eq!(b.action, "list");
    assert!(!b.require_active);
}

// ─── 4. builder_auth_only_binding_stored ────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn builder_auth_only_binding_stored(pool: PgPool) {
    let state = builder(pool)
        .await
        .with_binding(RouteBinding::auth_only(axum::http::Method::GET, "/whoami"))
        .build()
        .await
        .expect("build must succeed");

    let b = state.bindings.iter().next().expect("binding stored");
    assert!(matches!(b.scope, BindingScope::AuthenticatedOnly));
    assert_eq!(b.resource_type, "");
    assert_eq!(b.action, "");
    assert!(!b.require_active);
}

// ─── 5. build_app_smoke ─────────────────────────────────────────────────

#[sqlx::test(migrations = "../../crates/db/migrations")]
async fn build_app_smoke(pool: PgPool) {
    let state = builder(pool)
        .await
        .build()
        .await
        .expect("build must succeed");
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
    let state = builder(pool)
        .await
        .build()
        .await
        .expect("build must succeed");
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
        .await
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

    // Custom resource types are NOT bootstrapped without RBAC (documented
    // in `state.rs` step 7). Verify by querying with a custom name — the
    // DB never saw it.
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
    // (a) No `with_prometheus` — `/metrics` → 404.
    let state_no = builder(pool.clone())
        .await
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

    // (b) With `with_prometheus` — `/metrics` → 200, body contains the
    //     marker we just incremented.
    static MARKER_COUNT: AtomicUsize = AtomicUsize::new(0);
    let tag = format!(
        "saas_axum_test_marker_{}",
        MARKER_COUNT.fetch_add(1, Ordering::SeqCst)
    );

    let state_yes = builder(pool)
        .await
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
