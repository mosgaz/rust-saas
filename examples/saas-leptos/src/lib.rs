//! Reference Leptos SSR consumer of the `rust-saas` library.
//!
//! `App` provides a meta context, mounts the `Router`, and wraps all routes
//! in [`layout::Layout`] (header with navigation and auth controls).
//! `shell` builds the `<html><head>…</head><body>…</body></html>` skeleton
//! used by `leptos_routes_with_context` (the 4th argument, not `App`), as
//! required by `leptos_meta`. `hydrate` is the WASM entry point.
//!
//! Stage 3d adds two auth routes: `/forgot-password`
//! ([`pages::auth::ForgotPasswordPage`]) and `/reset-password/:token`
//! ([`pages::auth::ResetPasswordPage`]). Both are public — no `CurrentUser`
//! is required; the reset flow ends with a manual redirect to `/login`
//! (no auto-login).
//!
//! Stage 3f renames `PlatformPage` to `PlatformTenantListPage` (route
//! `/platform` stays) and adds `/platform/audit`
//! ([`pages::platform::PlatformAuditListPage`]) for the platform-admin
//! audit view.
//!
//! **Client route guards (this follow-up).** Every private route is
//! wrapped in [`guard::GuardRoute`] with a [`guard::RouteGuard`] policy
//! declared right here, next to the `<Route>`. `pages/*.rs` are not
//! touched: the policy lives in the router. Guards are **UX-only** —
//! `saas::*` and `saas::platform::*` still call `authz.require` /
//! `resolve_active_tenant` server-side. Public routes (`/`, `/login`,
//! `/register`, `/verify/:token`, `/forgot-password`,
//! `/reset-password/:token`, `/invitations/:token`) have no guard.
//!
//! A server-side per-route middleware (defense in depth) is deferred to
//! Stage 4 — see `handoff.md` §16 and Appendix B §2.49 / §IV.40.
//!
//! **Stage 3h:** `PermsCache` provided as context at the root `App`
//! component. Pages read `my_permissions` through the cache
//! (`PermsCache::get_or_fetch`) and invalidate it after mutations
//! (`assign_role`, `remove_role`, `change_role`, role CRUD). TTL 30s.

// Leptos' `view!` macro expands to deeply nested generic types; the default
// rustc recursion limit (128) is insufficient once `pages/member.rs` grows
// (member list → per-member role list → per-role remove button). 256 is the
// value recommended by the rustc diagnostic; it does not affect runtime.
#![recursion_limit = "256"]

pub mod auth;
pub mod email;
pub mod guard;
pub mod layout;
pub mod pages;
pub mod perms_cache;

#[cfg(feature = "ssr")]
pub mod cookie;
#[cfg(feature = "ssr")]
pub mod error;
#[cfg(feature = "ssr")]
pub mod extract;
#[cfg(feature = "ssr")]
pub mod middleware;
#[cfg(feature = "ssr")]
pub mod state;

use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, path};

use crate::guard::{GuardRoute, RouteGuard};
use crate::perms_cache::PermsCache;

/// Root component: provides the meta context, mounts the router, and wraps
/// every page in the global [`layout::Layout`].
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    // Stage 3h: client-side permissions cache, shared across all pages.
    // Pages call `use_context::<PermsCache>()` to read/invalidate.
    provide_context(PermsCache::new());

    view! {
        <Router>
            <layout::Layout>
                <Routes fallback=|| "Not found">
                    // ── Public routes (no guard) ───────────────────────────
                    <Route path=path!("/") view=pages::home::HomePage />
                    <Route path=path!("/login") view=pages::auth::LoginPage />
                    <Route path=path!("/register") view=pages::auth::RegisterPage />
                    <Route path=path!("/verify/:token") view=pages::auth::VerifyEmailPage />
                    <Route
                        path=path!("/forgot-password")
                        view=pages::auth::ForgotPasswordPage
                    />
                    <Route
                        path=path!("/reset-password/:token")
                        view=pages::auth::ResetPasswordPage
                    />
                    <Route
                        path=path!("/invitations/:token")
                        view=pages::invitation::InvitationAcceptPage
                    />

                    // ── Platform admin ─────────────────────────────────────
                    <Route
                        path=path!("/platform")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Platform {
                                    resource: "tenants",
                                    action: "list",
                                }
                            >
                                <pages::platform::PlatformTenantListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/platform/audit")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Platform {
                                    resource: "audit",
                                    action: "read",
                                }
                            >
                                <pages::platform::PlatformAuditListPage />
                            </GuardRoute>
                        }
                    />

                    // ── Tenants ────────────────────────────────────────────
                    <Route
                        path=path!("/tenants")
                        view=move || view! {
                            <GuardRoute guard=RouteGuard::Auth>
                                <pages::tenant::TenantListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/tenants/:tenant_id")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::TenantAny(vec![
                                    ("workspaces", "create"),
                                    ("members", "list"),
                                    ("roles", "list"),
                                    ("invitations", "list"),
                                ])
                            >
                                <pages::tenant::TenantPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/tenants/:tenant_id/invitations")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Tenant {
                                    resource: "invitations",
                                    action: "list",
                                }
                            >
                                <pages::invitation::TenantInvitationListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/tenants/:tenant_id/members")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Tenant {
                                    resource: "members",
                                    action: "list",
                                }
                            >
                                <pages::member::TenantMemberListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/tenants/:tenant_id/roles")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Tenant {
                                    resource: "roles",
                                    action: "list",
                                }
                            >
                                <pages::role::TenantRoleListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/tenants/:tenant_id/roles/:role_id")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Tenant {
                                    resource: "roles",
                                    action: "manage",
                                }
                            >
                                <pages::role::TenantRoleFormPage />
                            </GuardRoute>
                        }
                    />

                    // ── Workspaces ─────────────────────────────────────────
                    <Route
                        path=path!("/workspaces")
                        view=move || view! {
                            <GuardRoute guard=RouteGuard::Auth>
                                <pages::workspace::WorkspaceListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::WorkspaceAny(vec![
                                    ("documents", "read"),
                                    ("documents", "write"),
                                    ("members", "list"),
                                    ("roles", "list"),
                                    ("invitations", "list"),
                                ])
                            >
                                <pages::workspace::WorkspacePage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/documents/:document_id")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Workspace {
                                    resource: "documents",
                                    action: "read",
                                }
                            >
                                <pages::workspace::DocumentPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/invitations")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Workspace {
                                    resource: "invitations",
                                    action: "list",
                                }
                            >
                                <pages::invitation::WorkspaceInvitationListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/members")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Workspace {
                                    resource: "members",
                                    action: "list",
                                }
                            >
                                <pages::member::WorkspaceMemberListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/roles")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Workspace {
                                    resource: "roles",
                                    action: "list",
                                }
                            >
                                <pages::role::WorkspaceRoleListPage />
                            </GuardRoute>
                        }
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/roles/:role_id")
                        view=move || view! {
                            <GuardRoute
                                guard=RouteGuard::Workspace {
                                    resource: "roles",
                                    action: "manage",
                                }
                            >
                                <pages::role::WorkspaceRoleFormPage />
                            </GuardRoute>
                        }
                    />
                </Routes>
            </layout::Layout>
        </Router>
    }
}

/// HTML shell used by `leptos_routes_with_context` (4th argument).
#[cfg(feature = "ssr")]
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <AutoReload options=options.clone() />
                <HydrationScripts options />
                <MetaTags />
                <Stylesheet id="leptos" href="/pkg/rust-saas-leptos.css"/>
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

/// WASM entry point: hydrates the SSR-rendered `App`.
///
/// Compiled only for `target_arch = "wasm32"`: `console_error_panic_hook`
/// is a wasm32-only dependency (see `Cargo.toml`,
/// `[target.'cfg(target_arch = "wasm32")'.dependencies]`), so including
/// this function on the host (e.g. `cargo check --features hydrate`)
/// would fail with a missing-crate error. Host `cargo check --features
/// hydrate` now verifies the type-level API on the host; the actual wasm
/// build is `cargo leptos watch`.
#[cfg(all(feature = "hydrate", target_arch = "wasm32"))]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(crate::App);
}
// ─── Stage 4.7: `build_app` (moved out of `main.rs`) ─────────────────────
//
// Router assembly — public vs protected (ADR-0002 rev.2 §2.1) — lives here
// so `tests/e2e.rs` can drive it in-process via
// `tower::ServiceExt::oneshot`. `main.rs` stays a thin binary (env →
// `AppState` → `axum::serve(build_app(state))`).
//
// Layer order on the protected router (outermost first; note that
// `.route_layer` calls run in reverse of the order written):
// `same_origin_guard` → `auto_refresh` → handler.
//
// `healthz` is inlined (not a separate module) for the same reason as
// before: `axum` is optional and only enabled under `ssr`, so a top-level
// module would leak into the `hydrate` build.

#[cfg(feature = "ssr")]
async fn healthz() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "status": "ok" })),
    )
}

/// Builds the full `axum::Router` for `saas-leptos`.
///
/// Split (ADR-0002 rev.2 §2.1):
/// - **protected** — Leptos SSR routes + `/_server/*` behind
///   `same_origin_guard` (CSRF via `Origin`/`Host`) and `auto_refresh`
///   (JWT verify, refresh rotation).
/// - **public** — `/healthz` + `file_and_error_handler` (static assets,
///   404). No middleware: static assets must not pay for JWT verification.
///
/// `TraceLayer` covers the merged router.
/// `GET /readyz` — readiness probe (Stage 4.10).
///
/// `saas-leptos` не имеет прямой `redis`-зависимости (`rate-limiter`
/// инкапсулирует её); поэтому `redis` всегда `"not_configured"` —
/// reference consumer полагается на `InMemoryRateLimiter`.
/// `/readyz` здесь проверяет только БД. Полный deep-probe с PING
/// Redis — в `examples/axum-minimal/src/health.rs`.
#[cfg(feature = "ssr")]
async fn readyz(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> impl axum::response::IntoResponse {
    use axum::http::StatusCode;
    let db = match sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(state.saas.pool())
        .await
    {
        Ok(1) => "ok",
        _ => "down",
    };
    let ok = db == "ok";
    let status = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, axum::Json(serde_json::json!({
        "status": if ok { "ok" } else { "fail" },
        "checks": { "db": db, "redis": "not_configured" },
    })))
}

/// `GET /metrics` — Prometheus exposition format (Stage 4.10).
///
/// Public on purpose: Prometheus-scraper не имеет сессии; в теле —
/// только числовые counters/histograms (никакого PII).
#[cfg(feature = "ssr")]
async fn metrics(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> impl axum::response::IntoResponse {
    state.prometheus.render()
}

#[cfg(feature = "ssr")]
pub fn build_app(app_state: crate::state::AppState) -> axum::Router {
    use axum::middleware::from_fn;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use leptos::config::LeptosOptions;
    use leptos_axum::{file_and_error_handler, generate_route_list, LeptosRoutes};
    use tower_http::trace::TraceLayer;

    let authn = app_state.authn.clone();
    let cookie_cfg = app_state.cookie.clone();
    let leptos_options: LeptosOptions = app_state.leptos_options.clone();
    let routes = generate_route_list(crate::App);

    let protected: Router<crate::state::AppState> = Router::new()
        .leptos_routes_with_context(
            &app_state,
            routes,
            {
                let state = app_state.clone();
                move || leptos::prelude::provide_context(state.clone())
            },
            {
                let opts = leptos_options.clone();
                move || crate::shell(opts.clone())
            },
        )
        .route_layer(from_fn_with_state(
            (authn, cookie_cfg),
            crate::middleware::auto_refresh,
        ))
        // Stage 4.1c: reject cross-origin mutations on `/_server/*` and
        // SSR pages (Leptos `#[server]` has no per-call header hook).
        .route_layer(from_fn(crate::middleware::same_origin_guard));

    let public: Router<crate::state::AppState> = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .fallback(file_and_error_handler::<crate::state::AppState, _>(
            crate::shell,
        ));

    protected
        .merge(public)
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}
