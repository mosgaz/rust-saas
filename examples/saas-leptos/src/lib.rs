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

// Leptos' `view!` macro expands to deeply nested generic types; the default
// rustc recursion limit (128) is insufficient once `pages/member.rs` grows
// (member list → per-member role list → per-role remove button). 256 is the
// value recommended by the rustc diagnostic; it does not affect runtime.
#![recursion_limit = "256"]

pub mod auth;
pub mod email;
pub mod layout;
pub mod pages;

#[cfg(feature = "ssr")]
pub mod error;
#[cfg(feature = "ssr")]
pub mod extract;
#[cfg(feature = "ssr")]
pub mod middleware;
#[cfg(feature = "ssr")]
pub mod rate_limit;
#[cfg(feature = "ssr")]
pub mod state;

use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, path};

/// Root component: provides the meta context, mounts the router, and wraps
/// every page in the global [`layout::Layout`].
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Router>
            <layout::Layout>
                <Routes fallback=|| "Not found">
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
                    <Route path=path!("/platform") view=pages::platform::PlatformPage />

                    <Route path=path!("/tenants") view=pages::tenant::TenantListPage />
                    <Route path=path!("/tenants/:tenant_id") view=pages::tenant::TenantPage />
                    <Route
                        path=path!("/tenants/:tenant_id/invitations")
                        view=pages::invitation::TenantInvitationListPage
                    />
                    <Route
                        path=path!("/tenants/:tenant_id/members")
                        view=pages::member::TenantMemberListPage
                    />
                    <Route
                        path=path!("/tenants/:tenant_id/roles")
                        view=pages::role::TenantRoleListPage
                    />
                    <Route
                        path=path!("/tenants/:tenant_id/roles/:role_id")
                        view=pages::role::TenantRoleFormPage
                    />

                    <Route path=path!("/workspaces") view=pages::workspace::WorkspaceListPage />
                    <Route
                        path=path!("/workspaces/:workspace_id")
                        view=pages::workspace::WorkspacePage
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/documents/:document_id")
                        view=pages::workspace::DocumentPage
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/invitations")
                        view=pages::invitation::WorkspaceInvitationListPage
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/members")
                        view=pages::member::WorkspaceMemberListPage
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/roles")
                        view=pages::role::WorkspaceRoleListPage
                    />
                    <Route
                        path=path!("/workspaces/:workspace_id/roles/:role_id")
                        view=pages::role::WorkspaceRoleFormPage
                    />

                    <Route
                        path=path!("/invitations/:token")
                        view=pages::invitation::InvitationAcceptPage
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