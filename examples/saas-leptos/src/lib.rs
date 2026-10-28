//! Reference Leptos SSR consumer of the `rust-saas` library.
//!
//! `App` provides a meta context, mounts the `Router`, and wraps all routes
//! in [`layout::Layout`] (header with navigation and auth controls).
//! `shell` builds the `<html><head>…</head><body>…</body></html>` skeleton
//! used by `leptos_routes_with_context` (the 4th argument, not `App`), as
//! required by `leptos_meta`. `hydrate` is the WASM entry point.

pub mod auth;
pub mod layout;
pub mod pages;

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
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(crate::App);
}