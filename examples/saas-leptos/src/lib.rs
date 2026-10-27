pub mod auth;
pub mod pages;

#[cfg(feature = "ssr")]
pub mod state;

use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, path};

#[component]
pub fn App() -> impl IntoView {
    // Мета-контекст создаётся в App, как в официальном шаблоне leptos-rs/start-axum 0.8.
    // SSR рендерит shell → shell строит <head><MetaTags/></head><body><App/></body>;
    // App выполняется во время построения дерева и регистрирует контекст,
    // после чего MetaTags и Stylesheet могут инжектить теги на финальном этапе рендера.
    provide_meta_context();

    view! {
        <Stylesheet href="/pkg/site.css" />
        <Router>
            <Routes fallback=|| "Not found">
                <Route path=path!("/") view=pages::home::HomePage />
                <Route path=path!("/login") view=pages::auth::LoginPage />
                <Route path=path!("/register") view=pages::auth::RegisterPage />
                <Route path=path!("/platform") view=pages::platform::PlatformPage />
                <Route path=path!("/tenant/:tenant_id") view=pages::tenant::TenantPage />
                <Route path=path!("/workspace/:workspace_id") view=pages::workspace::WorkspacePage />
            </Routes>
        </Router>
    }
}

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
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(crate::App);
}