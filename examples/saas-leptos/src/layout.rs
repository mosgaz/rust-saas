//! Global layout: header with navigation and auth controls (Logout, Renew).
//!
//! Wraps every page rendered inside `<Router>`. Auth controls are shown only
//! when the user is logged in (`who_am_i` on mount, refreshed by `Renew`).
//!
//! The `Renew` button is a **demo** for the auto-refresh middleware.
//! The navigation uses `<A>` from `leptos_router` for active highlighting
//! and client-side navigation (no full page reload).

use leptos::callback::Callback;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use leptos_router::hooks::{use_location, use_navigate};

use crate::auth::{logout, refresh};
use crate::pages::invitation::who_am_i;

/// Wraps every page: renders the header and puts `children` inside `<main>`.
#[component]
pub fn Layout(children: Children) -> impl IntoView {
    let logged_in = RwSignal::new(None::<bool>);
    let status = RwSignal::new(None::<String>);
    let navigate = use_navigate();
    let location = use_location();

    Effect::new(move |_| {
        let _ = location.pathname.get();
        
        spawn_local(async move {
            match who_am_i().await {
                Ok(email) => logged_in.set(Some(email.is_some())),
                Err(_) => logged_in.set(Some(false)),
            }
        });
    });

    let on_logout = Callback::new({
        let navigate = navigate.clone();
        move |_: ()| {
            let navigate = navigate.clone();
            spawn_local(async move {
                let _ = logout().await;
                logged_in.set(Some(false));
                status.set(None);
                navigate("/login", Default::default());
            });
        }
    });

    let on_renew = Callback::new(move |_: ()| {
        spawn_local(async move {
            match refresh().await {
                Ok(u) => {
                    logged_in.set(Some(true));
                    status.set(Some(format!("Renewed as {}", u.email)));
                }
                Err(e) => status.set(Some(e.to_string())),
            }
        });
    });

    view! {
        <header class="border-b border-neutral-800 px-6 py-3 flex flex-wrap items-center gap-4">
            <A href="/" attr:class="font-semibold">"Rust SAAS"</A>
            <nav class="flex gap-3 text-sm text-neutral-400">
                // <A> automatically adds an `aria-current="page"` and active state
                <A href="/tenants" attr:class="hover:text-white">"Tenants"</A>
                <A href="/workspaces" attr:class="hover:text-white">"Workspaces"</A>
                <A href="/platform" attr:class="hover:text-white">"Platform"</A>
            </nav>
            <div class="ml-auto flex items-center gap-2">
                {move || match logged_in.get() {
                    None => view! { <span class="text-sm text-neutral-500">"…"</span> }.into_any(),
                    Some(false) => view! {
                        <a class="btn text-sm" href="/login">"Login"</a>
                        <a class="btn text-sm" href="/register">"Register"</a>
                    }.into_any(),
                    Some(true) => view! {
                        <button
                            class="btn text-sm"
                            on:click=move |_| on_renew.run(())
                        >
                            "Renew (demo)"
                        </button>
                        <button
                            class="btn text-sm"
                            on:click=move |_| on_logout.run(())
                        >
                            "Logout"
                        </button>
                    }.into_any(),
                }}
            </div>
            {move || status.get().map(|s| view! {
                <span class="text-xs text-neutral-400">{s}</span>
            })}
        </header>
        <main>{children()}</main>
    }
}