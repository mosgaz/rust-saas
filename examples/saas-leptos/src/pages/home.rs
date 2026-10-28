//! Landing page: links to log in / register / platform and the user's lists
//! of tenants and workspaces. Also exposes a "jump to tenant" input.

use icons::leptos::{Building2, LogIn, LayoutList, UserPlus};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

/// Landing page (`/`).
#[component]
pub fn HomePage() -> impl IntoView {
    let tenant_id = RwSignal::new(String::new());
    let navigate = use_navigate();

    let open_tenant = {
        let navigate = navigate.clone();
        move |_| {
            let id = tenant_id.get();
            let id = id.trim();
            if !id.is_empty() {
                navigate(&format!("/tenants/{id}"), Default::default());
            }
        }
    };

    view! {
        <main class="mx-auto max-w-3xl p-8">
            <h1 class="text-3xl font-bold">"Multitenant MVP"</h1>
            <p class="mt-4 text-neutral-400">
                "Platform, tenants, workspaces and authorization."
            </p>

            <div class="mt-8 flex flex-wrap gap-4">
                <a class="btn inline-flex items-center gap-2" href="/login">
                    <LogIn class="w-4 h-4" />
                    "Login"
                </a>
                <a class="btn inline-flex items-center gap-2" href="/register">
                    <UserPlus class="w-4 h-4" />
                    "Register"
                </a>
                <a class="btn inline-flex items-center gap-2" href="/platform">
                    <Building2 class="w-4 h-4" />
                    "Platform"
                </a>
                <a class="btn inline-flex items-center gap-2" href="/tenants">
                    <LayoutList class="w-4 h-4" />
                    "My tenants"
                </a>
                <a class="btn inline-flex items-center gap-2" href="/workspaces">
                    <LayoutList class="w-4 h-4" />
                    "My workspaces"
                </a>
            </div>

            <div class="card mt-8">
                <p class="text-sm text-neutral-400">
                    "Open tenant by id (paste a tenant id from the seed output)"
                </p>
                <input class="input mt-2" placeholder="tenant_id" bind:value=tenant_id />
                <button class="btn mt-3" on:click=open_tenant>"Open tenant"</button>
            </div>
        </main>
    }
}