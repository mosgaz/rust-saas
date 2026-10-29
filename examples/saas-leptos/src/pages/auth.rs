//! Login and registration pages.
//!
//! Stage 3a: after a successful `login` / `register`, the page consumes the
//! `return_url` cookie (set by `pages::invitation::InvitationAcceptPage` for
//! anonymous visitors) via `crate::auth::take_return_url` and navigates
//! there. If the cookie is absent or unsafe (open-redirect attempts), the
//! page falls back to `/`.

use crate::auth::{login, register, take_return_url};
use domain::AuthUser;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

#[component]
pub fn LoginPage() -> impl IntoView {
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let user = RwSignal::new(None::<AuthUser>);
    let error = RwSignal::new(None::<String>);
    let navigate = use_navigate();

    let submit = {
        let navigate = navigate.clone();
        move |_| {
            let navigate = navigate.clone();
            spawn_local(async move {
                match login(email.get(), password.get()).await {
                    Ok(u) => {
                        user.set(Some(u));
                        let back = take_return_url().await.ok().flatten();
                        let target = back.unwrap_or_else(|| "/".to_string());
                        navigate(&target, Default::default());
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            });
        }
    };

    view! {
        <main class="mx-auto max-w-sm p-8">
            <h1 class="text-2xl font-bold">"Login"</h1>

            <div class="mt-6 space-y-4">
                <input class="input" placeholder="Email" bind:value=email />
                <input class="input" type="password" placeholder="Password" bind:value=password />
                <button class="btn" on:click=submit>"Sign in"</button>

                {move || error.get().map(|e| view! { <p class="text-red-400">{e}</p> })}
                {move || user.get().map(|u| view! { <p class="text-green-400">{u.email}</p> })}
            </div>
        </main>
    }
}

#[component]
pub fn RegisterPage() -> impl IntoView {
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let user = RwSignal::new(None::<AuthUser>);
    let error = RwSignal::new(None::<String>);
    let navigate = use_navigate();

    let submit = {
        let navigate = navigate.clone();
        move |_| {
            let navigate = navigate.clone();
            spawn_local(async move {
                match register(email.get(), password.get()).await {
                    Ok(u) => {
                        user.set(Some(u));
                        let back = take_return_url().await.ok().flatten();
                        let target = back.unwrap_or_else(|| "/".to_string());
                        navigate(&target, Default::default());
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            });
        }
    };

    view! {
        <main class="mx-auto max-w-sm p-8">
            <h1 class="text-2xl font-bold">"Register"</h1>

            <div class="mt-6 space-y-4">
                <input class="input" placeholder="Email" bind:value=email />
                <input class="input" type="password" placeholder="Password" bind:value=password />
                <button class="btn" on:click=submit>"Create account"</button>

                {move || error.get().map(|e| view! { <p class="text-red-400">{e}</p> })}
                {move || user.get().map(|u| view! { <p class="text-green-400">{u.email}</p> })}
            </div>
        </main>
    }
}