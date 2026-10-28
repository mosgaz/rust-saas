//! Platform administration page: a platform admin creates a tenant.
//!
//! The `#[server]` function keeps the name `create_tenant` for the Leptos
//! endpoint (URL/contract unchanged) but delegates to
//! `saas::platform::provision_tenant` with `actor == owner`. The UI scenario
//! "created → became owner" is preserved through an explicit call:
//! `create_tenant` (container-only) no longer grants `tenant_owner`, so the
//! server function passes the current user as the owner.

use domain::Tenant;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Creates a tenant and assigns the current user as its owner.
///
/// Delegates to `saas::platform::provision_tenant(&state.saas, &user, name, &user)`.
/// Errors are mapped to HTTP status codes by `crate::error::core_error_to_server_fn`.
#[server]
pub async fn create_tenant(name: String) -> Result<Tenant, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    let tenant = saas::platform::provision_tenant(&state.saas, &user, name, &user)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;

    Ok(tenant)
}

/// Platform administration page: create a tenant as its owner.
#[component]
pub fn PlatformPage() -> impl IntoView {
    let name = RwSignal::new(String::new());
    let tenant = RwSignal::new(None::<Tenant>);
    let error = RwSignal::new(None::<String>);

    let submit = move |_| {
        spawn_local(async move {
            match create_tenant(name.get()).await {
                Ok(t) => tenant.set(Some(t)),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <h1 class="text-2xl font-bold">"Platform administration"</h1>

            <div class="card mt-6">
                <input class="input" placeholder="Tenant name" bind:value=name />
                <button class="btn mt-4" on:click=submit>"Create tenant"</button>

                {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
                {move || tenant.get().map(|t| view! {
                    <p class="mt-4 text-green-400">
                        "Created tenant: " {t.name}
                    </p>
                })}
            </div>
        </main>
    }
}