use domain::Tenant;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[server]
pub async fn create_tenant(name: String) -> Result<Tenant, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    let tenant = saas::platform::create_tenant(&state.saas, &user, name)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;

    Ok(tenant)
}

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