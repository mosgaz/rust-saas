use domain::Workspace;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;
use uuid::Uuid;

#[derive(Params, PartialEq)]
struct TenantParams {
    tenant_id: Uuid,
}

#[server]
pub async fn create_workspace(tenant_id: Uuid, name: String) -> Result<Workspace, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = crate::auth::current_user()
        .await?
        .ok_or_else(|| ServerFnError::new("unauthorized"))?;

    // Не доверяем tenant_id из параметра как источнику авторизации (§14.1):
    // передаём его в Casbin, который разрешит только tenant_owner'у этого tenant.
    let domain_str = domain::tenant_domain(tenant_id);

    state
        .authz
        .require(user.id, &domain_str, "workspaces", "create")
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let workspace = sqlx::query_as::<_, Workspace>(
        r#"
        insert into workspaces (tenant_id, name)
        values ($1, $2)
        returning id, tenant_id, name, created_at
        "#,
    )
    .bind(tenant_id)
    .bind(name)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(workspace)
}

#[component]
pub fn TenantPage() -> impl IntoView {
    let params = use_params::<TenantParams>();
    let tenant_id = move || params.with(|r| r.as_ref().ok().map(|p| p.tenant_id));

    let name = RwSignal::new(String::new());
    let workspace = RwSignal::new(None::<Workspace>);
    let error = RwSignal::new(None::<String>);

    let submit = move |_| {
        let tenant_id = tenant_id();
        spawn_local(async move {
            let Some(tenant_id) = tenant_id else {
                return;
            };
            match create_workspace(tenant_id, name.get()).await {
                Ok(w) => workspace.set(Some(w)),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <h1 class="text-2xl font-bold">"Tenant"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                {move || tenant_id()
                    .map(|id| format!("id: {id}"))
                    .unwrap_or_else(|| "invalid tenant id".into())}
            </p>

            <div class="card mt-6">
                <input class="input" placeholder="Workspace name" bind:value=name />
                <button class="btn mt-4" on:click=submit>"Create workspace"</button>

                {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
                {move || workspace.get().map(|w| view! {
                    <p class="mt-4 text-green-400">"Created workspace: " {w.name.clone()}</p>
                    <a class="btn mt-2 inline-block" href=format!("/workspace/{}", w.id)>
                        "Open workspace"
                    </a>
                })}
            </div>
        </main>
    }
}