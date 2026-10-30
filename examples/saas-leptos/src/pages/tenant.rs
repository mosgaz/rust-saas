//! Tenant pages: the list of tenants the current user belongs to, and a
//! single-tenant page (create workspace, open invitations/members/roles).

use domain::Workspace;
use leptos::callback::Callback;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params};
use leptos_router::params::Params;
use uuid::Uuid;

use crate::pages::member::my_permissions;

// ─── Server functions ───────────────────────────────────────────────────────

/// Lists tenants the current user is a member of.
#[server]
pub async fn list_my_tenants() -> Result<Vec<domain::Tenant>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::tenant::list_memberships(&state.saas, &user)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Creates a workspace inside a tenant; the creator becomes `owner`.
#[server]
pub async fn create_workspace(tenant_id: Uuid, name: String) -> Result<Workspace, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    let owner_key =
        access::RoleKey::parse("owner").map_err(|e| ServerFnError::new(e.to_string()))?;

    saas::tenant::create_workspace(&state.saas, &user, tenant_id, name, &user, &owner_key)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

// ─── Tenant list (`/tenants`) ───────────────────────────────────────────────

/// `/tenants` — list of tenants the current user belongs to.
#[component]
pub fn TenantListPage() -> impl IntoView {
    let tenants = RwSignal::new(Vec::<domain::Tenant>::new());
    let error = RwSignal::new(None::<String>);

    Effect::new(move |_| {
        spawn_local(async move {
            match list_my_tenants().await {
                Ok(list) => tenants.set(list),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <h1 class="text-2xl font-bold">"My tenants"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                "Tenants you are a member of. To create a new tenant, use the platform page."
            </p>
            <a class="btn mt-4 inline-block" href="/platform">"Create tenant"</a>

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            <ul class="mt-8 divide-y divide-neutral-800">
                {move || {
                    let list = tenants.get();
                    if list.is_empty() {
                        view! {
                            <li class="py-2 text-neutral-500">"No tenants yet."</li>
                        }
                            .into_any()
                    } else {
                        list.into_iter()
                            .map(|t| {
                                let id = t.id;
                                view! {
                                    <li class="py-3 flex items-center justify-between gap-4">
                                        <div>
                                            <p class="font-medium">{t.name.clone()}</p>
                                            <p class="text-sm text-neutral-400">
                                                {format!("id: {id} · status: {:?}", t.status)}
                                            </p>
                                        </div>
                                        <div class="flex gap-2">
                                            <a
                                                class="btn text-sm"
                                                href=format!("/tenants/{id}")
                                            >
                                                "Open"
                                            </a>
                                            <a
                                                class="btn text-sm"
                                                href=format!("/tenants/{id}/invitations")
                                            >
                                                "Invitations"
                                            </a>
                                        </div>
                                    </li>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }
                }}
            </ul>
        </main>
    }
}

// ─── Single tenant (`/tenants/:tenant_id`) ──────────────────────────────────

#[derive(Params, PartialEq)]
struct TenantParams {
    tenant_id: Uuid,
}

/// `/tenants/:tenant_id` — single tenant page: create a workspace (only
/// when permitted), links to invitations/members/roles (only when
/// permitted).
#[component]
pub fn TenantPage() -> impl IntoView {
    let params = use_params::<TenantParams>();
    let tenant_id = move || params.with(|r| r.as_ref().ok().map(|p| p.tenant_id));

    let can_create_workspace = RwSignal::new(false);
    let can_members = RwSignal::new(false);
    let can_roles = RwSignal::new(false);
    let can_invitations = RwSignal::new(false);

    Effect::new(move |_| {
        let Some(id) = tenant_id() else { return };
        let domain = domain::tenant_domain(id);
        spawn_local(async move {
            match my_permissions(domain).await {
                Ok(perms) => {
                    let has = |r: &str, a: &str| {
                        perms.iter().any(|(pr, pa)| pr == r && pa == a)
                    };
                    can_create_workspace.set(has("workspaces", "create"));
                    can_members.set(has("members", "list"));
                    can_roles.set(has("roles", "list"));
                    can_invitations.set(has("invitations", "list"));
                }
                Err(_) => {
                    can_create_workspace.set(false);
                    can_members.set(false);
                    can_roles.set(false);
                    can_invitations.set(false);
                }
            }
        });
    });

    let name = RwSignal::new(String::new());
    let workspace = RwSignal::new(None::<Workspace>);
    let error = RwSignal::new(None::<String>);
    let navigate = use_navigate();

    let submit = Callback::new(move |_: ()| {
        let tid = tenant_id();
        let nav = navigate.clone();
        spawn_local(async move {
            let Some(tid) = tid else { return };
            match create_workspace(tid, name.get()).await {
                Ok(w) => {
                    workspace.set(Some(w.clone()));
                    error.set(None);
                    nav(&format!("/workspaces/{}", w.id), Default::default());
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/tenants">"← All tenants"</a>

            <h1 class="mt-2 text-2xl font-bold">"Tenant"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                {move || tenant_id()
                    .map(|id| format!("id: {id}"))
                    .unwrap_or_else(|| "invalid tenant id".into())}
            </p>

            <div class="mt-4 flex gap-2 flex-wrap">
                {move || {
                    let id = tenant_id()?;
                    let mut links = Vec::new();
                    if can_invitations.get() {
                        links.push(view! {
                            <a class="btn text-sm" href=format!("/tenants/{id}/invitations")>
                                "Invitations"
                            </a>
                        });
                    }
                    if can_members.get() {
                        links.push(view! {
                            <a class="btn text-sm" href=format!("/tenants/{id}/members")>
                                "Members"
                            </a>
                        });
                    }
                    if can_roles.get() {
                        links.push(view! {
                            <a class="btn text-sm" href=format!("/tenants/{id}/roles")>
                                "Roles"
                            </a>
                        });
                    }
                    Some(links)
                }}
            </div>

            {move || can_create_workspace.get().then(|| view! {
                <div class="card mt-6">
                    <h2 class="text-lg font-semibold">"Create workspace"</h2>
                    <input class="input mt-2" placeholder="Workspace name" bind:value=name />
                    <button class="btn mt-3" on:click=move |_| submit.run(())>
                        "Create workspace"
                    </button>

                    {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
                    {move || workspace.get().map(|w| view! {
                        <p class="mt-4 text-green-400">"Created workspace: " {w.name}</p>
                    })}
                </div>
            })}
        </main>
    }
}