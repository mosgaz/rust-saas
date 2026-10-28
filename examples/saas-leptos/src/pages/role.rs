//! Tenant and workspace roles: list, create, delete.
//!
//! `RoleView` is a client-side mirror of `access::Role` (which is SSR-only
//! because `access` pulls `sqlx`). Conversion happens server-side only.
//!
//! `update_role` and a dedicated `RoleFormPage` are deferred to Stage 2.5;
//! MVP uses the inline create form in `RoleListPage` and `delete` per row.

use std::collections::HashSet;

use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── DTOs ───────────────────────────────────────────────────────────────────

/// Client-side view of a role.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoleView {
    pub id: Uuid,
    pub domain: String,
    pub key: String,
    pub name: String,
    pub description: String,
    pub protected: bool,
    pub immutable: bool,
    pub permissions: Vec<(String, String)>,
}

#[cfg(feature = "ssr")]
impl From<access::Role> for RoleView {
    fn from(r: access::Role) -> Self {
        RoleView {
            id: r.id,
            domain: r.domain,
            key: r.key.as_str().to_string(),
            name: r.name,
            description: r.description,
            protected: r.protected,
            immutable: r.immutable,
            permissions: r
                .permissions
                .into_iter()
                .map(|p| (p.resource, p.action))
                .collect(),
        }
    }
}

// ─── Server functions ───────────────────────────────────────────────────────

/// Lists roles in `domain`.
#[server]
pub async fn list_roles(domain: String) -> Result<Vec<RoleView>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    let roles = saas::access::list_roles(&state.saas, &user, &domain)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;
    Ok(roles.into_iter().map(RoleView::from).collect())
}

/// Returns the `(resource, action, description)` triples of the
/// `permissions` reference table.
#[server]
pub async fn list_permissions() -> Result<Vec<(String, String, String)>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let perms = saas::access::list_permissions(&state.saas)
        .await
        .map_err(crate::error::core_error_to_server_fn)?;
    Ok(perms
        .into_iter()
        .map(|p| (p.resource, p.action, p.description))
        .collect())
}

/// Creates a role. `permissions` are `"resource:action"` pairs.
#[server]
pub async fn create_role(
    domain: String,
    key: String,
    name: String,
    description: String,
    permissions: Vec<String>,
) -> Result<RoleView, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    let key = access::RoleKey::parse(key).map_err(crate::error::access_error_to_server_fn)?;
    let pairs = parse_permission_pairs(&permissions)?;

    let role = saas::access::create_role(
        &state.saas,
        &user,
        &domain,
        &key,
        name,
        description,
        &pairs,
    )
    .await
    .map_err(crate::error::core_error_to_server_fn)?;
    Ok(RoleView::from(role))
}

/// Deletes a role.
#[server]
pub async fn delete_role(role_id: Uuid) -> Result<(), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::access::delete_role(&state.saas, &user, role_id)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Returns the actor's effective permissions in `domain`.
#[server]
pub async fn my_permissions(domain: String) -> Result<Vec<(String, String)>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::access::my_permissions(&state.saas, &user, &domain)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

#[cfg(feature = "ssr")]
fn parse_permission_pairs(raw: &[String]) -> Result<Vec<(String, String)>, ServerFnError> {
    raw.iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            let s = s.trim();
            let (resource, action) = s
                .split_once(':')
                .ok_or_else(|| ServerFnError::new(format!("expected resource:action, got {s}")))?;
            if resource.is_empty() || action.is_empty() {
                return Err(ServerFnError::new(format!(
                    "empty resource or action in {s}"
                )));
            }
            Ok((resource.to_string(), action.to_string()))
        })
        .collect()
}

// ─── Shared panel ───────────────────────────────────────────────────────────

/// Inline roles panel. Lists roles in `domain`, offers a delete button per
/// non-protected role (if `(roles, delete)`), and an inline create form (if
/// `(roles, create)`).
#[component]
pub fn RoleListPage(domain: String) -> impl IntoView {
    let domain = StoredValue::new(domain);
    let roles = RwSignal::new(Vec::<RoleView>::new());
    let perms = RwSignal::new(HashSet::<(String, String)>::new());
    let error = RwSignal::new(None::<String>);
    let refresh = RwSignal::new(0u32);

    let new_key = RwSignal::new(String::new());
    let new_name = RwSignal::new(String::new());
    let new_description = RwSignal::new(String::new());
    let new_permissions = RwSignal::new(String::new());

    Effect::new(move |_| {
        let _ = refresh.get();
        let d = domain.get_value();
        spawn_local(async move {
            match list_roles(d.clone()).await {
                Ok(list) => {
                    roles.set(list);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            match my_permissions(d).await {
                Ok(p) => perms.set(p.into_iter().collect()),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    let can = move |resource: &'static str, action: &'static str| {
        perms.with(|p| p.contains(&(resource.to_string(), action.to_string())))
    };

    let submit_create = move |_| {
        let d = domain.get_value();
        let key = new_key.get().trim().to_string();
        let name = new_name.get();
        let description = new_description.get();
        let raw_perms = new_permissions.get();
        let perms_vec: Vec<String> = raw_perms
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if key.is_empty() || name.is_empty() {
            error.set(Some("key and name are required".into()));
            return;
        }
        spawn_local(async move {
            match create_role(d, key, name, description, perms_vec).await {
                Ok(_) => {
                    new_key.set(String::new());
                    new_name.set(String::new());
                    new_description.set(String::new());
                    new_permissions.set(String::new());
                    error.set(None);
                    refresh.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <div class="card mt-6">
            <h2 class="text-lg font-semibold">"Roles"</h2>
            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            <ul class="mt-4 divide-y divide-neutral-800">
                {move || {
                    let list = roles.get();
                    if list.is_empty() {
                        view! { <li class="py-2 text-neutral-500">"No roles."</li> }.into_any()
                    } else {
                        list.into_iter()
                            .map(|r| {
                                let id = r.id;
                                let key = r.key.clone();
                                let protected = r.protected;
                                let perms_str = r
                                    .permissions
                                    .iter()
                                    .map(|(res, act)| format!("{res}:{act}"))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                view! {
                                    <li class="py-3 flex items-start justify-between gap-4">
                                        <div>
                                            <p class="font-medium">
                                                {key.clone()}
                                                {if protected {
                                                    Some(view! {
                                                        <span class="ml-2 text-xs text-neutral-500">
                                                            "(protected)"
                                                        </span>
                                                    })
                                                } else {
                                                    None
                                                }}
                                            </p>
                                            <p class="text-sm text-neutral-400">
                                                {format!("{} — {}", r.name, r.description)}
                                            </p>
                                            <p class="text-xs text-neutral-500 mt-1">
                                                {format!("id: {id} · perms: [{perms_str}]")}
                                            </p>
                                        </div>
                                        {move || if !protected && can("roles", "delete") {
                                            Some(view! {
                                                <button
                                                    class="btn text-sm"
                                                    on:click=move |_| {
                                                        spawn_local(async move {
                                                            match delete_role(id).await {
                                                                Ok(()) => {
                                                                    error.set(None);
                                                                    refresh.update(|n| *n += 1);
                                                                }
                                                                Err(e) => error.set(Some(e.to_string())),
                                                            }
                                                        });
                                                    }
                                                >
                                                    "Delete"
                                                </button>
                                            })
                                        } else {
                                            None
                                        }}
                                    </li>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }
                }}
            </ul>

            {move || if can("roles", "create") {
                Some(view! {
                    <div class="mt-6 border-t border-neutral-800 pt-4">
                        <h3 class="text-sm font-semibold">"Create role"</h3>
                        <input class="input mt-2" placeholder="key (a-z0-9_)" bind:value=new_key />
                        <input class="input mt-2" placeholder="name" bind:value=new_name />
                        <input
                            class="input mt-2"
                            placeholder="description"
                            bind:value=new_description
                        />
                        <input
                            class="input mt-2"
                            placeholder="permissions, comma-separated (e.g. documents:read, documents:write)"
                            bind:value=new_permissions
                        />
                        <button class="btn mt-3" on:click=submit_create>"Create"</button>
                    </div>
                })
            } else {
                None
            }}
        </div>
    }
}

// ─── Route pages ────────────────────────────────────────────────────────────

#[derive(Params, PartialEq)]
struct TenantIdParams {
    tenant_id: Uuid,
}

/// `/tenants/:tenant_id/roles` — tenant roles.
#[component]
pub fn TenantRoleListPage() -> impl IntoView {
    let params = use_params::<TenantIdParams>();
    let tenant_id = move || params.with(|r| r.as_ref().ok().map(|p| p.tenant_id));

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/tenants">"← All tenants"</a>
            <h1 class="mt-2 text-2xl font-bold">"Tenant roles"</h1>
            {move || tenant_id().map(|id| {
                let domain = domain::tenant_domain(id);
                view! {
                    <div class="mt-2">
                        <a class="btn text-sm" href=format!("/tenants/{id}")>"Open tenant"</a>
                    </div>
                    <RoleListPage domain=domain />
                }
            })}
        </main>
    }
}

#[derive(Params, PartialEq)]
struct WorkspaceIdParams {
    workspace_id: Uuid,
}

/// `/workspaces/:workspace_id/roles` — workspace roles.
#[component]
pub fn WorkspaceRoleListPage() -> impl IntoView {
    let params = use_params::<WorkspaceIdParams>();
    let workspace_id = move || params.with(|r| r.as_ref().ok().map(|p| p.workspace_id));

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/workspaces">"← All workspaces"</a>
            <h1 class="mt-2 text-2xl font-bold">"Workspace roles"</h1>
            {move || workspace_id().map(|id| {
                let domain = domain::workspace_domain(id);
                view! {
                    <div class="mt-2">
                        <a class="btn text-sm" href=format!("/workspaces/{id}")>
                            "Open workspace"
                        </a>
                    </div>
                    <RoleListPage domain=domain />
                }
            })}
        </main>
    }
}