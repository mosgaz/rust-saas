//! Tenant and workspace roles: list, create, edit, delete.
//!
//! `RoleView` is a client-side mirror of `access::Role` (which is SSR-only
//! because `access` pulls `sqlx`). Conversion happens server-side only.
//!
//! Stage 3a: `RoleFormPage` edits `name`, `description`, and `permissions`.
//! `key` is read-only (ADR-0001: `roles.key` is immutable — renaming is
//! delete + create). `protected`/`immutable` roles are rejected client-side
//! (`navigate(back_url)` on direct entry) and server-side
//! (`AccessError::Protected`/`Immutable` → `CoreError::Forbidden` → 403).

use std::collections::{BTreeMap, HashSet};

use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params};
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

/// Returns a role by `role_id`, or `None` if not found.
///
/// Uses `access::get_role_by_id` (no `actor`, §5 p.5 helper): any
/// authenticated user who knows the `role_id` can read its metadata. The
/// mutation (`update_role`) performs `authz.require(actor, domain,
/// "roles", "manage")` server-side.
#[server]
pub async fn get_role(role_id: Uuid) -> Result<Option<RoleView>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let _user = crate::extract::CurrentUser::from_request().await?.require()?;
    let role = access::get_role_by_id(state.saas.access(), role_id)
        .await
        .map_err(crate::error::access_error_to_server_fn)?;
    Ok(role.map(RoleView::from))
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

/// Updates a role's `name`, `description`, and `permissions`. Never `key`
/// (ADR-0001: `roles.key` is immutable).
#[server]
pub async fn update_role(
    role_id: Uuid,
    name: String,
    description: String,
    permissions: Vec<String>,
) -> Result<RoleView, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    let pairs = parse_permission_pairs(&permissions)?;

    let role = saas::access::update_role(&state.saas, &user, role_id, name, description, &pairs)
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

// ─── Shared list panel ──────────────────────────────────────────────────────

/// Inline roles panel. Lists roles in `domain`, offers an Edit button per
/// non-protected/non-immutable role (if `(roles, manage)`), a Delete button
/// per non-protected role (if `(roles, delete)`), and an inline create form
/// (if `(roles, create)`).
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

    let edit_url_for = move |r: &RoleView| -> Option<String> {
        let d = domain.get_value();
        if let Some(tid) = d.strip_prefix("tenant:") {
            Some(format!("/tenants/{tid}/roles/{}", r.id))
        } else if let Some(wid) = d.strip_prefix("workspace:") {
            Some(format!("/workspaces/{wid}/roles/{}", r.id))
        } else {
            None
        }
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
                                let immutable = r.immutable;
                                let perms_str = r
                                    .permissions
                                    .iter()
                                    .map(|(res, act)| format!("{res}:{act}"))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                let edit_href = edit_url_for(&r);
                                let can_manage = perms.with(|p| {
                                    p.contains(&("roles".to_string(), "manage".to_string()))
                                });
                                let can_delete = perms.with(|p| {
                                    p.contains(&("roles".to_string(), "delete".to_string()))
                                });
                                let show_edit =
                                    !protected && !immutable && can_manage && edit_href.is_some();
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
                                                {if immutable && !protected {
                                                    Some(view! {
                                                        <span class="ml-2 text-xs text-neutral-500">
                                                            "(immutable)"
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
                                        <div class="flex gap-2">
                                            {if show_edit {
                                                let href = edit_href.unwrap();
                                                Some(view! {
                                                    <a class="btn text-sm" href=href>"Edit"</a>
                                                })
                                            } else {
                                                None
                                            }}
                                            {if !protected && can_delete {
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
                                        </div>
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

// ─── Shared form panel ──────────────────────────────────────────────────────

/// Inline role edit form for a `domain` and `role_id`.
///
/// State:
/// - `name` — required (UI validation; backend unchanged);
/// - `description` — free-form;
/// - `selected` — `HashSet<(resource, action)>`, initialised from the
///   loaded role; permissions present in the role but missing from the
///   reference (an anomaly, FK prevents writes) are silently dropped by the
///   checkbox rendering — they are not re-submitted.
///
/// Behaviour:
/// - Direct entry to a `protected` or `immutable` role: `navigate(back_url)`.
/// - Submit error (403/404/500): stay on the form, show banner.
/// - Submit success: `navigate(back_url)` (the list refetches on mount).
/// - `key` is displayed read-only (ADR-0001).
#[component]
pub fn RoleFormPage(domain: String, role_id: Uuid, back_url: String) -> impl IntoView {
    let _ = &domain;
    let domain = StoredValue::new(domain);
    let back_url = StoredValue::new(back_url);

    let role = RwSignal::new(None::<RoleView>);
    let reference = RwSignal::new(Vec::<(String, String, String)>::new());
    let error = RwSignal::new(None::<String>);
    let refresh = RwSignal::new(0u32);

    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let selected = RwSignal::new(HashSet::<(String, String)>::new());

    let navigate = use_navigate();
    let navigate_for_guard = navigate.clone();

    Effect::new(move |_| {
        let _ = refresh.get();
        let _ = domain.get_value();
        let back = back_url.get_value();
        let nav = navigate_for_guard.clone();
        spawn_local(async move {
            match get_role(role_id).await {
                Ok(Some(r)) => {
                    if r.protected || r.immutable {
                        nav(&back, Default::default());
                        return;
                    }
                    name.set(r.name.clone());
                    description.set(r.description.clone());
                    selected.set(r.permissions.iter().cloned().collect());
                    role.set(Some(r));
                    error.set(None);
                }
                Ok(None) => error.set(Some("role not found".into())),
                Err(e) => error.set(Some(e.to_string())),
            }
            match list_permissions().await {
                Ok(p) => reference.set(p),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    let submit = {
        let navigate = navigate.clone();
        move |_| {
            let name_v = name.get().trim().to_string();
            if name_v.is_empty() {
                error.set(Some("Name is required".into()));
                return;
            }
            let description_v = description.get();
            let perms: Vec<String> = selected
                .get()
                .into_iter()
                .map(|(r, a)| format!("{r}:{a}"))
                .collect();
            let back = back_url.get_value();
            let navigate = navigate.clone();
            spawn_local(async move {
                match update_role(role_id, name_v, description_v, perms).await {
                    Ok(_) => {
                        error.set(None);
                        navigate(&back, Default::default());
                    }
                    Err(e) => error.set(Some(e.to_string())),
                }
            });
        }
    };

    view! {
        <div class="card mt-6">
            <h2 class="text-lg font-semibold">"Edit role"</h2>
            <a class="text-sm text-neutral-400" href=move || back_url.get_value()>
                "← Back to roles"
            </a>

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            {move || role.get().map(|r| view! {
                <div class="mt-4">
                    <p class="text-sm text-neutral-400">
                        {format!("key: {} · id: {} · domain: {}", r.key, r.id, r.domain)}
                    </p>
                    <input class="input mt-2" placeholder="name" bind:value=name />
                    <input class="input mt-2" placeholder="description" bind:value=description />

                    <h3 class="mt-6 text-sm font-semibold">"Permissions"</h3>
                    {move || {
                        let current = selected.get();
                        let mut groups: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
                        for (r, a, d) in reference.get() {
                            groups.entry(r.clone()).or_default().push((r, a, d));
                        }
                        if groups.is_empty() {
                            view! {
                                <p class="mt-2 text-neutral-500">"No permissions reference loaded."</p>
                            }.into_any()
                        } else {
                            groups.into_iter().map(|(resource, items)| {
                                view! {
                                    <div class="mt-3">
                                        <h4 class="text-xs font-semibold text-neutral-400 uppercase tracking-wide">
                                            {resource.clone()}
                                        </h4>
                                        <div class="mt-2 space-y-1">
                                            {items.into_iter().map(|(r, a, d)| {
                                                let key = (r.clone(), a.clone());
                                                let checked = current.contains(&key);
                                                let r_for = r.clone();
                                                let a_for = a.clone();
                                                view! {
                                                    <label class="flex items-start gap-2 text-sm">
                                                        <input
                                                            type="checkbox"
                                                            prop:checked=checked
                                                            on:change=move |_| {
                                                                selected.update(|s| {
                                                                    let k = (r_for.clone(), a_for.clone());
                                                                    if s.contains(&k) { s.remove(&k); } else { s.insert(k); }
                                                                });
                                                            }
                                                        />
                                                        <span>
                                                            <span class="font-medium">{a.clone()}</span>
                                                            <span class="text-neutral-500 ml-2">{d.clone()}</span>
                                                        </span>
                                                    </label>
                                                }
                                            }).collect_view()}
                                        </div>
                                    </div>
                                }
                            }).collect_view().into_any()
                        }
                    }}
                </div>
            })}

            <button class="btn mt-4" on:click=submit>"Save"</button>
        </div>
    }
}

// ─── Route pages: role lists ────────────────────────────────────────────────

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

// ─── Route pages: role edit forms (Stage 3a) ────────────────────────────────

#[derive(Params, PartialEq)]
struct TenantRoleFormParams {
    tenant_id: Uuid,
    role_id: Uuid,
}

/// `/tenants/:tenant_id/roles/:role_id` — edit a tenant role.
#[component]
pub fn TenantRoleFormPage() -> impl IntoView {
    let params = use_params::<TenantRoleFormParams>();
    let ids = move || {
        params.with(|r| {
            r.as_ref()
                .ok()
                .map(|p| (p.tenant_id, p.role_id))
        })
    };

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/tenants">"← All tenants"</a>
            <h1 class="mt-2 text-2xl font-bold">"Edit tenant role"</h1>
            {move || match ids() {
                Some((tid, rid)) => {
                    let domain_str = domain::tenant_domain(tid);
                    let back_url = format!("/tenants/{tid}/roles");
                    view! {
                        <RoleFormPage domain=domain_str role_id=rid back_url=back_url />
                    }.into_any()
                }
                None => view! {
                    <div class="mt-4">
                        <p class="text-red-400">"Invalid tenant or role id."</p>
                        <a class="btn text-sm mt-2 inline-block" href="/tenants">"Back to tenants"</a>
                    </div>
                }.into_any(),
            }}
        </main>
    }
}

#[derive(Params, PartialEq)]
struct WorkspaceRoleFormParams {
    workspace_id: Uuid,
    role_id: Uuid,
}

/// `/workspaces/:workspace_id/roles/:role_id` — edit a workspace role.
#[component]
pub fn WorkspaceRoleFormPage() -> impl IntoView {
    let params = use_params::<WorkspaceRoleFormParams>();
    let ids = move || {
        params.with(|r| {
            r.as_ref()
                .ok()
                .map(|p| (p.workspace_id, p.role_id))
        })
    };

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/workspaces">"← All workspaces"</a>
            <h1 class="mt-2 text-2xl font-bold">"Edit workspace role"</h1>
            {move || match ids() {
                Some((wid, rid)) => {
                    let domain_str = domain::workspace_domain(wid);
                    let back_url = format!("/workspaces/{wid}/roles");
                    view! {
                        <RoleFormPage domain=domain_str role_id=rid back_url=back_url />
                    }.into_any()
                }
                None => view! {
                    <div class="mt-4">
                        <p class="text-red-400">"Invalid workspace or role id."</p>
                        <a class="btn text-sm mt-2 inline-block" href="/workspaces">"Back to workspaces"</a>
                    </div>
                }.into_any(),
            }}
        </main>
    }
}