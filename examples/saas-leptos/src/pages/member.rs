//! Tenant and workspace member management: list members, assign or remove
//! roles.
//!
//! Server functions delegate to `saas::member::*` and
//! `saas::access::{assign_role, my_permissions}`; errors go through
//! `crate::error::core_error_to_server_fn`.
//!
//! Stage 3a: `MemberListPage` uses `<select>` for user (all current members,
//! including the actor) and role (all roles from `list_roles`), replacing the
//! former free-text inputs. "Invite instead" links to `scope_url`, the
//! invitations page for the same tenant or workspace.
//!
//! Role key is passed to the server as a raw string and parsed into
//! `access::RoleKey` server-side; the client never sees `access` types
//! (`access` is SSR-only).

use std::collections::HashSet;

use domain::Member;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params;
use leptos_router::params::Params;
use uuid::Uuid;

use crate::pages::role::{list_roles, RoleView};

#[cfg(feature = "ssr")]
use access::RoleKey;

// ─── Server functions ───────────────────────────────────────────────────────

/// Lists members of the domain identified by `domain`
/// (`tenant:{uuid}` or `workspace:{uuid}`).
#[server]
pub async fn list_members(domain: String) -> Result<Vec<Member>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    let scope = parse_scope(&domain)?;
    saas::member::list(&state.saas, &user, scope)
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

/// Assigns `role_key` to `user_id` in `domain` (`(members, manage)` required
/// via `saas::access::assign_role`).
#[server]
pub async fn assign_member_role(
    domain: String,
    user_id: Uuid,
    role_key: String,
) -> Result<(), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    let key = RoleKey::parse(role_key).map_err(crate::error::access_error_to_server_fn)?;
    saas::access::assign_role(&state.saas, &user, user_id, &domain, &key)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Removes `role_key` from `user_id` in `domain` (`(members, manage)` required
/// via `saas::member::remove_role`).
#[server]
pub async fn remove_member_role(
    domain: String,
    user_id: Uuid,
    role_key: String,
) -> Result<(), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    let key = RoleKey::parse(role_key).map_err(crate::error::access_error_to_server_fn)?;
    let scope = parse_scope(&domain)?;
    saas::member::remove_role(&state.saas, &user, scope, user_id, &key)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

#[cfg(feature = "ssr")]
fn parse_scope(domain: &str) -> Result<saas::member::MemberScope, ServerFnError> {
    if let Some(id) = domain.strip_prefix("tenant:") {
        Uuid::parse_str(id)
            .map(saas::member::MemberScope::Tenant)
            .map_err(|e| ServerFnError::new(e.to_string()))
    } else if let Some(id) = domain.strip_prefix("workspace:") {
        Uuid::parse_str(id)
            .map(saas::member::MemberScope::Workspace)
            .map_err(|e| ServerFnError::new(e.to_string()))
    } else {
        Err(ServerFnError::new(format!("invalid domain: {domain}")))
    }
}

// ─── Shared panel ───────────────────────────────────────────────────────────

/// Inline member panel for a domain. Renders the member list and, when the
/// actor has `(members, manage)`, per-role remove buttons, a role- and
/// member-select "Assign role" form, and an "Invite instead" link to
/// `scope_url`.
///
/// `scope_url` is the invitations page for the same tenant or workspace
/// (e.g. `/tenants/{id}/invitations`). Explicit parameter so the panel does
/// not have to re-derive the URL from `domain`.
#[component]
pub fn MemberListPage(domain: String, scope_url: String) -> impl IntoView {
    let domain = StoredValue::new(domain);
    let scope_url = StoredValue::new(scope_url);
    let members = RwSignal::new(Vec::<Member>::new());
    let roles = RwSignal::new(Vec::<RoleView>::new());
    let perms = RwSignal::new(HashSet::<(String, String)>::new());
    let error = RwSignal::new(None::<String>);
    let refresh = RwSignal::new(0u32);

    let new_user = RwSignal::new(String::new());
    let new_role = RwSignal::new(String::new());

    Effect::new(move |_| {
        let _ = refresh.get();
        let d = domain.get_value();
        spawn_local(async move {
            match list_members(d.clone()).await {
                Ok(list) => {
                    members.set(list);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            match my_permissions(d.clone()).await {
                Ok(p) => perms.set(p.into_iter().collect()),
                Err(e) => error.set(Some(e.to_string())),
            }
            match list_roles(d).await {
                Ok(rs) => {
                    if new_role.get_untracked().is_empty() {
                        if let Some(first) = rs.first() {
                            new_role.set(first.key.clone());
                        }
                    }
                    roles.set(rs);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    let can_manage = move || {
        perms.with(|p| p.contains(&("members".to_string(), "manage".to_string())))
    };

    let submit_assign = move |_| {
        let d = domain.get_value();
        let uid = new_user.get();
        let role = new_role.get();
        if uid.is_empty() || role.is_empty() {
            error.set(Some("select a member and a role".into()));
            return;
        }
        let uid = match Uuid::parse_str(&uid) {
            Ok(u) => u,
            Err(_) => {
                error.set(Some("invalid user id".into()));
                return;
            }
        };
        spawn_local(async move {
            match assign_member_role(d, uid, role).await {
                Ok(()) => {
                    new_user.set(String::new());
                    error.set(None);
                    refresh.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <div class="card mt-6">
            <h2 class="text-lg font-semibold">"Members"</h2>
            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            <ul class="mt-4 divide-y divide-neutral-800">
                {move || {
                    let list = members.get();
                    if list.is_empty() {
                        view! { <li class="py-2 text-neutral-500">"No members."</li> }.into_any()
                    } else {
                        let d = domain.get_value();
                        list.into_iter()
                            .map(|m| {
                                let uid = m.user_id;
                                let email = m.email.clone();
                                let roles = m.roles.clone();
                                let d = d.clone();
                                view! {
                                    <li class="py-3">
                                        <p class="font-medium">{email}</p>
                                        <p class="text-sm text-neutral-400">
                                            {format!("id: {uid}")}
                                        </p>
                                        <div class="mt-2 flex flex-wrap gap-2">
                                            {roles
                                                .into_iter()
                                                .map(|r| {
                                                    let d = d.clone();
                                                    let role_label = r.clone();
                                                    let role_for_remove = r.clone();
                                                    view! {
                                                        <span class="inline-flex items-center gap-1 px-2 py-1 rounded bg-neutral-800 text-sm">
                                                            {role_label}
                                                            {move || if can_manage() {
                                                                let d = d.clone();
                                                                let role = role_for_remove.clone();
                                                                Some(view! {
                                                                    <button
                                                                        class="ml-1 text-red-400"
                                                                        on:click=move |_| {
                                                                            let d = d.clone();
                                                                            let role = role.clone();
                                                                            spawn_local(async move {
                                                                                match remove_member_role(d, uid, role).await {
                                                                                    Ok(()) => {
                                                                                        error.set(None);
                                                                                        refresh.update(|n| *n += 1);
                                                                                    }
                                                                                    Err(e) => error.set(Some(e.to_string())),
                                                                                }
                                                                            });
                                                                        }
                                                                    >
                                                                        "×"
                                                                    </button>
                                                                })
                                                            } else {
                                                                None
                                                            }}
                                                        </span>
                                                    }
                                                })
                                                .collect_view()}
                                        </div>
                                    </li>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }
                }}
            </ul>

            {move || if can_manage() {
                let member_opts = members.get();
                let role_opts = roles.get();
                let invite_href = scope_url.get_value();
                Some(view! {
                    <div class="mt-6 border-t border-neutral-800 pt-4">
                        <h3 class="text-sm font-semibold">"Assign role"</h3>
                        <select class="input mt-2" bind:value=new_user>
                            <option value="">"— select member —"</option>
                            {member_opts
                                .into_iter()
                                .map(|m| {
                                    let id = m.user_id.to_string();
                                    let label = m.email.clone();
                                    view! { <option value=id.clone()>{label}</option> }
                                })
                                .collect_view()}
                        </select>
                        <select class="input mt-2" bind:value=new_role>
                            <option value="">"— select role —"</option>
                            {role_opts
                                .into_iter()
                                .map(|r| {
                                    let v = r.key.clone();
                                    let label = format!("{} — {}", r.key, r.name);
                                    view! { <option value=v.clone()>{label}</option> }
                                })
                                .collect_view()}
                        </select>
                        <button class="btn mt-3" on:click=submit_assign>"Assign"</button>

                        <p class="mt-4 text-sm text-neutral-400">
                            "Member not in the list? "
                            <a class="text-blue-400 hover:underline" href=invite_href>
                                "Invite instead"
                            </a>
                        </p>
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

/// `/tenants/:tenant_id/members` — tenant member list.
#[component]
pub fn TenantMemberListPage() -> impl IntoView {
    let params = use_params::<TenantIdParams>();
    let tenant_id = move || params.with(|r| r.as_ref().ok().map(|p| p.tenant_id));

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/tenants">"← All tenants"</a>
            <h1 class="mt-2 text-2xl font-bold">"Tenant members"</h1>
            {move || tenant_id().map(|id| {
                let domain = domain::tenant_domain(id);
                let scope_url = format!("/tenants/{id}/invitations");
                view! {
                    <div class="mt-2">
                        <a class="btn text-sm" href=format!("/tenants/{id}")>
                            "Open tenant"
                        </a>
                    </div>
                    <MemberListPage domain=domain scope_url=scope_url />
                }
            })}
        </main>
    }
}

#[derive(Params, PartialEq)]
struct WorkspaceIdParams {
    workspace_id: Uuid,
}

/// `/workspaces/:workspace_id/members` — workspace member list.
#[component]
pub fn WorkspaceMemberListPage() -> impl IntoView {
    let params = use_params::<WorkspaceIdParams>();
    let workspace_id = move || params.with(|r| r.as_ref().ok().map(|p| p.workspace_id));

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/workspaces">"← All workspaces"</a>
            <h1 class="mt-2 text-2xl font-bold">"Workspace members"</h1>
            {move || workspace_id().map(|id| {
                let domain = domain::workspace_domain(id);
                let scope_url = format!("/workspaces/{id}/invitations");
                view! {
                    <div class="mt-2">
                        <a class="btn text-sm" href=format!("/workspaces/{id}")>
                            "Open workspace"
                        </a>
                    </div>
                    <MemberListPage domain=domain scope_url=scope_url />
                }
            })}
        </main>
    }
}