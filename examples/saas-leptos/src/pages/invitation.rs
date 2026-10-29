//! Invitation UI: create/list/revoke (tenant- and workspace-scoped) and
//! accept via an invitation link.
//!
//! Every server function delegates to `saas::invitation::*`; errors go
//! through `crate::error::core_error_to_server_fn` (HTTP 400/401/403/404/500).
//!
//! Stage 3a: on `InvitationAcceptPage`, when the visitor is anonymous, the
//! page calls `set_return_url("/invitations/{token}")`. The `return_url`
//! cookie is then consumed by `pages::auth::{LoginPage, RegisterPage}` after
//! a successful sign-in, so an anonymous user returning from the login page
//! lands back on the invitation accept page and can finish the flow.

use domain::{Invitation, InvitationTarget};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params};
use leptos_router::params::Params;
use uuid::Uuid;

use crate::auth::set_return_url;

// ─── Server functions ───────────────────────────────────────────────────────

/// Returns the current user's email, or `None` if not logged in.
#[server]
pub async fn who_am_i() -> Result<Option<String>, ServerFnError> {
    let current = crate::extract::CurrentUser::from_request().await?;
    Ok(current.0.map(|u| u.email))
}

/// Checks an invitation token without accepting it.
#[server]
pub async fn get_invitation_info(token: String) -> Result<Option<Invitation>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    saas::invitation::check_invitation(&state.saas, &token)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Creates an invitation. Returns the invitation row plus the raw token.
#[server]
pub async fn create_invitation(
    target: InvitationTarget,
    email: Option<String>,
    role: String,
    max_uses: Option<i32>,
) -> Result<(Invitation, String), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::invitation::create_invitation(&state.saas, &user, target, email, role, None, max_uses)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Lists invitations for a tenant or workspace, newest first.
#[server]
pub async fn list_invitations(target: InvitationTarget) -> Result<Vec<Invitation>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::invitation::list_invitations(&state.saas, &user, target)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Revokes an invitation (sets `revoked_at`).
#[server]
pub async fn revoke_invitation(
    target: InvitationTarget,
    invitation_id: Uuid,
) -> Result<(), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::invitation::revoke_invitation(&state.saas, &user, target, invitation_id)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Accepts an invitation by raw token.
#[server]
pub async fn accept_invitation(token: String) -> Result<Invitation, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::invitation::accept_invitation(&state.saas, &user, &token)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

// ─── Shared panel ───────────────────────────────────────────────────────────

#[component]
pub fn InvitationListPage(target: InvitationTarget) -> impl IntoView {
    let invitations = RwSignal::new(Vec::<Invitation>::new());
    let error = RwSignal::new(None::<String>);
    let refresh = RwSignal::new(0u32);

    Effect::new(move |_| {
        let _ = refresh.get();
        spawn_local(async move {
            match list_invitations(target).await {
                Ok(list) => {
                    invitations.set(list);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    let email = RwSignal::new(String::new());
    let role = RwSignal::new(default_role(target).to_string());
    let max_uses = RwSignal::new(String::new());
    let created_token = RwSignal::new(None::<String>);

    let submit = move |_| {
        let email_v = email.get();
        let email_opt = if email_v.trim().is_empty() {
            None
        } else {
            Some(email_v)
        };
        let role_v = role.get();
        let max_uses_v = max_uses.get();
        let max_uses_opt = if max_uses_v.trim().is_empty() {
            None
        } else {
            match max_uses_v.trim().parse::<i32>() {
                Ok(n) => Some(n),
                Err(_) => {
                    error.set(Some("max_uses must be an integer".into()));
                    return;
                }
            }
        };
        spawn_local(async move {
            match create_invitation(target, email_opt, role_v, max_uses_opt).await {
                Ok((_inv, token)) => {
                    created_token.set(Some(token));
                    email.set(String::new());
                    max_uses.set(String::new());
                    error.set(None);
                    refresh.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    };

    let role_options = role_options(target);

    view! {
        <div class="card mt-6">
            <h2 class="text-lg font-semibold">"Create invitation"</h2>

            <input
                class="input mt-2"
                placeholder="Email (leave empty for a reusable link)"
                bind:value=email
            />
            <select class="input mt-2" bind:value=role>
                {role_options
                    .iter()
                    .map(|r| view! { <option value=*r>{*r}</option> })
                    .collect_view()}
            </select>
            <input
                class="input mt-2"
                placeholder="Max uses (empty = unlimited)"
                bind:value=max_uses
            />
            <button class="btn mt-3" on:click=submit>"Create"</button>

            {move || created_token.get().map(|t| view! {
                <div class="mt-4 p-3 rounded bg-neutral-800">
                    <p class="text-sm text-neutral-400">
                        "Invitation link (copy now — it will not be shown again):"
                    </p>
                    <code class="block mt-2 break-all text-sm">{format!("/invitations/{t}")}</code>
                </div>
            })}
        </div>

        {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

        <div class="mt-8">
            <h2 class="text-xl font-semibold">"Invitations"</h2>
            <ul class="mt-3 divide-y divide-neutral-800">
                {move || {
                    let list = invitations.get();
                    if list.is_empty() {
                        view! {
                            <li class="py-2 text-neutral-500">"No invitations yet."</li>
                        }
                            .into_any()
                    } else {
                        list.into_iter()
                            .map(|inv| {
                                let inv_id = inv.id;
                                let label = inv
                                    .email
                                    .clone()
                                    .unwrap_or_else(|| "link".into());
                                let state = invite_status(&inv);
                                view! {
                                    <li class="py-3 flex items-center justify-between gap-4">
                                        <div>
                                            <p class="font-medium">
                                                {format!("{} — {}", inv.role, label)}
                                            </p>
                                            <p class="text-sm text-neutral-400">{state}</p>
                                        </div>
                                        <button
                                            class="btn text-sm"
                                            on:click=move |_| {
                                                spawn_local(async move {
                                                    match revoke_invitation(target, inv_id).await {
                                                        Ok(()) => {
                                                            error.set(None);
                                                            refresh.update(|n| *n += 1);
                                                        }
                                                        Err(e) => error.set(Some(e.to_string())),
                                                    }
                                                });
                                            }
                                        >
                                            "Revoke"
                                        </button>
                                    </li>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }
                }}
            </ul>
        </div>
    }
}

fn default_role(target: InvitationTarget) -> &'static str {
    match target {
        InvitationTarget::Tenant(_) => "owner",
        InvitationTarget::Workspace(_) => "editor",
    }
}

fn role_options(target: InvitationTarget) -> &'static [&'static str] {
    match target {
        InvitationTarget::Tenant(_) => &["owner"],
        InvitationTarget::Workspace(_) => &["owner", "editor", "viewer"],
    }
}

fn invite_status(inv: &Invitation) -> String {
    if inv.revoked_at.is_some() {
        "revoked".into()
    } else if let Some(max) = inv.max_uses {
        format!(
            "{}/{} uses · expires {}",
            inv.used_count, max, inv.expires_at
        )
    } else {
        format!("{} uses · expires {}", inv.used_count, inv.expires_at)
    }
}

// ─── Tenant / workspace pages ───────────────────────────────────────────────

#[derive(Params, PartialEq)]
struct TenantIdParams {
    tenant_id: Uuid,
}

#[component]
pub fn TenantInvitationListPage() -> impl IntoView {
    let params = use_params::<TenantIdParams>();
    let tenant_id = move || params.with(|r| r.as_ref().ok().map(|p| p.tenant_id));

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/tenants">"← All tenants"</a>

            <h1 class="mt-2 text-2xl font-bold">"Tenant invitations"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                {move || tenant_id()
                    .map(|id| format!("tenant id: {id}"))
                    .unwrap_or_else(|| "invalid tenant id".into())}
            </p>

            {move || tenant_id().map(|id| view! {
                <div class="mt-2">
                    <a class="btn text-sm" href=format!("/tenants/{id}")>"Open tenant"</a>
                </div>
                <InvitationListPage target=InvitationTarget::Tenant(id) />
            })}
        </main>
    }
}

#[derive(Params, PartialEq)]
struct WorkspaceIdParams {
    workspace_id: Uuid,
}

#[component]
pub fn WorkspaceInvitationListPage() -> impl IntoView {
    let params = use_params::<WorkspaceIdParams>();
    let workspace_id = move || params.with(|r| r.as_ref().ok().map(|p| p.workspace_id));

    view! {
        <main class="mx-auto max-w-2xl p-8">
            <a class="text-sm text-neutral-400" href="/workspaces">"← All workspaces"</a>

            <h1 class="mt-2 text-2xl font-bold">"Workspace invitations"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                {move || workspace_id()
                    .map(|id| format!("workspace id: {id}"))
                    .unwrap_or_else(|| "invalid workspace id".into())}
            </p>

            {move || workspace_id().map(|id| view! {
                <div class="mt-2">
                    <a class="btn text-sm" href=format!("/workspaces/{id}")>"Open workspace"</a>
                </div>
                <InvitationListPage target=InvitationTarget::Workspace(id) />
            })}
        </main>
    }
}

// ─── Accept page ────────────────────────────────────────────────────────────

#[derive(Params, PartialEq)]
struct InviteTokenParams {
    token: String,
}

#[component]
pub fn InvitationAcceptPage() -> impl IntoView {
    let params = use_params::<InviteTokenParams>();
    let token = move || params.with(|r| r.as_ref().ok().map(|p| p.token.clone()));

    let invite_info = RwSignal::new(None::<Option<Invitation>>);
    let user_email = RwSignal::new(None::<Option<String>>);
    let error = RwSignal::new(None::<String>);
    let navigate = use_navigate();

    Effect::new(move |_| {
        let Some(tok) = token() else {
            error.set(Some("invalid invitation token".into()));
            return;
        };
        spawn_local(async move {
            match get_invitation_info(tok).await {
                Ok(info) => invite_info.set(Some(info)),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    Effect::new(move |_| {
        spawn_local(async move {
            match who_am_i().await {
                Ok(email) => user_email.set(Some(email)),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    // Stage 3a: if the visitor is anonymous, remember this page in the
    // `return_url` cookie, so `pages::auth::{LoginPage, RegisterPage}` can
    // redirect here after a successful sign-in. Idempotent: fire only once,
    // and only when `who_am_i()` has resolved to `Some(None)`.
    let return_url_set = RwSignal::new(false);
    Effect::new(move |_| {
        let Some(tok) = token() else { return };
        let Some(user) = user_email.get() else { return };
        if user.is_some() || return_url_set.get_untracked() {
            return;
        }
        return_url_set.set(true);
        spawn_local(async move {
            let _ = set_return_url(format!("/invitations/{tok}")).await;
        });
    });

    view! {
        <main class="mx-auto max-w-sm p-8">
            <h1 class="text-2xl font-bold">"Accept invitation"</h1>

            {move || match invite_info.get() {
                None => view! { <p class="mt-6 text-neutral-400">"Checking invitation…"</p> }.into_any(),
                Some(None) => view! {
                    <p class="mt-6 text-red-400">
                        "This invitation is invalid, expired, revoked, or has reached its maximum uses."
                    </p>
                }.into_any(),
                Some(Some(_)) => match user_email.get() {
                    None => view! { <p class="mt-6 text-neutral-400">"Loading…"</p> }.into_any(),
                    Some(None) => view! {
                        <div class="mt-6 space-y-3">
                            <p class="text-neutral-400">
                                "You need to log in or register first, then come back to this page."
                            </p>
                            <a class="btn inline-block" href="/login">"Log in"</a>
                            <a class="btn inline-block" href="/register">"Register"</a>
                        </div>
                    }.into_any(),
                    Some(Some(email)) => {
                        let navigate = navigate.clone();
                        let accept_handler = move |_| {
                            let Some(tok) = token() else {
                                error.set(Some("invalid invitation token".into()));
                                return;
                            };
                            let navigate = navigate.clone();
                            spawn_local(async move {
                                match accept_invitation(tok).await {
                                    Ok(inv) => {
                                        if let Some(tid) = inv.tenant_id {
                                            navigate(&format!("/tenants/{tid}"), Default::default());
                                        } else if let Some(wid) = inv.workspace_id {
                                            navigate(&format!("/workspaces/{wid}"), Default::default());
                                        } else {
                                            error.set(Some("invitation has no target".into()));
                                        }
                                    }
                                    Err(e) => error.set(Some(e.to_string())),
                                }
                            });
                        };
                        view! {
                            <div class="mt-6 space-y-3">
                                <p class="text-neutral-400">{format!("Logged in as {email}")}</p>
                                <button class="btn" on:click=accept_handler>
                                    "Accept invitation"
                                </button>
                            </div>
                        }.into_any()
                    }
                }
            }}

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
        </main>
    }
}