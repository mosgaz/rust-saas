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
//!
//! Stage 3c — addressed invitations (`invitation.email IS NOT NULL`):
//! - [`who_am_i`] returns [`SessionUser`] (`email` + `email_verified`)
//!   instead of a bare `String`. The DTO is named `SessionUser` (not
//!   `WhoAmI`) because the `#[server]` macro generates a same-named struct
//!   `WhoAmI` for the function's endpoint, causing a name collision.
//!   `Layout` only reads `Option::is_some` and is unaffected.
//! - [`create_invitation`] returns `(Invitation, String, Option<EmailResult>)`.
//!   `Some` appears only for addressed invitations, where the raw token is
//!   sent by [`crate::email::EmailSender::send_invitation`]; the UI renders
//!   `Sent` / `Failed` / `Disabled` (and a copy-link fallback) instead of
//!   always showing the raw token as a link.
//! - [`InvitationAcceptPage`] gates Accept for addressed invitations:
//!   - unverified actor → the server returns
//!     [`saas::CoreError::EmailNotVerified`]; the UI shows
//!     "verify your email first" and a **Resend verification email**
//!     button that reuses [`crate::auth::request_email_verification`].
//!   - verified actor whose email does not match the invitation
//!     (case-insensitive) → the server returns
//!     [`saas::CoreError::Forbidden`]; the UI shows "invitation is for X,
//!     you are logged in as Y" and a link to `/login`.
//!   Link invitations (`email IS NULL`) skip both checks (Stage 2a
//!   behaviour preserved).

use domain::{Invitation, InvitationTarget};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params};
use leptos_router::params::Params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{request_email_verification, set_return_url};
use crate::email::EmailResult;

// ─── Session user (Stage 3c) ───────────────────────────────────────────────

/// The current user as seen by client code: email + verified flag.
///
/// Replaces the Stage 2a `Option<String>` return type of [`who_am_i`].
/// `email_verified` mirrors `domain::AuthUser.email_verified`, which `authn`
/// resolves from `users.email_verified_at` on every request; it is not
/// embedded in the access JWT (Stage 3b claims cleanup).
///
/// **Not** named `WhoAmI`: the `#[server]` attribute on `who_am_i` generates
/// a struct of that exact name for the function endpoint; a client-side DTO
/// `WhoAmI` collides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionUser {
    pub email: String,
    pub email_verified: bool,
}

/// Returns the current user, or `None` if not logged in.
#[server]
pub async fn who_am_i() -> Result<Option<SessionUser>, ServerFnError> {
    let current = crate::extract::CurrentUser::from_request().await?;
    Ok(current.0.map(|u| SessionUser {
        email: u.email,
        email_verified: u.email_verified,
    }))
}

/// Checks an invitation token without accepting it.
#[server]
pub async fn get_invitation_info(token: String) -> Result<Option<Invitation>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    saas::invitation::check_invitation(&state.saas, &token)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

/// Creates an invitation. Returns the invitation row, the raw token, and —
/// **only for addressed invitations** (`email IS NOT NULL`) — the email-send
/// outcome.
///
/// Link invitations (`email IS NULL`) return `None` for the third element:
/// the raw token is displayed once in the UI and shared out of band.
#[server]
pub async fn create_invitation(
    target: InvitationTarget,
    email: Option<String>,
    role: String,
    max_uses: Option<i32>,
) -> Result<(Invitation, String, Option<EmailResult>), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    let (invitation, token) = saas::invitation::create_invitation(
        &state.saas,
        &user,
        target,
        email,
        role,
        None,
        max_uses,
    )
    .await
    .map_err(crate::error::core_error_to_server_fn)?;

    // Addressed invitation — send the link via SMTP. Link invitations skip
    // this branch entirely (raw token is shown in the UI instead).
    let email_result = match invitation.email.as_deref() {
        Some(addr) => Some(state.email.send_invitation(addr, &token).await),
        None => None,
    };

    Ok((invitation, token, email_result))
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
///
/// Stage 3c: for addressed invitations the server enforces
/// `CoreError::EmailNotVerified` (actor unverified) and
/// `CoreError::Forbidden` (email mismatch, case-insensitive) before any
/// mutation; the UI's client-side gating is a convenience, not the security
/// boundary.
#[server]
pub async fn accept_invitation(token: String) -> Result<Invitation, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    saas::invitation::accept_invitation(&state.saas, &user, &token)
        .await
        .map_err(crate::error::core_error_to_server_fn)
}

// ─── Shared panel ───────────────────────────────────────────────────────────

/// Local view of a freshly-created invitation: the invitation row, the raw
/// token (to display once for link invitations or as a manual-share
/// fallback for addressed invitations whose send failed), and the optional
/// email outcome for addressed invitations.
///
/// `#[derive(Clone)]` is required because `RwSignal<Option<T>>::get()`
/// returns `Option<T>` by clone.
#[derive(Clone)]
struct CreatedInvitation {
    invitation: Invitation,
    token: String,
    email_result: Option<EmailResult>,
}

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
    let created = RwSignal::new(None::<CreatedInvitation>);

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
                Ok((inv, token, email_result)) => {
                    created.set(Some(CreatedInvitation {
                        invitation: inv,
                        token,
                        email_result,
                    }));
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

            {move || created.get().map(created_view)}
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

/// Renders the "created" panel. Four cases:
///
/// - addressed + `Sent` → confirmation; the raw token is not shown (it was
///   delivered by email);
/// - addressed + `Failed { reason }` → error banner + copy-link fallback
///   (the invitation row exists; the user shares the link manually);
/// - addressed + `Disabled` → "email delivery is not configured" + copy-link;
/// - link invitation (`email IS NULL`) → raw-token link, shown once
///   (Stage 2a behaviour).
fn created_view(c: CreatedInvitation) -> AnyView {
    let invitation_url = format!("/invitations/{}", c.token);
    let is_addressed = c.invitation.email.is_some();

    if !is_addressed {
        return view! {
            <div class="mt-4 p-3 rounded bg-neutral-800">
                <p class="text-sm text-neutral-400">
                    "Invitation link (copy now — it will not be shown again):"
                </p>
                <code class="block mt-2 break-all text-sm">{invitation_url}</code>
            </div>
        }
        .into_any();
    }

    let addr = c.invitation.email.clone().unwrap_or_default();
    match c.email_result {
        Some(EmailResult::Sent) => view! {
            <div class="mt-4 p-3 rounded bg-neutral-800">
                <p class="text-sm text-neutral-400">
                    {format!("Invitation sent to {addr}.")}
                </p>
            </div>
        }
        .into_any(),
        Some(EmailResult::Failed { reason }) => view! {
            <div class="mt-4 p-3 rounded bg-neutral-800">
                <p class="text-sm text-red-400">
                    {format!("Could not send the invitation to {addr}: {reason}")}
                </p>
                <p class="mt-2 text-sm text-neutral-400">
                    "Share this link manually:"
                </p>
                <code class="block mt-2 break-all text-sm">{invitation_url}</code>
            </div>
        }
        .into_any(),
        Some(EmailResult::Disabled) => view! {
            <div class="mt-4 p-3 rounded bg-neutral-800">
                <p class="text-sm text-yellow-400">
                    {format!("Email delivery is not configured; share this link with {addr}:")}
                </p>
                <code class="block mt-2 break-all text-sm">{invitation_url}</code>
            </div>
        }
        .into_any(),
        // Defensive: addressed invitation with `None` email_result should not
        // occur (the server always calls `send_invitation` for addressed).
        // Fall back to showing the link so the operator can debug.
        None => view! {
            <div class="mt-4 p-3 rounded bg-neutral-800">
                <p class="text-sm text-neutral-400">
                    "Invitation created (no email outcome reported):"
                </p>
                <code class="block mt-2 break-all text-sm">{invitation_url}</code>
            </div>
        }
        .into_any(),
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
    let who = RwSignal::new(None::<Option<SessionUser>>);
    let error = RwSignal::new(None::<String>);
    let resend_status = RwSignal::new(None::<String>);
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
                Ok(w) => who.set(Some(w)),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    });

    // Stage 3a: remember this page in `return_url` for anonymous visitors, so
    // `pages::auth::{LoginPage, RegisterPage}` can redirect back after a
    // successful sign-in. Idempotent: fire once, only when `who_am_i()` has
    // resolved to `Some(None)`.
    let return_url_set = RwSignal::new(false);
    Effect::new(move |_| {
        let Some(tok) = token() else { return };
        let Some(w) = who.get() else { return };
        if w.is_some() || return_url_set.get_untracked() {
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

            {move || {
                let nav = navigate.clone();
                match invite_info.get() {
                    None => view! {
                        <p class="mt-6 text-neutral-400">"Checking invitation…"</p>
                    }.into_any(),
                    Some(None) => view! {
                        <p class="mt-6 text-red-400">
                            "This invitation is invalid, expired, revoked, or has reached its maximum uses."
                        </p>
                    }.into_any(),
                    Some(Some(inv)) => match who.get() {
                        None => view! {
                            <p class="mt-6 text-neutral-400">"Loading…"</p>
                        }.into_any(),
                        Some(None) => view! {
                            <div class="mt-6 space-y-3">
                                <p class="text-neutral-400">
                                    "You need to log in or register first, then come back to this page."
                                </p>
                                <a class="btn inline-block" href="/login">"Log in"</a>
                                <a class="btn inline-block" href="/register">"Register"</a>
                            </div>
                        }.into_any(),
                        Some(Some(u)) => {
                            let needs_verify = inv.email.is_some() && !u.email_verified;
                            let wrong_user = inv
                                .email
                                .as_deref()
                                .map(|e| u.email_verified && !u.email.eq_ignore_ascii_case(e))
                                .unwrap_or(false);

                            if needs_verify {
                                let inv_email = inv.email.clone().unwrap_or_default();
                                view! {
                                    <div class="mt-6 space-y-3">
                                        <p class="text-red-400">
                                            "This invitation was sent to a specific email address. Verify your email before accepting."
                                        </p>
                                        <p class="text-sm text-neutral-400">
                                            {format!("Your address: {} (unverified)", u.email)}
                                        </p>
                                        <p class="text-xs text-neutral-500">
                                            {format!("Invitation for: {inv_email}")}
                                        </p>
                                    </div>
                                }.into_any()
                            } else if wrong_user {
                                let inv_email = inv.email.clone().unwrap_or_default();
                                let u_email = u.email.clone();
                                let inv_email_for_label = inv_email.clone();
                                view! {
                                    <div class="mt-6 space-y-3">
                                        <p class="text-red-400">
                                            {format!("This invitation is for {inv_email}.")}
                                        </p>
                                        <p class="text-sm text-neutral-400">
                                            {format!("You are logged in as {u_email}.")}
                                        </p>
                                        <a class="btn inline-block" href="/login">
                                            {format!("Sign in as {inv_email_for_label}")}
                                        </a>
                                        <p class="text-xs text-neutral-500">
                                            "Log out first if you are already signed in as another user."
                                        </p>
                                    </div>
                                }.into_any()
                            } else {
                                match token() {
                                    Some(tok) => {
                                        let nav = nav.clone();
                                        let on_accept = move |_| {
                                            let tok = tok.clone();
                                            let nav = nav.clone();
                                            spawn_local(async move {
                                                match accept_invitation(tok).await {
                                                    Ok(acc) => {
                                                        if let Some(tid) = acc.tenant_id {
                                                            nav(
                                                                &format!("/tenants/{tid}"),
                                                                Default::default(),
                                                            );
                                                        } else if let Some(wid) = acc.workspace_id {
                                                            nav(
                                                                &format!("/workspaces/{wid}"),
                                                                Default::default(),
                                                            );
                                                        }
                                                    }
                                                    Err(e) => error.set(Some(e.to_string())),
                                                }
                                            });
                                        };
                                        view! {
                                            <div class="mt-6 space-y-3">
                                                <button class="btn" on:click=on_accept>
                                                    "Accept invitation"
                                                </button>
                                            </div>
                                        }.into_any()
                                    }
                                    None => view! {
                                        <p class="mt-6 text-red-400">
                                            "Invalid invitation token."
                                        </p>
                                    }.into_any(),
                                }
                            }
                        }
                    },
                }
            }}

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}

            {move || resend_status.get().map(|s| view! {
                <p class="mt-4 text-sm text-neutral-400">{s}</p>
            })}

            {move || {
                // Show the Resend button only when the accept view decided
                // the actor needs to verify first (addressed + unverified).
                let info = invite_info.get();
                let w = who.get();
                let needs_verify = match (info, w) {
                    (Some(Some(inv)), Some(Some(u))) => {
                        inv.email.is_some() && !u.email_verified
                    }
                    _ => false,
                };
                if !needs_verify {
                    return None;
                }
                Some(view! {
                    <button
                        class="btn mt-3"
                        on:click=move |_| {
                            resend_status.set(None);
                            spawn_local(async move {
                                match request_email_verification().await {
                                    Ok(EmailResult::Sent) => resend_status.set(Some(
                                        "Verification email sent.".into(),
                                    )),
                                    Ok(EmailResult::Failed { reason }) => resend_status
                                        .set(Some(format!("Resend failed: {reason}"))),
                                    Ok(EmailResult::Disabled) => resend_status.set(Some(
                                        "Email delivery is not configured on this server.".into(),
                                    )),
                                    Err(e) => resend_status.set(Some(e.to_string())),
                                }
                            });
                        }
                    >
                        "Resend verification email"
                    </button>
                })
            }}
        </main>
    }
}