//! Login, registration, email verification (Stage 3b), and password reset
//! (Stage 3d) pages.
//!
//! Stage 3a: after a successful `login` / `register`, the page consumes the
//! `return_url` cookie (set by `pages::invitation::InvitationAcceptPage` for
//! anonymous visitors) via `crate::auth::take_return_url`.
//!
//! Stage 3b:
//! - `RegisterPage`: `register` now returns `(AuthUser, EmailResult)`. After
//!   success, the page shows the account-created banner, the email outcome
//!   (Sent / Failed + Resend / Disabled), and a "Continue" button that
//!   navigates to `return_url` (or `/`). The verification email is
//!   best-effort; a failed send does not block registration.
//! - `VerifyEmailPage` (`/verify/:token`): calls the **public**
//!   `crate::auth::verify_email` on mount. Idempotent on the server side;
//!   shows a generic "verified" or "invalid/expired" message and links to
//!   `/login`. Does not log the user in.
//!
//! Stage 3d:
//! - `LoginPage`: a "Forgot password?" link next to the sign-in button.
//! - `ForgotPasswordPage` (`/forgot-password`): submits the address to the
//!   **public** `crate::auth::request_password_reset`. The server is silent
//!   on unknown emails and the page shows a **generic** confirmation —
//!   "If an account with that email exists, we've sent a reset link" — for
//!   both existing and unknown addresses. Only a `429` (rate limited) is
//!   surfaced as an error; other server-side outcomes are swallowed by the
//!   silent path.
//! - `ResetPasswordPage` (`/reset-password/:token`): a "new password" +
//!   "confirm password" form. Client-side checks (min 8 chars, match) run
//!   before the `#[server]` call; the server validates again via
//!   `identity::validate_password`. On success shows "Password updated" and
//!   a link to `/login`. `TokenInvalid` / `TokenExpired` are shown as a
//!   banner. The server is **one-shot**: a replayed token returns
//!   `TokenInvalid`. Does **not** auto-login — cookies from before the reset
//!   are revoked server-side (all refresh-token families are revoked with
//!   `revoked_reason = "password_reset"`); the user signs in again.

use crate::auth::{
    login, register, request_email_verification, request_password_reset, reset_password,
    take_return_url, verify_email,
};
use crate::email::EmailResult;
use domain::AuthUser;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::{use_navigate, use_params};
use leptos_router::params::Params;

// ─── Login ──────────────────────────────────────────────────────────────────

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

                <p class="text-sm text-neutral-400">
                    <a class="text-blue-400 hover:underline" href="/forgot-password">
                        "Forgot password?"
                    </a>
                </p>

                {move || error.get().map(|e| view! { <p class="text-red-400">{e}</p> })}
                {move || user.get().map(|u| view! { <p class="text-green-400">{u.email}</p> })}
            </div>
        </main>
    }
}

// ─── Register (Stage 3b: EmailResult + Resend) ──────────────────────────────

#[component]
pub fn RegisterPage() -> impl IntoView {
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let user = RwSignal::new(None::<AuthUser>);
    let email_result = RwSignal::new(None::<EmailResult>);
    let back_url = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let resend_status = RwSignal::new(None::<String>);
    let resending = RwSignal::new(false);
    let submitting = RwSignal::new(false);
    let navigate = use_navigate();

    view! {
        <main class="mx-auto max-w-sm p-8">
            <h1 class="text-2xl font-bold">"Register"</h1>

            {move || match user.get() {
                None => {
                    let on_submit = Callback::new(move |_: ()| {
                        if submitting.get_untracked() {
                            return;
                        }
                        submitting.set(true);
                        error.set(None);
                        let e = email.get_untracked();
                        let p = password.get_untracked();
                        spawn_local(async move {
                            match register(e, p).await {
                                Ok((u, er)) => {
                                    user.set(Some(u));
                                    email_result.set(Some(er));
                                    let back = take_return_url().await.ok().flatten();
                                    back_url.set(back);
                                    error.set(None);
                                }
                                Err(e) => error.set(Some(e.to_string())),
                            }
                            submitting.set(false);
                        });
                    });
                    view! {
                        <div class="mt-6 space-y-4">
                            <input class="input" placeholder="Email" bind:value=email />
                            <input class="input" type="password" placeholder="Password" bind:value=password />
                            <button class="btn" on:click=move |_| on_submit.run(())>
                                "Create account"
                            </button>
                        </div>
                    }.into_any()
                }
                Some(u) => match email_result.get() {
                    Some(result) => {
                        let nav = navigate.clone();
                        let on_resend = Callback::new(move |_: ()| {
                            if resending.get_untracked() {
                                return;
                            }
                            resending.set(true);
                            resend_status.set(None);
                            spawn_local(async move {
                                match request_email_verification().await {
                                    Ok(r @ EmailResult::Sent) => {
                                        resend_status.set(Some("Verification email sent.".into()));
                                        email_result.set(Some(r));
                                    }
                                    Ok(r @ EmailResult::Failed { .. }) => {
                                        resend_status.set(Some("Resend failed.".into()));
                                        email_result.set(Some(r));
                                    }
                                    Ok(r @ EmailResult::Disabled) => {
                                        resend_status.set(Some(
                                            "Email delivery is still not configured.".into(),
                                        ));
                                        email_result.set(Some(r));
                                    }
                                    Err(e) => {
                                        resend_status.set(Some(e.to_string()));
                                    }
                                }
                                resending.set(false);
                            });
                        });
                        let on_continue = Callback::new(move |_: ()| {
                            let target = back_url.get_untracked().unwrap_or_else(|| "/".to_string());
                            nav(&target, Default::default());
                        });
                        let result_view = match result {
                            EmailResult::Sent => view! {
                                <p class="text-sm text-neutral-400">
                                    "We sent a verification link to your email. Check your inbox."
                                </p>
                            }.into_any(),
                            EmailResult::Failed { reason } => view! {
                                <div class="space-y-2">
                                    <p class="text-sm text-red-400">
                                        {format!("Could not send the verification email: {reason}")}
                                    </p>
                                    <button class="btn text-sm" on:click=move |_| on_resend.run(())>
                                        "Resend verification email"
                                    </button>
                                </div>
                            }.into_any(),
                            EmailResult::Disabled => view! {
                                <p class="text-sm text-yellow-400">
                                    "Email delivery is not configured on this server. Contact the administrator."
                                </p>
                            }.into_any(),
                        };
                        view! {
                            <div class="mt-6 space-y-4">
                                <p class="text-green-400">
                                    "Account created for " {u.email.clone()}
                                </p>
                                {result_view}
                                {move || resend_status.get().map(|s| view! {
                                    <p class="text-sm text-neutral-400">{s}</p>
                                })}
                                <button class="btn" on:click=move |_| on_continue.run(())>
                                    "Continue"
                                </button>
                            </div>
                        }.into_any()
                    }
                    None => view! { <p class="mt-6 text-neutral-400">"Loading…"</p> }.into_any(),
                },
            }}

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
        </main>
    }
}

// ─── Verify email (Stage 3b, `/verify/:token`) ──────────────────────────────

#[derive(Params, PartialEq)]
struct VerifyTokenParams {
    token: String,
}

#[derive(Clone)]
enum VerifyStatus {
    Loading,
    Verified { email: String },
    Invalid { reason: String },
}

#[component]
pub fn VerifyEmailPage() -> impl IntoView {
    let params = use_params::<VerifyTokenParams>();
    let token = move || params.with(|r| r.as_ref().ok().map(|p| p.token.clone()));

    let status = RwSignal::new(VerifyStatus::Loading);

    Effect::new(move |_| {
        let Some(tok) = token() else {
            status.set(VerifyStatus::Invalid {
                reason: "missing token".into(),
            });
            return;
        };
        spawn_local(async move {
            match verify_email(tok).await {
                Ok(u) => status.set(VerifyStatus::Verified { email: u.email }),
                Err(e) => status.set(VerifyStatus::Invalid {
                    reason: e.to_string(),
                }),
            }
        });
    });

    view! {
        <main class="mx-auto max-w-sm p-8">
            <h1 class="text-2xl font-bold">"Verify email"</h1>

            {move || match status.get() {
                VerifyStatus::Loading => view! {
                    <p class="mt-6 text-neutral-400">"Checking your link…"</p>
                }.into_any(),
                VerifyStatus::Verified { email } => view! {
                    <div class="mt-6 space-y-4">
                        <p class="text-green-400">
                            {format!("Email verified: {email}")}
                        </p>
                        <p class="text-sm text-neutral-400">
                            "You can now sign in."
                        </p>
                        <a class="btn inline-block" href="/login">"Go to login"</a>
                    </div>
                }.into_any(),
                VerifyStatus::Invalid { reason } => view! {
                    <div class="mt-6 space-y-4">
                        <p class="text-red-400">
                            "This verification link is invalid or has expired."
                        </p>
                        <p class="text-xs text-neutral-500">{reason}</p>
                        <a class="btn inline-block" href="/login">"Go to login"</a>
                    </div>
                }.into_any(),
            }}
        </main>
    }
}

// ─── Forgot password (Stage 3d, `/forgot-password`) ─────────────────────────

/// Requests a password-reset email for the entered address.
///
/// Silent: the server returns `Ok(())` for unknown emails, and the page
/// shows the same generic confirmation regardless of whether the address is
/// registered. Only rate-limit errors (`429`) are surfaced as such — the
/// rate limiter is keyed by the raw submitted address, not by the resolved
/// user id, so the shape of the response does not depend on whether the
/// address exists.
#[component]
pub fn ForgotPasswordPage() -> impl IntoView {
    let email = RwSignal::new(String::new());
    let submitted = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let submitting = RwSignal::new(false);

    let submit = move |_| {
        if submitting.get_untracked() {
            return;
        }
        let addr = email.get().trim().to_string();
        if addr.is_empty() {
            error.set(Some("email is required".into()));
            return;
        }
        submitting.set(true);
        error.set(None);
        spawn_local(async move {
            match request_password_reset(addr).await {
                Ok(()) => {
                    submitted.set(true);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            submitting.set(false);
        });
    };

    view! {
        <main class="mx-auto max-w-sm p-8">
            <h1 class="text-2xl font-bold">"Forgot password"</h1>
            <p class="mt-2 text-sm text-neutral-400">
                "Enter the email address on your account and we will send you a reset link."
            </p>

            {move || {
                if submitted.get() {
                    view! {
                        <div class="mt-6 space-y-4">
                            <p class="text-green-400">
                                "If an account with that email exists, we've sent a reset link."
                            </p>
                            <p class="text-sm text-neutral-400">
                                "Check your inbox (and spam folder). The link expires in 1 hour."
                            </p>
                            <a class="btn inline-block" href="/login">"Back to login"</a>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="mt-6 space-y-4">
                            <input class="input" placeholder="Email" bind:value=email />
                            <button class="btn" on:click=submit>"Send reset link"</button>
                        </div>
                    }.into_any()
                }
            }}

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
        </main>
    }
}

// ─── Reset password (Stage 3d, `/reset-password/:token`) ────────────────────

#[derive(Params, PartialEq)]
struct ResetTokenParams {
    token: String,
}

#[component]
pub fn ResetPasswordPage() -> impl IntoView {
    let params = use_params::<ResetTokenParams>();
    let token = move || params.with(|r| r.as_ref().ok().map(|p| p.token.clone()));

    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let done = RwSignal::new(false);
    let submitting = RwSignal::new(false);

    let submit = move |_| {
        if submitting.get_untracked() {
            return;
        }
        let Some(tok) = token() else {
            error.set(Some("invalid reset link".into()));
            return;
        };
        let pw = password.get();
        let cf = confirm.get();
        if pw.len() < 8 {
            error.set(Some("password must be at least 8 characters".into()));
            return;
        }
        if pw != cf {
            error.set(Some("passwords do not match".into()));
            return;
        }
        submitting.set(true);
        error.set(None);
        spawn_local(async move {
            match reset_password(tok, pw).await {
                Ok(_) => {
                    done.set(true);
                    error.set(None);
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            submitting.set(false);
        });
    };

    view! {
        <main class="mx-auto max-w-sm p-8">
            <h1 class="text-2xl font-bold">"Set a new password"</h1>

            {move || {
                if done.get() {
                    view! {
                        <div class="mt-6 space-y-4">
                            <p class="text-green-400">"Password updated."</p>
                            <p class="text-sm text-neutral-400">
                                "You have been signed out of all sessions. Sign in with your new password."
                            </p>
                            <a class="btn inline-block" href="/login">"Go to login"</a>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="mt-6 space-y-4">
                            <input
                                class="input"
                                type="password"
                                placeholder="New password (min 8 characters)"
                                bind:value=password
                            />
                            <input
                                class="input"
                                type="password"
                                placeholder="Confirm new password"
                                bind:value=confirm
                            />
                            <button class="btn" on:click=submit>"Update password"</button>
                        </div>
                    }.into_any()
                }
            }}

            {move || error.get().map(|e| view! { <p class="mt-4 text-red-400">{e}</p> })}
        </main>
    }
}