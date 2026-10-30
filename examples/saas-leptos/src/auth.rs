//! Server functions for registration, login, refresh, logout, email
//! verification (Stage 3b), and post-auth return-URL preservation (Stage 3a).
//!
//! All delegate to `authn::*`. Cookies are managed by the example, not by
//! `authn`:
//!
//! - `access_token` — short-lived JWT (default TTL 15 min).
//! - `refresh_token` — opaque, rotation with family revocation (default TTL
//!   30 days).
//!
//! Cookie attributes in the MVP: `path = "/"`, `http_only = true`.
//! `Secure` / `SameSite` are Stage 4. Session cookies (no `Max-Age`) — the
//! browser keeps them until close; persistence is Stage 4.
//!
//! Stage 3a: `set_return_url` / `take_return_url`. Flow: an anonymous
//! user lands on `/invitations/:token` → `set_return_url` stores the path in
//! the `return_url` cookie → login or registration → `take_return_url` reads
//! and removes it → the client navigates there. Both server functions are
//! deliberately **unauthenticated**: the cookie may be set before login and
//! consumed immediately after, with no `CurrentUser` yet.
//!
//! Stage 3b:
//! - `register` now returns `(AuthUser, EmailResult)`: the account is
//!   created and tokens are issued regardless of the email outcome; the
//!   verification email is best-effort. The UI shows "sent" / "failed, retry?"
//!   / "disabled (no SMTP)" on `RegisterPage`.
//! - `request_email_verification` issues a fresh token (single-active;
//!   replaces any unused one) and sends the link. Rate limited to
//!   `3 / 1h` per email via `AppState.rate_limit`; the 4th call in the
//!   window returns HTTP 429.
//! - `verify_email(token)` is **public** (no `CurrentUser::require`): the
//!   link is clicked from the email, possibly in an anonymous browser. It is
//!   idempotent (already-verified → `Ok`) and does **not** log the user in.
//!
//! Errors are mapped to HTTP status codes by `crate::error`
//! (`authn_error_to_server_fn`, `rate_limited_error`).

use domain::AuthUser;
use leptos::prelude::*;

use crate::email::EmailResult;

#[cfg(feature = "ssr")]
use axum::http::HeaderValue;
#[cfg(feature = "ssr")]
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

// ─── Stage 3a: return-URL cookie helpers (SSR-only) ─────────────────────────

/// Cookie name for the post-auth return URL (Stage 3a). Session cookie
/// (`httpOnly`, `SameSite=Lax`, `Path=/`; **no `Secure`** — Stage 4 adds it
/// together with the other auth cookies).
#[cfg(feature = "ssr")]
pub const RETURN_URL_COOKIE: &str = "return_url";

/// Builds the `return_url` cookie. `SameSite=Lax` so it travels on the
/// top-level navigation to `/login` (POST body is same-origin; Lax suffices).
#[cfg(feature = "ssr")]
fn return_url_cookie(url: String) -> Cookie<'static> {
    Cookie::build((RETURN_URL_COOKIE, url))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

/// Returns `true` iff `s` is a safe internal path for a post-auth redirect.
///
/// Checks (all must pass):
/// - starts with `/`, does **not** start with `//` (protocol-relative →
///   open redirect to another host);
/// - no `;`, `,`, `"`, `\`, or whitespace (cookie-header safety; `;`/`,`
///   would split `Set-Cookie` on the wire, `\` and whitespace are used in
///   Windows-path / header-injection tricks);
/// - no `:` before the first `?`/`#` (scheme prefix — defense in depth; the
///   leading `/` already prevents it, but rejecting it is harmless);
/// - does not start with `/login` or `/register` (returning to the login
///   page after login is a loop; **starts_with**, not equality, so
///   `/login?x=1` and `/register/foo` are also rejected).
#[cfg(feature = "ssr")]
fn is_safe_return_url(s: &str) -> bool {
    if !s.starts_with('/') || s.starts_with("//") {
        return false;
    }
    if s.chars().any(|c| {
        c.is_whitespace() || c == ';' || c == ',' || c == '"' || c == '\\'
    }) {
        return false;
    }
    let after = &s[1..];
    let head = after.split(['?', '#']).next().unwrap_or(after);
    if head.contains(':') {
        return false;
    }
    if s.starts_with("/login") || s.starts_with("/register") {
        return false;
    }
    true
}

#[cfg(feature = "ssr")]
fn append_cookie(
    response: &leptos_axum::ResponseOptions,
    c: Cookie<'static>,
) -> Result<(), ServerFnError> {
    let header = HeaderValue::from_str(&c.to_string())
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    response.append_header(axum::http::header::SET_COOKIE, header);
    Ok(())
}

// ─── register / login / refresh / logout ────────────────────────────────────

/// Registers a new user, issues access + refresh tokens, sets both cookies,
/// and attempts to send the verification email (best-effort).
///
/// The verification email is sent **after** cookies are set: registration
/// succeeds even if SMTP is down. `EmailResult` in the return value tells
/// the UI which of `Sent` / `Failed` / `Disabled` to render on
/// `RegisterPage`.
#[server]
pub async fn register(
    email: String,
    password: String,
) -> Result<(AuthUser, EmailResult), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = state
        .authn
        .register(&email, &password)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;

    let access = state
        .authn
        .issue_access_token(&user)
        .map_err(crate::error::authn_error_to_server_fn)?;
    let refresh = state
        .authn
        .issue_refresh_token(&user)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;

    let response = expect_context::<leptos_axum::ResponseOptions>();
    append_cookie(&response, crate::middleware::access_cookie(access))?;
    append_cookie(&response, crate::middleware::refresh_cookie(refresh))?;

    // Best-effort verification email. `AlreadyVerified` here would mean the
    // user is already verified right after `create_user` (unreachable in
    // practice — `email_verified_at` is NULL on insert). Log and skip.
    let email_result = match state.authn.create_email_verification(user.id).await {
        Ok(token) => state.email.send_verification(&user.email, &token).await,
        Err(authn::AuthnError::AlreadyVerified) => {
            tracing::error!(
                user_id = %user.id,
                "register: user already verified immediately after creation; skipping verification email"
            );
            EmailResult::Disabled
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                user_id = %user.id,
                "register: create_email_verification failed; verification email not sent"
            );
            EmailResult::Failed {
                reason: e.to_string(),
            }
        }
    };

    Ok((user, email_result))
}

/// Logs in an existing user, issues access + refresh tokens, sets both cookies.
#[server]
pub async fn login(email: String, password: String) -> Result<AuthUser, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();

    let user = state
        .authn
        .login(&email, &password)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;

    let access = state
        .authn
        .issue_access_token(&user)
        .map_err(crate::error::authn_error_to_server_fn)?;
    let refresh = state
        .authn
        .issue_refresh_token(&user)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;

    let response = expect_context::<leptos_axum::ResponseOptions>();
    append_cookie(&response, crate::middleware::access_cookie(access))?;
    append_cookie(&response, crate::middleware::refresh_cookie(refresh))?;

    Ok(user)
}

/// Returns the current authenticated user, if any.
///
/// After auto-refresh middleware has run for this request, the user reflects
/// the post-rotation state. On the client, callers usually follow this with a
/// page reload so that new cookies take effect across subsequent requests.
#[server]
pub async fn refresh() -> Result<AuthUser, ServerFnError> {
    let user = crate::extract::CurrentUser::from_request().await?.require()?;
    Ok(user)
}

/// Clears both cookies and revokes the refresh-token family in the database.
///
/// Access token stays valid until its short `exp`; refresh-token family is
/// revoked (`revoked_reason = "logout"`), so the session cannot be extended.
#[server]
pub async fn logout() -> Result<(), ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let jar = leptos_axum::extract::<CookieJar>().await?;

    if let Some(raw) = jar
        .get(crate::middleware::REFRESH_COOKIE)
        .map(|c| c.value().to_string())
    {
        state
            .authn
            .revoke_refresh_token(&raw)
            .await
            .map_err(crate::error::authn_error_to_server_fn)?;
    }

    let response = expect_context::<leptos_axum::ResponseOptions>();
    append_cookie(
        &response,
        crate::middleware::removal_cookie(crate::middleware::ACCESS_COOKIE),
    )?;
    append_cookie(
        &response,
        crate::middleware::removal_cookie(crate::middleware::REFRESH_COOKIE),
    )?;

    Ok(())
}

// ─── Stage 3b: email verification ───────────────────────────────────────────

/// Issues a fresh email-verification token for the current user and sends
/// the link. Replaces any unused previous token (single-active).
///
/// Rate limited to `3 / 1h` per user email
/// (`AppState.rate_limit::try_acquire`); the 4th request in the window
/// returns HTTP 429 with the number of seconds until the window frees a
/// slot.
///
/// Returns `EmailResult` (`Sent` / `Failed` / `Disabled`) — transport
/// failures are not `ServerFnError`s; they surface in the UI so the user
/// can retry. `authn::AuthnError::AlreadyVerified` (user already verified)
/// maps to HTTP 409 via `authn_error_to_server_fn`.
#[server]
pub async fn request_email_verification() -> Result<EmailResult, ServerFnError> {
    use std::time::Duration;

    let state = expect_context::<crate::state::AppState>();
    let user = crate::extract::CurrentUser::from_request().await?.require()?;

    if let Err(retry_after) = state
        .rate_limit
        .try_acquire(&user.email, 3, Duration::from_secs(3600))
    {
        return Err(crate::error::rate_limited_error(retry_after));
    }

    let token = state
        .authn
        .create_email_verification(user.id)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;

    Ok(state.email.send_verification(&user.email, &token).await)
}

/// Verifies an email address by raw token from the `/verify/:token` link.
///
/// **Public** (no `CurrentUser::require`): the link is clicked from an
/// email, possibly in an anonymous browser session. Idempotent — already-
/// verified users get `Ok(AuthUser)`; the original
/// `users.email_verified_at` is preserved. Does **not** log the user in;
/// `VerifyEmailPage` prompts them to sign in afterwards.
#[server]
pub async fn verify_email(token: String) -> Result<AuthUser, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let user = state
        .authn
        .verify_email(&token)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;
    Ok(user)
}

// ─── Stage 3a: return-URL preservation ──────────────────────────────────────

/// Stores `url` in the `return_url` cookie for the post-auth redirect.
///
/// Silent no-op on an unsafe URL — no `400`, so the caller cannot use this
/// server function to probe which paths are considered safe.
///
/// Does **not** require an authenticated user: the cookie is set before the
/// login / registration page renders.
#[server]
pub async fn set_return_url(url: String) -> Result<(), ServerFnError> {
    if !is_safe_return_url(&url) {
        return Ok(());
    }
    let Some(response) = use_context::<leptos_axum::ResponseOptions>() else {
        return Ok(());
    };
    append_cookie(&response, return_url_cookie(url))
}

/// Reads and removes the `return_url` cookie. Returns `Ok(None)` if absent or
/// unsafe. Always issues a removal `Set-Cookie` (idempotent), so a stale URL
/// cannot be reused after one redirect.
///
/// Does **not** require an authenticated user: it is called right after
/// login / registration, and the cookie may have been set while anonymous.
#[server]
pub async fn take_return_url() -> Result<Option<String>, ServerFnError> {
    let jar = leptos_axum::extract::<CookieJar>().await?;
    let raw = jar.get(RETURN_URL_COOKIE).map(|c| c.value().to_string());

    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        append_cookie(
            &response,
            crate::middleware::removal_cookie(RETURN_URL_COOKIE),
        )?;
    }

    Ok(raw.filter(|s| is_safe_return_url(s)))
}