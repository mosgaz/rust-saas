//! Server functions for registration, login, refresh, logout, and (Stage 3a)
//! post-auth return-URL preservation.
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
//! Stage 3a adds `set_return_url` / `take_return_url`. Flow: an anonymous
//! user lands on `/invitations/:token` → `set_return_url` stores the path in
//! the `return_url` cookie → login or registration → `take_return_url` reads
//! and removes it → the client navigates there. Both server functions are
//! deliberately **unauthenticated**: the cookie may be set before login and
//! consumed immediately after, with no `CurrentUser` yet.
//!
//! Errors are mapped to HTTP status codes by `crate::error`
//! (`authn_error_to_server_fn`).

use domain::AuthUser;
use leptos::prelude::*;

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

/// Registers a new user, issues access + refresh tokens, and sets both cookies.
#[server]
pub async fn register(email: String, password: String) -> Result<AuthUser, ServerFnError> {
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

    Ok(user)
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
/// revoked, so the session cannot be extended.
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