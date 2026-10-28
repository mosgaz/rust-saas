//! Server functions for registration, login, refresh, and logout.
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
//! Errors are mapped to HTTP status codes by `crate::error`
//! (`authn_error_to_server_fn`).

use domain::AuthUser;
use leptos::prelude::*;

#[cfg(feature = "ssr")]
use axum::http::HeaderValue;

#[cfg(feature = "ssr")]
fn append_cookie(response: &leptos_axum::ResponseOptions, c: axum_extra::extract::cookie::Cookie<'static>) -> Result<(), ServerFnError> {
    let header = HeaderValue::from_str(&c.to_string())
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    response.append_header(axum::http::header::SET_COOKIE, header);
    Ok(())
}

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
    use axum_extra::extract::cookie::CookieJar;

    let state = expect_context::<crate::state::AppState>();
    let jar = leptos_axum::extract::<CookieJar>().await?;

    if let Some(raw) = jar.get(crate::middleware::REFRESH_COOKIE).map(|c| c.value().to_string()) {
        state
            .authn
            .revoke_refresh_token(&raw)
            .await
            .map_err(crate::error::authn_error_to_server_fn)?;
    }

    let response = expect_context::<leptos_axum::ResponseOptions>();
    append_cookie(&response, crate::middleware::removal_cookie(crate::middleware::ACCESS_COOKIE))?;
    append_cookie(&response, crate::middleware::removal_cookie(crate::middleware::REFRESH_COOKIE))?;

    Ok(())
}