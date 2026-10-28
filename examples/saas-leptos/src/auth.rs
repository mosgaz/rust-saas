//! Server functions for user registration and login.
//!
//! Both functions delegate to `authn::*`, issue a session JWT, and set it
//! as an `httpOnly` cookie named `session`. Cookie attributes are the
//! consumer's responsibility: the current MVP sets `path = "/"` and
//! `http_only = true`, but not `Secure` or `SameSite` (see handoff §16).
//!
//! Errors are mapped to HTTP status codes by `crate::error`
//! (`authn_error_to_server_fn`).

use domain::AuthUser;
use leptos::prelude::*;

#[cfg(feature = "ssr")]
use axum::http::HeaderValue;

/// Registers a new user, issues a session JWT, and sets the `session` cookie.
///
/// Delegates to `authn::Authn::register` and `authn::Authn::issue_token`.
/// On success returns the created `AuthUser`; the caller's browser receives
/// a `Set-Cookie` header via `leptos_axum::ResponseOptions`.
#[server]
pub async fn register(email: String, password: String) -> Result<AuthUser, ServerFnError> {
    use axum_extra::extract::cookie::Cookie;

    let state = expect_context::<crate::state::AppState>();

    let user = state
        .authn
        .register(&email, &password)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;

    let token = state
        .authn
        .issue_token(&user)
        .map_err(crate::error::authn_error_to_server_fn)?;

    let cookie = Cookie::build(("session", token)).path("/").http_only(true);

    let response = expect_context::<leptos_axum::ResponseOptions>();
    let header = HeaderValue::from_str(&cookie.to_string())
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    response.append_header(axum::http::header::SET_COOKIE, header);

    Ok(user)
}

/// Logs in an existing user, issues a session JWT, and sets the `session` cookie.
///
/// Delegates to `authn::Authn::login` and `authn::Authn::issue_token`.
/// On success returns the authenticated `AuthUser`; the caller's browser
/// receives a `Set-Cookie` header via `leptos_axum::ResponseOptions`.
#[server]
pub async fn login(email: String, password: String) -> Result<AuthUser, ServerFnError> {
    use axum_extra::extract::cookie::Cookie;

    let state = expect_context::<crate::state::AppState>();

    let user = state
        .authn
        .login(&email, &password)
        .await
        .map_err(crate::error::authn_error_to_server_fn)?;

    let token = state
        .authn
        .issue_token(&user)
        .map_err(crate::error::authn_error_to_server_fn)?;

    let cookie = Cookie::build(("session", token)).path("/").http_only(true);

    let response = expect_context::<leptos_axum::ResponseOptions>();
    let header = HeaderValue::from_str(&cookie.to_string())
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    response.append_header(axum::http::header::SET_COOKIE, header);

    Ok(user)
}