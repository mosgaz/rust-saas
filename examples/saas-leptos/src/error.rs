//! Typed mapping of library crate errors into `ServerFnError` with HTTP
//! status codes.
//!
//! Mapping:
//! - `Validation` (Core / Identity)                         -> 400
//! - `Unauthorized`, `InvalidCredentials`, `TokenInvalid`, `TokenExpired` -> 401
//! - `Forbidden`                                            -> 403
//! - `NotFound` (Core / Identity)                           -> 404
//! - `DuplicateEmail` (Identity)                            -> 409
//! - `Internal`, `Db`                                       -> 500
//!
//! The body of `ServerFnError` is the error's `Display` string. The HTTP
//! status is set via `leptos_axum::ResponseOptions` before the `#[server]`
//! function returns. If the `ResponseOptions` context is unavailable (unit
//! test, not a `#[server]` call), the status is not set and the same
//! `ServerFnError` is returned.
//!
//! Stage 2a (`saas::invitation::*`) reuses the existing variants:
//! - `accept_invitation` returns `CoreError::NotFound` for a token that does
//!   not match any active invitation (does not exist, revoked, expired, or
//!   exhausted) — mapped to HTTP 404. The specific reason is intentionally
//!   not distinguished, to avoid leaking invitation state.
//! - `create_invitation` returns `CoreError::Validation` for an invalid
//!   `role`/`ttl_hours`/`max_uses` — HTTP 400.
//! - `create/revoke/list_invitations` return `CoreError::Forbidden` when
//!   `authz.require` denies — HTTP 403.
//! No new `CoreError` variant was introduced in Stage 2a.

use leptos::prelude::*;

use authn::AuthnError;
use identity::IdentityError;
use saas::CoreError;

fn status_for_core(e: &CoreError) -> u16 {
    match e {
        CoreError::Validation(_) => 400,
        CoreError::Unauthorized => 401,
        CoreError::Forbidden => 403,
        CoreError::NotFound => 404,
        CoreError::Internal(_) | CoreError::Db(_) => 500,
    }
}

fn status_for_identity(e: &IdentityError) -> u16 {
    match e {
        IdentityError::Validation(_) => 400,
        IdentityError::NotFound => 404,
        IdentityError::DuplicateEmail => 409,
        IdentityError::Db(_) => 500,
    }
}

fn status_for_authn(e: &AuthnError) -> u16 {
    match e {
        AuthnError::InvalidCredentials => 401,
        AuthnError::TokenInvalid | AuthnError::TokenExpired => 401,
        AuthnError::Internal(_) => 500,
        AuthnError::Identity(inner) => status_for_identity(inner),
        AuthnError::Db(_) => 500,
    }
}

fn set_status(status: u16) {
    let Some(response) = use_context::<leptos_axum::ResponseOptions>() else {
        return;
    };
    let code = axum::http::StatusCode::from_u16(status)
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    response.set_status(code);
}

/// Maps `saas::CoreError` into `ServerFnError` with the corresponding HTTP code.
pub fn core_error_to_server_fn(e: CoreError) -> ServerFnError {
    set_status(status_for_core(&e));
    ServerFnError::new(e.to_string())
}

/// Maps `authn::AuthnError` into `ServerFnError` with the corresponding HTTP code.
pub fn authn_error_to_server_fn(e: AuthnError) -> ServerFnError {
    set_status(status_for_authn(&e));
    ServerFnError::new(e.to_string())
}

/// `ServerFnError` with HTTP 401 for "no authenticated user".
pub fn unauthorized_error() -> ServerFnError {
    set_status(401);
    ServerFnError::new("unauthorized")
}