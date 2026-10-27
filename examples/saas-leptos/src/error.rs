//! Типизированный маппинг ошибок библиотечных крейтов в `ServerFnError`
//! с HTTP-кодами.
//!
//! Карта:
//! - `Validation` (Core / Identity)   → 400
//! - `Unauthorized`, `InvalidCredentials`, `TokenInvalid`, `TokenExpired` → 401
//! - `Forbidden`                      → 403
//! - `NotFound` (Core / Identity)     → 404
//! - `DuplicateEmail` (Identity)      → 409
//! - `Internal`, `Db`                 → 500
//!
//! Тело `ServerFnError` — текст ошибки; HTTP-код выставляется через
//! `leptos_axum::ResponseOptions` до возврата значения из `#[server]`-функции.
//! Если контекст `ResponseOptions` недоступен (unit-тест, не `#[server]`),
//! статус не выставляется, возвращается тот же `ServerFnError`.

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

/// Маппит `saas::CoreError` в `ServerFnError` с соответствующим HTTP-кодом.
pub fn core_error_to_server_fn(e: CoreError) -> ServerFnError {
    set_status(status_for_core(&e));
    ServerFnError::new(e.to_string())
}

/// Маппит `authn::AuthnError` в `ServerFnError` с соответствующим HTTP-кодом.
pub fn authn_error_to_server_fn(e: AuthnError) -> ServerFnError {
    set_status(status_for_authn(&e));
    ServerFnError::new(e.to_string())
}

/// `ServerFnError` с HTTP 401 — для случая «нет аутентифицированного пользователя».
pub fn unauthorized_error() -> ServerFnError {
    set_status(401);
    ServerFnError::new("unauthorized")
}