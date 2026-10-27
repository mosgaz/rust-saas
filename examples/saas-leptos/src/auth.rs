use domain::AuthUser;
use leptos::prelude::*;

#[cfg(feature = "ssr")]
use axum::http::HeaderValue;

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

/// Текущий пользователь из cookie `session`.
///
/// Тонкая обёртка над `crate::extract::CurrentUser::from_request()`; сигнатура
/// сохранена для обратной совместимости с `pages/*.rs`. Маппинг ошибок —
/// типизированный (`AuthnError` → HTTP-код через `crate::error`).
#[server]
pub async fn current_user() -> Result<Option<AuthUser>, ServerFnError> {
    let current = crate::extract::CurrentUser::from_request().await?;
    Ok(current.0)
}