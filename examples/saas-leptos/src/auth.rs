use domain::AuthUser;
use leptos::prelude::*;

#[cfg(feature = "ssr")]
use axum::http::HeaderValue;
#[cfg(feature = "ssr")]
use leptos_axum::extract;

#[server]
pub async fn register(email: String, password: String) -> Result<AuthUser, ServerFnError> {
    use axum_extra::extract::cookie::Cookie;

    let state = expect_context::<crate::state::AppState>();

    let user = state
        .authn
        .register(&email, &password)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let token = state
        .authn
        .issue_token(&user)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

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
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let token = state
        .authn
        .issue_token(&user)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let cookie = Cookie::build(("session", token)).path("/").http_only(true);

    let response = expect_context::<leptos_axum::ResponseOptions>();
    let header = HeaderValue::from_str(&cookie.to_string())
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    response.append_header(axum::http::header::SET_COOKIE, header);

    Ok(user)
}

#[server]
pub async fn current_user() -> Result<Option<AuthUser>, ServerFnError> {
    let state = expect_context::<crate::state::AppState>();
    let jar = extract::<axum_extra::extract::cookie::CookieJar>().await?;

    let Some(token) = jar.get("session").map(|c| c.value().to_string()) else {
        return Ok(None);
    };

    state
        .authn
        .verify_token(&token)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}