use domain::AuthUser;
use leptos::prelude::*;

#[cfg(feature = "ssr")]
use {
    argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier},
    axum::http::HeaderValue,
    leptos_axum::extract,
    // serde::Deserialize, // TODO: Claims
    // uuid::Uuid, // TODO: Claims
};

// TODO: Claims
// #[cfg(feature = "ssr")]
// #[derive(Debug, Deserialize)]
// struct Claims {
//     sub: Uuid,
//     email: String,
//     exp: usize,
// }

#[server]
pub async fn register(email: String, password: String) -> Result<AuthUser, ServerFnError> {
    use axum_extra::extract::cookie::Cookie;
    use axum_extra::extract::cookie::CookieJar;

    let state = expect_context::<crate::state::AppState>();
    let _jar = extract::<CookieJar>().await?;

    let password_hash = Argon2::default()
        .hash_password(
            password.as_bytes(),
            &argon2::password_hash::SaltString::generate(
                &mut argon2::password_hash::rand_core::OsRng,
            ),
        )
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .to_string();

    let user = sqlx::query_as::<_, AuthUser>(
        "insert into users (email, password_hash) values ($1, $2) returning id, email, created_at",
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ServerFnError::new(e.to_string()))?;

    let token = state
        .issue_token(&user)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let cookie = Cookie::build(("session", token)).path("/").http_only(true);

    let response = expect_context::<leptos_axum::ResponseOptions>();
    response.append_header(
        axum::http::header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );

    Ok(user)
}

#[server]
pub async fn login(email: String, password: String) -> Result<AuthUser, ServerFnError> {
    use axum_extra::extract::cookie::Cookie;
    use axum_extra::extract::cookie::CookieJar;

    let state = expect_context::<crate::state::AppState>();
    let _jar = extract::<CookieJar>().await?;

    let row = sqlx::query_as::<_, (uuid::Uuid, String, String)>(
        "select id, email, password_hash from users where email = $1",
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ServerFnError::new("invalid credentials"))?;

    let parsed = PasswordHash::new(&row.2).map_err(|e| ServerFnError::new(e.to_string()))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| ServerFnError::new("invalid credentials"))?;

    let user = AuthUser {
        id: row.0,
        email: row.1,
        created_at: chrono::Utc::now(),
    };

    let token = state
        .issue_token(&user)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let cookie = Cookie::build(("session", token)).path("/").http_only(true);

    let response = expect_context::<leptos_axum::ResponseOptions>();
    response.append_header(
        axum::http::header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );

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
        .verify_token(&token)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
