//! `CurrentUser` — текущий пользователь из cookie `session`.
//!
//! Поверх `authn::verify_token` (контракт: `Ok(None)` для удалённого
//! пользователя и невалидного `sub`; `Err` для невалидной подписи/exp).
//! Заменяет ручной `current_user().await?.ok_or_else(...)` в `#[server]`-функциях.
//!
//! Не реализован как `axum::FromRequestParts`, чтобы не тянуть `async-trait`
//! в зависимости примера; вызывается в начале каждого `#[server]`-fn:
//!
//! ```ignore
//! let user = crate::extract::CurrentUser::from_request().await?.require()?;
//! ```

use domain::AuthUser;
use leptos::prelude::*;

pub struct CurrentUser(pub Option<AuthUser>);

impl CurrentUser {
    /// Загружает текущего пользователя из cookie `session` в текущем запросе.
    /// `Ok(Self(None))` — нет cookie либо токен невалиден/просрочен/удалён.
    pub async fn from_request() -> Result<Self, ServerFnError> {
        use axum_extra::extract::cookie::CookieJar;
        use leptos_axum::extract;

        let state = expect_context::<crate::state::AppState>();
        let jar = extract::<CookieJar>().await?;

        let Some(token) = jar.get("session").map(|c| c.value().to_string()) else {
            return Ok(Self(None));
        };

        let user = state
            .authn
            .verify_token(&token)
            .await
            .map_err(crate::error::authn_error_to_server_fn)?;

        Ok(Self(user))
    }

    /// Требует аутентифицированного пользователя. Возвращает `ServerFnError`
    /// с HTTP 401, если cookie нет или токен невалиден.
    pub fn require(self) -> Result<AuthUser, ServerFnError> {
        self.0.ok_or_else(crate::error::unauthorized_error)
    }
}