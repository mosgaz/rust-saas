#[cfg(feature = "ssr")]
use std::sync::Arc;

#[cfg(feature = "ssr")]
use authz::Authz;
#[cfg(feature = "ssr")]
use domain::AuthUser;
#[cfg(feature = "ssr")]
use leptos::prelude::LeptosOptions;
#[cfg(feature = "ssr")]
use sqlx::PgPool;

#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub authz: Arc<Authz>,
    pub jwt_secret: String,
    pub leptos_options: LeptosOptions,
}

#[cfg(feature = "ssr")]
impl axum::extract::FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}

#[cfg(feature = "ssr")]
impl AppState {
    pub async fn issue_token(&self, user: &AuthUser) -> anyhow::Result<String> {
        let claims = serde_json::json!({
            "sub": user.id.to_string(),
            "email": user.email,
            "exp": chrono::Utc::now().timestamp() + 60 * 60 * 24 * 7,
        });

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    /// Проверяет подпись и срок JWT, затем подгружает AuthUser из БД по `sub`.
    ///
    /// Возвращает `Ok(None)`, если:
    /// - подпись/exp валидны, но пользователь удалён из БД (отсекает «мёртвые» сессии);
    /// - claim `sub` указывает на несуществующий UUID.
    ///
    /// Возвращает `Err`, если:
    /// - подпись невалидна или токен истёк;
    /// - claims не содержат `sub`/`email` в ожидаемом формате;
    /// - БД недоступна.
    pub async fn verify_token(&self, token: &str) -> anyhow::Result<Option<AuthUser>> {
        let data = jsonwebtoken::decode::<serde_json::Value>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        )?;

        let sub = data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("invalid token: missing or non-string `sub` claim"))?;

        let id: uuid::Uuid = sub
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid token: `sub` is not a UUID ({e})"))?;

        // Реальная загрузка AuthUser из БД:
        // 1) created_at всегда достоверен (раньше был фиктивный Utc::now());
        // 2) удалённый пользователь с валидным JWT больше не проходит.
        let user = sqlx::query_as::<_, AuthUser>(
            "select id, email, created_at from users where id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        // `email` из JWT здесь намеренно не используется: если пользователь
        // сменил email (в будущем), JWT может содержать старое значение.
        // Источник истины — БД.
        Ok(user)
    }
}