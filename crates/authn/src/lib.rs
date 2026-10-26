//! Механизм аутентификации: Argon2, JWT, register/login/verify_token/issue_token.
//!
//! Крейт использует `identity` для доступа к таблице `users`, но сам владеет
//! хэшированием паролей и выпуском/проверкой JWT. Cookie, HTTP, Leptos и
//! Casbin сюда не входят — это ответственность `app` / `authz`.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use chrono::{Duration, Utc};
use domain::AuthUser;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use identity::{IdentityError, UserRecord};

#[derive(Debug, thiserror::Error)]
pub enum AuthnError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("token invalid")]
    TokenInvalid,
    #[error("token expired")]
    TokenExpired,
    #[error("internal authentication error: {0}")]
    Internal(String),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    exp: i64,
}

const TOKEN_TTL_DAYS: i64 = 7;

pub struct Authn {
    pool: PgPool,
    jwt_secret: String,
}

impl Authn {
    pub fn new(pool: PgPool, jwt_secret: impl Into<String>) -> Self {
        Self {
            pool,
            jwt_secret: jwt_secret.into(),
        }
    }

    pub async fn register(&self, email: &str, password: &str) -> Result<AuthUser, AuthnError> {
        identity::validate_email(email)?;
        identity::validate_password(password)?;

        let hash = hash_password(password)?;
        let user = identity::create_user(&self.pool, email, &hash).await?;
        Ok(user)
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<AuthUser, AuthnError> {
        let record: UserRecord = identity::find_by_email(&self.pool, email)
            .await?
            .ok_or(AuthnError::InvalidCredentials)?;

        let parsed =
            PasswordHash::new(&record.password_hash).map_err(|_| AuthnError::InvalidCredentials)?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| AuthnError::InvalidCredentials)?;

        Ok(record.into())
    }

    pub fn issue_token(&self, user: &AuthUser) -> Result<String, AuthnError> {
        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            exp: (Utc::now() + Duration::days(TOKEN_TTL_DAYS)).timestamp(),
        };

        jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthnError::Internal(e.to_string()))
    }

    /// Контракт (handoff §8):
    /// - подпись/exp невалидны → `Err(TokenInvalid|TokenExpired)`;
    /// - отсутствует `sub` или `sub` — не UUID → `Ok(None)`;
    /// - пользователь удалён → `Ok(None)`;
    /// - БД недоступна → `Err(Db)`.
    pub async fn verify_token(&self, token: &str) -> Result<Option<AuthUser>, AuthnError> {
        let data = match jsonwebtoken::decode::<serde_json::Value>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        ) {
            Ok(d) => d,
            Err(e) => {
                return match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        Err(AuthnError::TokenExpired)
                    }
                    _ => Err(AuthnError::TokenInvalid),
                };
            }
        };

        let Some(sub) = data.claims.get("sub").and_then(|v| v.as_str()) else {
            return Ok(None);
        };

        let id: Uuid = match sub.parse() {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };

        let user = identity::find_by_id(&self.pool, id).await?;
        Ok(user)
    }
}

pub fn hash_password(password: &str) -> Result<String, AuthnError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthnError::Internal(e.to_string()))
}