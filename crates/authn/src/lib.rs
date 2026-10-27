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

#[cfg(test)]
mod tests {
    //! Unit-тесты `authn` без реальной БД.
    //!
    //! `PgPool::connect_lazy` создаёт пул без установления соединения.
    //! Все сценарии ниже либо не доходят до БД (невалидный/отсутствующий `sub`),
    //! либо работают только с JWT-операциями в памяти.
    //!
    //! `verify_token` для существующего/удалённого пользователя и
    //! `register`/`login` — integration-тесты, требуют БД (см. handoff §17).

    use super::*;
    use serde_json::json;

    fn lazy_pool() -> PgPool {
        // Реальное соединение не открывается; при deny-ветках до БД дело не доходит.
        PgPool::connect_lazy("postgres://authn-test-host/authn_test")
            .expect("lazy pool must be constructible")
    }

    fn authn(secret: &str) -> Authn {
        Authn::new(lazy_pool(), secret)
    }

    fn sample_user() -> AuthUser {
        AuthUser {
            id: Uuid::new_v4(),
            email: "user@example.test".to_string(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn hash_password_produces_valid_argon2_hash() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).expect("hashing must succeed");
        assert!(hash.starts_with("$argon2"), "must be Argon2 PHC string: {hash}");

        let parsed = PasswordHash::new(&hash).expect("hash must be parseable");
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .expect("verify must succeed for original password");
    }

    #[test]
    fn hash_password_uses_random_salt() {
        let password = "same-password";
        let h1 = hash_password(password).expect("hashing must succeed");
        let h2 = hash_password(password).expect("hashing must succeed");
        assert_ne!(h1, h2, "hash must use random salt");
    }

    #[test]
    fn hash_password_rejects_wrong_password() {
        let hash = hash_password("real").expect("hashing must succeed");
        let parsed = PasswordHash::new(&hash).expect("hash must be parseable");
        assert!(
            Argon2::default()
                .verify_password(b"wrong", &parsed)
                .is_err(),
            "verify must fail for wrong password"
        );
    }

    #[tokio::test]
    async fn issue_token_is_three_part_jwt() {
        let user = sample_user();
        let token = authn("secret").issue_token(&user).expect("issue must succeed");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have three parts: {token}");
        assert!(parts.iter().all(|p| !p.is_empty()), "no JWT part may be empty");
    }

    #[tokio::test]
    async fn issue_token_claims_contain_sub_email_exp() {
        let user = sample_user();
        let secret = "secret-for-claims-test";
        let token = authn(secret).issue_token(&user).expect("issue must succeed");

        let data = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .expect("token must decode with issuing secret");

        let claims = data.claims;
        let expected_sub = user.id.to_string();
        assert_eq!(
            claims.get("sub").and_then(|v| v.as_str()),
            Some(expected_sub.as_str()),
        );
        assert_eq!(
            claims.get("email").and_then(|v| v.as_str()),
            Some(user.email.as_str()),
        );
        let exp = claims
            .get("exp")
            .and_then(|v| v.as_i64())
            .expect("exp must be an integer");
        assert!(exp > Utc::now().timestamp(), "exp must be in the future");
    }

    #[tokio::test]
    async fn verify_token_rejects_wrong_signature() {
        let user = sample_user();
        let token = authn("issuer-secret")
            .issue_token(&user)
            .expect("issue must succeed");
        let verifier = authn("different-secret");

        let err = verifier
            .verify_token(&token)
            .await
            .expect_err("verify must reject");
        assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");
    }

    #[tokio::test]
    async fn verify_token_rejects_expired() {
        let secret = "expired-test-secret";
        let claims = json!({
            "sub": Uuid::new_v4().to_string(),
            "email": "x@example.test",
            // 1 hour in the past; default leeway is 60s.
            "exp": Utc::now().timestamp() - 3600,
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode must succeed");

        let err = authn(secret)
            .verify_token(&token)
            .await
            .expect_err("verify must reject");
        assert!(matches!(err, AuthnError::TokenExpired), "got {err:?}");
    }

    #[tokio::test]
    async fn verify_token_returns_none_for_non_uuid_sub() {
        let secret = "non-uuid-sub-secret";
        let claims = json!({
            "sub": "not-a-uuid",
            "email": "x@example.test",
            "exp": Utc::now().timestamp() + 3600,
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode must succeed");

        let result = authn(secret)
            .verify_token(&token)
            .await
            .expect("verify must not error");
        assert!(result.is_none(), "non-UUID sub must yield Ok(None)");
    }

    #[tokio::test]
    async fn verify_token_returns_none_for_missing_sub() {
        let secret = "missing-sub-secret";
        let claims = json!({
            "email": "x@example.test",
            "exp": Utc::now().timestamp() + 3600,
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode must succeed");

        let result = authn(secret)
            .verify_token(&token)
            .await
            .expect("verify must not error");
        assert!(result.is_none(), "missing sub must yield Ok(None)");
    }

    #[tokio::test]
    async fn verify_token_rejects_garbage() {
        let err = authn("secret")
            .verify_token("not.a.jwt")
            .await
            .expect_err("verify must reject");
        assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");
    }
}