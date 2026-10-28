//! Authentication mechanism: Argon2, JWT access tokens, and opaque refresh
//! tokens with rotation and family revocation.
//!
//! Uses `identity` for the `users` table, but owns password hashing, JWT
//! issuing/verification, and the `refresh_tokens` table. Cookies, HTTP,
//! Leptos, and Casbin are not part of this crate — that is the consumer's
//! responsibility.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use chrono::{DateTime, Duration, Utc};
use domain::AuthUser;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use identity::{IdentityError, UserRecord};

/// Default access-token lifetime (Stage 2b). Can be overridden per instance
/// via [`Authn::with_ttl`].
pub const DEFAULT_ACCESS_TTL_MINUTES: i64 = 15;

/// Default refresh-token lifetime (Stage 2b).
pub const DEFAULT_REFRESH_TTL_DAYS: i64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum AuthnError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("token invalid")]
    TokenInvalid,
    #[error("token expired")]
    TokenExpired,
    /// Refresh token not found, revoked, or expired (Stage 2b).
    #[error("refresh token invalid")]
    RefreshInvalid,
    /// A previously used refresh token was presented; the whole family was
    /// revoked as a compromise signal (Stage 2b).
    #[error("refresh token reused")]
    RefreshReused,
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

#[derive(Debug, sqlx::FromRow)]
struct RefreshTokenRecord {
    id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

pub struct Authn {
    pool: PgPool,
    jwt_secret: String,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl Authn {
    /// Builds an [`Authn`] with the default TTLs.
    pub fn new(pool: PgPool, jwt_secret: impl Into<String>) -> Self {
        Self::with_ttl(
            pool,
            jwt_secret,
            Duration::minutes(DEFAULT_ACCESS_TTL_MINUTES),
            Duration::days(DEFAULT_REFRESH_TTL_DAYS),
        )
    }

    /// Builds an [`Authn`] with explicit TTLs.
    pub fn with_ttl(
        pool: PgPool,
        jwt_secret: impl Into<String>,
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Self {
        Self {
            pool,
            jwt_secret: jwt_secret.into(),
            access_ttl,
            refresh_ttl,
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

    /// Issues a short-lived access JWT (Stage 2b).
    pub fn issue_access_token(&self, user: &AuthUser) -> Result<String, AuthnError> {
        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            exp: (Utc::now() + self.access_ttl).timestamp(),
        };

        jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthnError::Internal(e.to_string()))
    }

    /// Issues an opaque refresh token, stores its SHA-256 hash, returns raw.
    pub async fn issue_refresh_token(&self, user: &AuthUser) -> Result<String, AuthnError> {
        let raw = generate_refresh_token();
        let token_hash = hash_token(&raw);
        let family_id = Uuid::new_v4();
        let expires_at = Utc::now() + self.refresh_ttl;

        sqlx::query(
            r#"
            insert into refresh_tokens (user_id, token_hash, family_id, expires_at)
            values ($1, $2, $3, $4)
            "#,
        )
        .bind(user.id)
        .bind(&token_hash)
        .bind(family_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(raw)
    }

    /// Rotates a refresh token; reuse detection revokes the whole family.
    pub async fn rotate_refresh_token(
        &self,
        raw: &str,
    ) -> Result<(String, AuthUser), AuthnError> {
        let token_hash = hash_token(raw);
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query_as::<_, RefreshTokenRecord>(
            r#"
            select id, user_id, family_id, expires_at, used_at, revoked_at
            from refresh_tokens
            where token_hash = $1
            for update
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AuthnError::RefreshInvalid)?;

        if row.revoked_at.is_some() {
            return Err(AuthnError::RefreshInvalid);
        }

        if row.used_at.is_some() {
            sqlx::query(
                r#"
                update refresh_tokens
                set revoked_at = now()
                where family_id = $1 and revoked_at is null
                "#,
            )
            .bind(row.family_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(AuthnError::RefreshReused);
        }

        if row.expires_at <= Utc::now() {
            return Err(AuthnError::RefreshInvalid);
        }

        sqlx::query("update refresh_tokens set used_at = now() where id = $1")
            .bind(row.id)
            .execute(&mut *tx)
            .await?;

        let new_raw = generate_refresh_token();
        let new_hash = hash_token(&new_raw);
        let new_expires_at = Utc::now() + self.refresh_ttl;

        sqlx::query(
            r#"
            insert into refresh_tokens (user_id, token_hash, family_id, expires_at)
            values ($1, $2, $3, $4)
            "#,
        )
        .bind(row.user_id)
        .bind(&new_hash)
        .bind(row.family_id)
        .bind(new_expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let user = identity::find_by_id(&self.pool, row.user_id)
            .await?
            .ok_or(AuthnError::RefreshInvalid)?;

        Ok((new_raw, user))
    }

    /// Revokes the family of a refresh token (idempotent).
    pub async fn revoke_refresh_token(&self, raw: &str) -> Result<(), AuthnError> {
        let token_hash = hash_token(raw);

        let family_id: Option<Uuid> = sqlx::query_scalar(
            "select family_id from refresh_tokens where token_hash = $1",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(family_id) = family_id {
            self.revoke_family(family_id).await?;
        }
        Ok(())
    }

    /// Revokes every not-yet-revoked row in `family_id`.
    pub async fn revoke_family(&self, family_id: Uuid) -> Result<(), AuthnError> {
        sqlx::query(
            r#"
            update refresh_tokens
            set revoked_at = now()
            where family_id = $1 and revoked_at is null
            "#,
        )
        .bind(family_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Verifies an access JWT. Contract (handoff §9).
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

fn generate_refresh_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    //! Unit tests for `authn` that do not touch a real database.

    use super::*;
    use serde_json::json;

    fn lazy_pool() -> PgPool {
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
        let h1 = hash_password("same-password").expect("hashing must succeed");
        let h2 = hash_password("same-password").expect("hashing must succeed");
        assert_ne!(h1, h2, "hash must use random salt");
    }

    #[test]
    fn hash_password_rejects_wrong_password() {
        let hash = hash_password("real").expect("hashing must succeed");
        let parsed = PasswordHash::new(&hash).expect("hash must be parseable");
        assert!(Argon2::default().verify_password(b"wrong", &parsed).is_err());
    }

    #[test]
    fn hash_token_is_deterministic_hex64() {
        let raw = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let h1 = hash_token(raw);
        let h2 = hash_token(raw);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(h1, raw);
    }

    #[test]
    fn generate_refresh_token_is_hex64_and_unique() {
        let a = generate_refresh_token();
        let b = generate_refresh_token();
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn issue_access_token_is_three_part_jwt() {
        let user = sample_user();
        let token = authn("secret").issue_access_token(&user).expect("issue");
        assert_eq!(token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn issue_access_token_claims_contain_sub_email_exp() {
        let user = sample_user();
        let secret = "secret-for-claims-test";
        let token = authn(secret).issue_access_token(&user).expect("issue");

        let data = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .expect("decode");

        let claims = data.claims;
        assert_eq!(
            claims.get("sub").and_then(|v| v.as_str()),
            Some(user.id.to_string().as_str()),
        );
        assert_eq!(
            claims.get("email").and_then(|v| v.as_str()),
            Some(user.email.as_str()),
        );
        let exp = claims.get("exp").and_then(|v| v.as_i64()).expect("exp");
        assert!(exp > Utc::now().timestamp());
    }

    #[tokio::test]
    async fn verify_token_rejects_wrong_signature() {
        let user = sample_user();
        let token = authn("issuer-secret").issue_access_token(&user).expect("issue");
        let err = authn("different-secret")
            .verify_token(&token)
            .await
            .expect_err("verify must reject");
        assert!(matches!(err, AuthnError::TokenInvalid));
    }

    #[tokio::test]
    async fn verify_token_rejects_expired() {
        let secret = "expired-test-secret";
        let claims = json!({
            "sub": Uuid::new_v4().to_string(),
            "email": "x@example.test",
            "exp": Utc::now().timestamp() - 3600,
        });
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode");
        let err = authn(secret)
            .verify_token(&token)
            .await
            .expect_err("verify must reject");
        assert!(matches!(err, AuthnError::TokenExpired));
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
        .expect("encode");
        let result = authn(secret).verify_token(&token).await.expect("verify");
        assert!(result.is_none());
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
        .expect("encode");
        let result = authn(secret).verify_token(&token).await.expect("verify");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn verify_token_rejects_garbage() {
        let err = authn("secret")
            .verify_token("not.a.jwt")
            .await
            .expect_err("verify must reject");
        assert!(matches!(err, AuthnError::TokenInvalid));
    }
}