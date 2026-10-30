//! Authentication mechanism: Argon2, JWT access tokens, and opaque refresh
//! tokens with rotation and family revocation.
//!
//! Uses `identity` for the `users` table, but owns password hashing, JWT
//! issuing/verification, and the `refresh_tokens` and `email_verifications`
//! tables. Cookies, HTTP, Leptos, and Casbin are not part of this crate —
//! that is the consumer's responsibility.
//!
//! Stage 2d: rotation includes a grace window
//! ([`REFRESH_GRACE_SECONDS`]). A refresh token presented within the window
//! after it was used returns [`AuthnError::RefreshInvalid`] and does **not**
//! revoke the family — this absorbs the parallel-request race where two
//! in-flight requests carry the same cookie (e.g. an SSR page and its
//! subresource fetches). Presenting an already-used token **after** the
//! window returns [`AuthnError::RefreshReused`] and revokes the family — a
//! genuine reuse signal.
//!
//! Stage 3b: access-token claims are `{ sub, iat, exp }` (no `email`); the
//! verified address and `email_verified` flag are resolved from `users` on
//! every `verify_token`. Email verification is provided by
//! [`Authn::create_email_verification`] (single-active, 24-hour TTL) and
//! [`Authn::verify_email`] (idempotent, no auto-login). Revocation reasons
//! are recorded in `refresh_tokens.revoked_reason` ([`RevokeReason`]).

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

/// Grace window (Stage 2d) around refresh-token rotation.
///
/// When a refresh token that was already consumed is presented within
/// [`REFRESH_GRACE_SECONDS`] seconds of its `used_at`, rotation returns
/// [`AuthnError::RefreshInvalid`] and leaves the family intact. This absorbs
/// the common race where two parallel in-flight requests share the same
/// cookie (SSR page + subresource fetches, two tabs, etc.): the winner
/// rotates and the loser fails cleanly instead of revoking the family.
///
/// Presenting the same token after the window is still treated as a genuine
/// reuse ([`AuthnError::RefreshReused`], family revoked). The value is an
/// internal knob (not deployment-specific) and is not read from the
/// environment.
pub const REFRESH_GRACE_SECONDS: i64 = 10;

/// Email-verification token lifetime (Stage 3b): 24 hours.
pub const EMAIL_VERIFICATION_TTL_HOURS: i64 = 24;

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
    /// A previously used refresh token was presented after the grace window;
    /// the whole family was revoked as a compromise signal (Stage 2b/2d).
    #[error("refresh token reused")]
    RefreshReused,
    /// `create_email_verification` refused because the address is already
    /// verified (Stage 3b).
    #[error("email already verified")]
    AlreadyVerified,
    #[error("internal authentication error: {0}")]
    Internal(String),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Reason recorded in `refresh_tokens.revoked_reason` (Stage 3b). The column
/// is free-form `text`; new reasons can be added without a migration as long
/// as [`RevokeReason::as_str`] is extended.
///
/// `PasswordReset` is reserved for Stage 3d and is not written by any code
/// path in Stage 3b.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeReason {
    /// Explicit user logout (`revoke_refresh_token`).
    Logout,
    /// Genuine reuse detected on rotation (`rotate_refresh_token`).
    ReuseDetected,
    /// Password reset invalidated the session family (Stage 3d, reserved).
    PasswordReset,
}

impl RevokeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevokeReason::Logout => "logout",
            RevokeReason::ReuseDetected => "reuse_detected",
            RevokeReason::PasswordReset => "password_reset",
        }
    }
}

/// Access-token claims (Stage 3b): `sub`, `iat`, `exp`. The user's email is
/// not embedded — `verify_token` resolves the `AuthUser` (including the
/// verified flag) from `users` on every call, so changes in verification
/// state or email are immediately visible without waiting for the access
/// token to expire.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
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

#[derive(Debug, sqlx::FromRow)]
struct VerificationRecord {
    id: Uuid,
    user_id: Uuid,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
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

    /// Issues a short-lived access JWT (Stage 2b; claims cleanup in 3b).
    ///
    /// Claims: `sub`, `iat`, `exp`. The user's email is **not** in the token
    /// — `verify_token` resolves the `AuthUser` (with its current
    /// `email_verified` flag) from `users`.
    pub fn issue_access_token(&self, user: &AuthUser) -> Result<String, AuthnError> {
        let now = Utc::now();
        let claims = Claims {
            sub: user.id.to_string(),
            iat: now.timestamp(),
            exp: (now + self.access_ttl).timestamp(),
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
        let raw = generate_opaque_token();
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

    /// Rotates a refresh token.
    ///
    /// Order:
    /// 1. Look up the row by `token_hash` (`FOR UPDATE`).
    /// 2. `revoked_at` set → [`AuthnError::RefreshInvalid`].
    /// 3. `used_at` set within [`REFRESH_GRACE_SECONDS`] → [`AuthnError::RefreshInvalid`]
    ///    (parallel-request race; the family is left intact).
    /// 4. `used_at` set after the grace window → revoke the family
    ///    (`revoked_reason = "reuse_detected"`) and return
    ///    [`AuthnError::RefreshReused`] (genuine reuse).
    /// 5. `expires_at` in the past → [`AuthnError::RefreshInvalid`].
    /// 6. Mark the row used, insert a new row in the same family, commit,
    ///    and return `(new_raw, user)`.
    pub async fn rotate_refresh_token(&self, raw: &str) -> Result<(String, AuthUser), AuthnError> {
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

        if let Some(used_at) = row.used_at {
            let elapsed = Utc::now().signed_duration_since(used_at);
            if elapsed.num_seconds() < REFRESH_GRACE_SECONDS {
                // Parallel-request race: another request already rotated this
                // token a moment ago. Do not revoke the family; just reject.
                return Err(AuthnError::RefreshInvalid);
            }
            sqlx::query(
                r#"
                update refresh_tokens
                set revoked_at = now(), revoked_reason = $2
                where family_id = $1 and revoked_at is null
                "#,
            )
            .bind(row.family_id)
            .bind(RevokeReason::ReuseDetected.as_str())
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

        let new_raw = generate_opaque_token();
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

    /// Revokes the family of a refresh token (idempotent). Records
    /// `revoked_reason = "logout"`.
    pub async fn revoke_refresh_token(&self, raw: &str) -> Result<(), AuthnError> {
        let token_hash = hash_token(raw);

        let family_id: Option<Uuid> =
            sqlx::query_scalar("select family_id from refresh_tokens where token_hash = $1")
                .bind(&token_hash)
                .fetch_optional(&self.pool)
                .await?;

        if let Some(family_id) = family_id {
            self.revoke_family(family_id, Some(RevokeReason::Logout.as_str()))
                .await?;
        }
        Ok(())
    }

    /// Revokes every not-yet-revoked row in `family_id` and stores
    /// `reason` in `refresh_tokens.revoked_reason` (`None` — leave the
    /// column `NULL`, e.g. internal cleanup paths).
    pub async fn revoke_family(
        &self,
        family_id: Uuid,
        reason: Option<&str>,
    ) -> Result<(), AuthnError> {
        sqlx::query(
            r#"
            update refresh_tokens
            set revoked_at = now(), revoked_reason = $2
            where family_id = $1 and revoked_at is null
            "#,
        )
        .bind(family_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Creates (or replaces) an email-verification token for `user_id`.
    ///
    /// Order:
    /// 1. `SELECT email_verified_at FROM users ... FOR UPDATE` — the
    ///    `AlreadyVerified` check runs under a row lock, so two concurrent
    ///    callers cannot both observe the pre-verification state.
    /// 2. `email_verified_at IS NOT NULL` → [`AuthnError::AlreadyVerified`].
    /// 3. `DELETE FROM email_verifications WHERE user_id = $1 AND used_at IS NULL`
    ///    (single-active invariant; also enforced by the partial unique
    ///    index `email_verifications_one_active_idx`).
    /// 4. `INSERT ... RETURNING` new row with `expires_at = now() +
    ///    EMAIL_VERIFICATION_TTL_HOURS`.
    ///
    /// Returns the raw token; only `token_hash` is persisted.
    pub async fn create_email_verification(&self, user_id: Uuid) -> Result<String, AuthnError> {
        let mut tx = self.pool.begin().await?;

        let verified_at: Option<Option<DateTime<Utc>>> =
            sqlx::query_scalar("select email_verified_at from users where id = $1 for update")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some(verified_at) = verified_at else {
            return Err(AuthnError::Identity(IdentityError::NotFound));
        };

        if verified_at.is_some() {
            return Err(AuthnError::AlreadyVerified);
        }

        sqlx::query("delete from email_verifications where user_id = $1 and used_at is null")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        let raw = generate_opaque_token();
        let token_hash = hash_token(&raw);
        let expires_at = Utc::now() + Duration::hours(EMAIL_VERIFICATION_TTL_HOURS);

        sqlx::query(
            r#"
            insert into email_verifications (user_id, token_hash, expires_at)
            values ($1, $2, $3)
            "#,
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(raw)
    }

    /// Verifies an email address by raw token. Idempotent: if the user is
    /// already verified, returns the `AuthUser` without touching
    /// `users.email_verified_at` (preserves the original timestamp). Does
    /// **not** issue tokens or cookies — callers (e.g. `#[server]
    /// verify_email`) may then direct the user to log in.
    ///
    /// Order:
    /// 1. Load the token row (`FOR UPDATE`) by `token_hash`; not found →
    ///    [`AuthnError::TokenInvalid`].
    /// 2. Load `email_verified_at` for the target user (`FOR UPDATE`).
    /// 3. Already verified → Ok(user) (and mark the token used if it was not,
    ///    so a stale link cannot be replayed).
    /// 4. Token already used → [`AuthnError::TokenInvalid`].
    /// 5. Token expired → [`AuthnError::TokenInvalid`].
    /// 6. Mark token used (`WHERE used_at IS NULL`; 0 rows affected → race →
    ///    [`AuthnError::TokenInvalid`]); `UPDATE users SET email_verified_at
    ///    = COALESCE(email_verified_at, now())`; commit; return `AuthUser`.
    pub async fn verify_email(&self, raw: &str) -> Result<AuthUser, AuthnError> {
        let token_hash = hash_token(raw);
        let mut tx = self.pool.begin().await?;

        let row: Option<VerificationRecord> = sqlx::query_as(
            r#"
            select id, user_id, expires_at, used_at
            from email_verifications
            where token_hash = $1
            for update
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            return Err(AuthnError::TokenInvalid);
        };

        let verified_at: Option<Option<DateTime<Utc>>> =
            sqlx::query_scalar("select email_verified_at from users where id = $1 for update")
                .bind(row.user_id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some(verified_at) = verified_at else {
            return Err(AuthnError::TokenInvalid);
        };

        if verified_at.is_some() {
            if row.used_at.is_none() {
                sqlx::query("update email_verifications set used_at = now() where id = $1")
                    .bind(row.id)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            let user = identity::find_by_id(&self.pool, row.user_id)
                .await?
                .ok_or(AuthnError::TokenInvalid)?;
            return Ok(user);
        }

        if row.used_at.is_some() {
            return Err(AuthnError::TokenInvalid);
        }

        if row.expires_at <= Utc::now() {
            return Err(AuthnError::TokenInvalid);
        }

        let updated = sqlx::query(
            "update email_verifications set used_at = now() where id = $1 and used_at is null",
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await?;

        if updated.rows_affected() == 0 {
            return Err(AuthnError::TokenInvalid);
        }

        sqlx::query(
            "update users set email_verified_at = coalesce(email_verified_at, now()) where id = $1",
        )
        .bind(row.user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let user = identity::find_by_id(&self.pool, row.user_id)
            .await?
            .ok_or(AuthnError::TokenInvalid)?;
        Ok(user)
    }

    /// Verifies an access JWT and resolves the current `AuthUser` from
    /// `users`.
    ///
    /// `email` is **not** read from the claims (Stage 3b): the DTO always
    /// reflects the current database row — including `email_verified` and
    /// the address itself.
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

/// Generates a 64-char hex opaque token (2 × UUID v4 simple hex). Used for
/// refresh tokens and email-verification tokens.
fn generate_opaque_token() -> String {
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
            email_verified: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn hash_password_produces_valid_argon2_hash() {
        let password = "correct horse battery staple";
        let hash = hash_password(password).expect("hashing must succeed");
        assert!(
            hash.starts_with("$argon2"),
            "must be Argon2 PHC string: {hash}"
        );

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
        assert!(Argon2::default()
            .verify_password(b"wrong", &parsed)
            .is_err());
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
    fn generate_opaque_token_is_hex64_and_unique() {
        let a = generate_opaque_token();
        let b = generate_opaque_token();
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn revoke_reason_as_str_is_stable() {
        assert_eq!(RevokeReason::Logout.as_str(), "logout");
        assert_eq!(RevokeReason::ReuseDetected.as_str(), "reuse_detected");
        assert_eq!(RevokeReason::PasswordReset.as_str(), "password_reset");
    }

    #[tokio::test]
    async fn issue_access_token_is_three_part_jwt() {
        let user = sample_user();
        let token = authn("secret").issue_access_token(&user).expect("issue");
        assert_eq!(token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn issue_access_token_claims_contain_sub_iat_exp() {
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
        let iat = claims.get("iat").and_then(|v| v.as_i64()).expect("iat");
        let exp = claims.get("exp").and_then(|v| v.as_i64()).expect("exp");
        assert!(exp > iat, "exp must be after iat");
        assert!(exp > Utc::now().timestamp(), "exp must be in the future");
        assert!(
            claims.get("email").is_none(),
            "email must not appear in claims (Stage 3b)"
        );
    }

    #[tokio::test]
    async fn verify_token_rejects_wrong_signature() {
        let user = sample_user();
        let token = authn("issuer-secret")
            .issue_access_token(&user)
            .expect("issue");
        let err = authn("different-secret")
            .verify_token(&token)
            .await
            .expect_err("verify must reject");
        assert!(matches!(err, AuthnError::TokenInvalid));
    }

    #[tokio::test]
    async fn verify_token_rejects_expired() {
        let secret = "expired-test-secret";
        let now = Utc::now().timestamp();
        let claims = json!({
            "sub": Uuid::new_v4().to_string(),
            "iat": now - 7200,
            "exp": now - 3600,
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
        let now = Utc::now().timestamp();
        let claims = json!({
            "sub": "not-a-uuid",
            "iat": now,
            "exp": now + 3600,
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
        let now = Utc::now().timestamp();
        let claims = json!({
            "iat": now,
            "exp": now + 3600,
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
