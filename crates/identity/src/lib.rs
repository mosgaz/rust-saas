//! Platform user entity.
//!
//! This crate owns the `users` table (sole writer by contract).
//! Password hashing is not performed here — `create_user`/`upsert_user`
//! accept a precomputed `password_hash` produced by `authn`. JWT, cookie,
//! HTTP, and Casbin are not part of this crate.

use domain::AuthUser;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("user not found")]
    NotFound,
    #[error("email already registered")]
    DuplicateEmail,
    #[error("validation error: {0}")]
    Validation(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Full `users` row, including `password_hash`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserRecord> for AuthUser {
    fn from(r: UserRecord) -> Self {
        Self {
            id: r.id,
            email: r.email,
            created_at: r.created_at,
        }
    }
}

pub fn validate_email(email: &str) -> Result<(), IdentityError> {
    let email = email.trim();
    if email.is_empty() || !email.contains('@') || email.len() > 320 {
        return Err(IdentityError::Validation("invalid email".into()));
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), IdentityError> {
    if password.len() < 8 {
        return Err(IdentityError::Validation(
            "password must be at least 8 characters".into(),
        ));
    }
    Ok(())
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<AuthUser>, IdentityError> {
    let user =
        sqlx::query_as::<_, AuthUser>("select id, email, created_at from users where id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(user)
}

pub async fn find_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserRecord>, IdentityError> {
    let user = sqlx::query_as::<_, UserRecord>(
        "select id, email, password_hash, created_at from users where email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

/// Creates a user. `password_hash` must already be computed (Argon2 is in
/// `authn`).
pub async fn create_user(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
) -> Result<AuthUser, IdentityError> {
    validate_email(email)?;

    let result = sqlx::query_as::<_, AuthUser>(
        "insert into users (email, password_hash) values ($1, $2) returning id, email, created_at",
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await;

    result.map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
            IdentityError::DuplicateEmail
        }
        other => IdentityError::Db(other),
    })
}

/// Idempotent upsert: if a user with this email exists, update
/// `password_hash`; otherwise create. Used by `seed`.
pub async fn upsert_user(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
) -> Result<AuthUser, IdentityError> {
    validate_email(email)?;

    let user = sqlx::query_as::<_, AuthUser>(
        r#"
        insert into users (email, password_hash)
        values ($1, $2)
        on conflict (email) do update
        set password_hash = excluded.password_hash
        returning id, email, created_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;

    Ok(user)
}
