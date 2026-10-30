//! Platform user entity.
//!
//! This crate owns the `users` table (sole writer by contract).
//! Password hashing is not performed here — `create_user`/`upsert_user`
//! accept a precomputed `password_hash` produced by `authn`. JWT, cookie,
//! HTTP, and Casbin are not part of this crate.
//!
//! Stage 3b: `users.email_verified_at` is the source of truth for whether
//! an email address has been verified. `domain::AuthUser.email_verified` is
//! a **derived** boolean (`email_verified_at IS NOT NULL`), computed in
//! every `SELECT` that maps a `users` row into `AuthUser`. The timestamp
//! itself is internal to this crate (`UserRecord`); it is not exposed on
//! `AuthUser`.
//!
//! Stage 3d: `users.password_changed_at` is the source of truth for "when
//! was the password last set". `UserRecord` carries it; `update_password_tx`
//! is the only writer that mutates `password_hash`, and it updates
//! `password_changed_at = now()` in the same statement. Stage 4 will use it
//! to invalidate access tokens issued before a password change (iat-vs-
//! `password_changed_at`); Stage 3d only maintains it.

use domain::AuthUser;
use sqlx::{PgPool, Postgres, Transaction};
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

/// Full `users` row, including `password_hash`, `email_verified_at`, and
/// `password_changed_at`.
///
/// Internal to `identity`/`authn`: `UserRecord` never crosses the crate
/// boundary (`AuthUser` is the public DTO; `From<UserRecord>` is the only
/// bridge).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the password was last changed (Stage 3d). Source of truth for
    /// the iat-vs-`password_changed_at` check in Stage 4; this stage only
    /// maintains it.
    pub password_changed_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserRecord> for AuthUser {
    fn from(r: UserRecord) -> Self {
        Self {
            id: r.id,
            email: r.email,
            email_verified: r.email_verified_at.is_some(),
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
    let user = sqlx::query_as::<_, AuthUser>(
        r#"
        select id, email, (email_verified_at is not null) as email_verified, created_at
        from users
        where id = $1
        "#,
    )
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
        r#"
        select id, email, password_hash, email_verified_at, password_changed_at, created_at
        from users
        where email = $1
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

/// Creates a user. `password_hash` must already be computed (Argon2 is in
/// `authn`). The new user is unverified (`email_verified_at IS NULL`);
/// `password_changed_at` defaults to `now()` via the column default from
/// migration `20261106000001_authn_password_reset.sql`.
pub async fn create_user(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
) -> Result<AuthUser, IdentityError> {
    validate_email(email)?;

    let result = sqlx::query_as::<_, AuthUser>(
        r#"
        insert into users (email, password_hash)
        values ($1, $2)
        returning id, email, (email_verified_at is not null) as email_verified, created_at
        "#,
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
///
/// Does **not** touch `email_verified_at` or `password_changed_at`: seed
/// uses `upsert_user` followed by an explicit `UPDATE` to set
/// `email_verified_at = COALESCE(...)` for demo accounts (see
/// `crates/seed/src/main.rs`). Not updating `password_changed_at` here is
/// intentional — a seed re-run is not treated as a security-relevant
/// password change (Stage 4's iat-vs-`password_changed_at` check would
/// otherwise invalidate freshly-issued demo access tokens after every
/// seed run).
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
        returning id, email, (email_verified_at is not null) as email_verified, created_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Updates a user's password inside a caller-supplied transaction (Stage 3d).
///
/// Sets `password_hash = $1` and `password_changed_at = now()` in a single
/// `UPDATE`. The caller (`authn::reset_password`) is responsible for
/// revoking refresh tokens and expiring outstanding reset tokens in the
/// same transaction; this function writes only the `users` row, preserving
/// the §2.9 single-writer invariant (`identity` writes `users`; `authn`
/// orchestrates the transaction via this helper — the same pattern as
/// `verify_email` writing `email_verified_at`).
///
/// Returns [`IdentityError::NotFound`] if no row matches `user_id`; in
/// `authn::reset_password` the user id comes from a reset token that was
/// just read under `FOR UPDATE`, so a miss is treated as an internal error
/// (the user cannot normally disappear between those two statements).
pub async fn update_password_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    new_hash: &str,
) -> Result<(), IdentityError> {
    let updated = sqlx::query(
        r#"
        update users
        set password_hash = $1, password_changed_at = now()
        where id = $2
        "#,
    )
    .bind(new_hash)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(IdentityError::NotFound);
    }
    Ok(())
}
