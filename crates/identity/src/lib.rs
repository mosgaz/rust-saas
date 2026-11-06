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
//! `password_changed_at = clock_timestamp()` in the same statement (Stage 4.5a
//! extension — see the `update_password_tx` doc-comment for why not `now()`).
//! Stage 4 uses it to invalidate access tokens issued before a password
//! change (iat-vs-`password_changed_at`); Stage 3d only maintains it.

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
    #[error("db error: {0}")]
    Db(String),
    #[error("external identity already linked")]
    DuplicateExternalIdentity,
    #[error("external identity not found")]
    ExternalIdentityNotFound,
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
    pub password_hash: Option<String>,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the password was last changed (Stage 3d). Source of truth for
    /// the iat-vs-`password_changed_at` check in Stage 4; this stage only
    /// maintains it.
    pub password_changed_at: Option<chrono::DateTime<chrono::Utc>>,
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

impl From<sqlx::Error> for IdentityError {
    fn from(e: sqlx::Error) -> Self {
        IdentityError::Db(e.to_string())
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

/// Like [`find_by_id`], but returns the full [`UserRecord`], including
/// `password_hash`, `email_verified_at`, and `password_changed_at`.
///
/// Used by `authn::verify_token` (Stage 4.1) to compare the access-JWT
/// `iat` claim with `users.password_changed_at` — a token issued before the
/// last password change is rejected, closing the gap where a stolen
/// access-token survived a `reset_password` for up to `access_ttl`.
///
/// Public because it is the only way to obtain `password_changed_at` from
/// outside `identity`; `UserRecord` is already `pub` (with the same
/// "internal to identity/authn" caveat).
pub async fn find_record_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<UserRecord>, IdentityError> {
    let user = sqlx::query_as::<_, UserRecord>(
        r#"
        select id, email, password_hash, email_verified_at, password_changed_at, created_at
        from users
        where id = $1
        "#,
    )
    .bind(id)
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
        other => IdentityError::Db(other.to_string()),
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
/// Sets `password_hash = $1` and `password_changed_at = clock_timestamp()`
/// in a single `UPDATE`. The caller (`authn::reset_password`) is
/// responsible for revoking refresh tokens and expiring outstanding reset
/// tokens in the same transaction; this function writes only the `users`
/// row, preserving the §2.9 single-writer invariant (`identity` writes
/// `users`; `authn` orchestrates the transaction via this helper — the
/// same pattern as `verify_email` writing `email_verified_at`).
///
/// **`clock_timestamp()`, not `now()` (Stage 4.5a extension).** `now()`
/// in PostgreSQL returns the transaction-start time
/// (`transaction_timestamp()`), not the time the `UPDATE` actually runs.
/// Using it here creates two problems:
///
/// 1. **Test flake** (`authn/tests/integration.rs::reset_password_marks_token_used_and_changes_password`).
///    The test sleeps 20 ms between register and reset, then asserts
///    `password_changed_at` moved forward. With `now()`, a `reset_password`
///    transaction that started before the sleep (e.g. SQLx pool scheduling
///    under parallel test load) lands `T1 <= T0`, and the assertion fails
///    intermittently.
/// 2. **Security gap for the Stage 4.1 `iat`-vs-`password_changed_at` check.**
///    If an access JWT is issued between `BEGIN` and the `UPDATE` inside
///    `reset_password`, its `iat` is in `[T_BEGIN, T_UPDATE]`, and
///    `password_changed_at = T_BEGIN` would let the token survive the
///    reset. `clock_timestamp()` makes `password_changed_at` strictly
///    greater than any token issued before the `UPDATE` statement itself.
///
/// Both are closed by the single substitution. No schema change
/// (`clock_timestamp()` returns `timestamptz`, same as `now()`); outside
/// behaviour of `reset_password` is unchanged apart from the narrower
/// window.
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
        set password_hash = $1, password_changed_at = clock_timestamp()
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

/// Creates a user with an external identity (e.g., OIDC).
///
/// This function creates a new user with the provided email and links the
/// external identity (provider + external_id) to the user. Since the user
/// authenticates via an external provider, no password_hash is stored.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `email` - User's email address
/// * `provider` - External identity provider (e.g., "google", "github")
/// * `external_id` - User ID from the external provider
/// * `email_verified` - Whether the email has been verified by the provider
///
/// # Returns
///
/// The created AuthUser on success, or an error if the email is already
/// registered or another database error occurs.
///
/// # Note
///
/// The user's `password_hash` is NULL since they authenticate via external
/// provider. `password_changed_at` is also NULL as there is no password.
/// `email_verified_at` is set based on the `email_verified` parameter.
pub async fn create_external_user(
    pool: &PgPool,
    email: &str,
    provider: &str,
    external_id: &str,
    email_verified: bool,
) -> Result<AuthUser, IdentityError> {
    validate_email(email)?;

    let email_verified_at = if email_verified {
        Some(chrono::Utc::now())
    } else {
        None
    };

    let mut tx = pool.begin().await?;

    // First, create the user
    let user = sqlx::query_as::<_, AuthUser>(
        r#"
        insert into users (email, email_verified_at)
        values ($1, $2)
        returning id, email, (email_verified_at is not null) as email_verified, created_at
        "#,
    )
    .bind(email)
    .bind(email_verified_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
            IdentityError::DuplicateEmail
        }
        other => IdentityError::Db(other.to_string()),
    })?;

    // Then, link the external identity
    sqlx::query(
        r#"
        insert into external_identities (user_id, provider, external_id, email)
        values ($1, $2, $3, $4)
        "#,
    )
    .bind(user.id)
    .bind(provider)
    .bind(external_id)
    .bind(email)
    .execute(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("external_identities_pkey") => {
            IdentityError::DuplicateExternalIdentity
        }
        other => IdentityError::Db(other.to_string()),
    })?;

    tx.commit().await?;

    Ok(user)
}

/// Finds a user by their external identity (provider + external_id).
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `provider` - External identity provider (e.g., "google", "github")
/// * `external_id` - User ID from the external provider
///
/// # Returns
///
/// The AuthUser if found, None if no user with that external identity exists,
/// or an error if a database error occurs.
pub async fn find_by_external_id(
    pool: &PgPool,
    provider: &str,
    external_id: &str,
) -> Result<Option<AuthUser>, IdentityError> {
    let user = sqlx::query_as::<_, AuthUser>(
        r#"
        select u.id, u.email, (u.email_verified_at is not null) as email_verified, u.created_at
        from users u
        join external_identities ei on u.id = ei.user_id
        where ei.provider = $1 and ei.external_id = $2
        "#,
    )
    .bind(provider)
    .bind(external_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Links an external identity to an existing user.
///
/// This function connects an external identity (e.g., from Google, GitHub)
/// to an existing user account. This allows users to sign in with multiple
/// providers or link social accounts to their existing account.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `user_id` - ID of the existing user
/// * `provider` - External identity provider (e.g., "google", "github")
/// * `external_id` - User ID from the external provider
/// * `email` - Email address from the external provider
///
/// # Returns
///
/// Ok(()) on success, or an error if the external identity is already
/// linked to another user or another database error occurs.
///
/// # Note
///
/// This function does not verify that the email from the external provider
/// matches the user's email. That validation should be done by the caller
/// if desired.
pub async fn link_external_identity(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    external_id: &str,
    email: &str,
) -> Result<(), IdentityError> {
    sqlx::query(
        r#"
        insert into external_identities (user_id, provider, external_id, email)
        values ($1, $2, $3, $4)
        "#,
    )
    .bind(user_id)
    .bind(provider)
    .bind(external_id)
    .bind(email)
    .execute(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("external_identities_pkey") => {
            IdentityError::DuplicateExternalIdentity
        }
        sqlx::Error::Database(db) if db.constraint() == Some("external_identities_user_id_fkey") => {
            IdentityError::NotFound
        }
        other => IdentityError::Db(other.to_string()),
    })?;

    Ok(())
}

/// Unlinks an external identity from a user.
///
/// This function removes the connection between an external identity and a
/// user account. If this was the user's only authentication method, they
/// will no longer be able to sign in unless they have a password or another
/// linked identity.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `user_id` - ID of the user
/// * `provider` - External identity provider to unlink
///
/// # Returns
///
/// Ok(()) on success, or an error if the external identity was not found
/// or another database error occurs.
///
/// # Note
///
/// This function does not delete the user account, only the link to the
/// external provider. The user account remains intact.
pub async fn unlink_external_identity(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
) -> Result<(), IdentityError> {
    let result = sqlx::query(
        r#"
        delete from external_identities
        where user_id = $1 and provider = $2
        "#,
    )
    .bind(user_id)
    .bind(provider)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(IdentityError::ExternalIdentityNotFound);
    }

    Ok(())
}
