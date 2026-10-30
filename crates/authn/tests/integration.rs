//! Integration tests for `authn` against a real PostgreSQL.
//!
//! `#[sqlx::test]` creates an isolated database per test on the server from
//! `DATABASE_URL` (the workspace-root `.env` is read automatically via
//! `sqlx`'s built-in `dotenvy` support), applies `crates/db/migrations`, and
//! drops the database afterwards.
//!
//! No manual `createdb` is required. `DATABASE_URL` must point at a server
//! where the user has the `CREATE DATABASE` privilege (the default postgres
//! superuser satisfies this).

use authn::{
    Authn, AuthnError, EMAIL_VERIFICATION_TTL_HOURS, PASSWORD_RESET_TTL_HOURS,
    REFRESH_GRACE_SECONDS,
};
use identity::IdentityError;
use sqlx::PgPool;
use uuid::Uuid;

fn fresh(pool: PgPool) -> Authn {
    Authn::new(pool, "test-jwt-secret-not-for-production")
}

fn unique_email(label: &str) -> String {
    format!("{label}-{}@test.local", Uuid::new_v4())
}

// ─── Register / login / verify ──────────────────────────────────────────────

#[sqlx::test(migrations = "../db/migrations")]
async fn register_and_login_roundtrip(pool: PgPool) {
    let authn = fresh(pool);
    let email = unique_email("roundtrip");

    let user = authn
        .register(&email, "Password123!")
        .await
        .expect("register must succeed");
    assert_eq!(user.email, email);
    assert!(
        !user.email_verified,
        "a freshly registered user must be unverified"
    );

    let logged = authn
        .login(&email, "Password123!")
        .await
        .expect("login must succeed");
    assert_eq!(logged.id, user.id);
    assert!(!logged.email_verified);
}

#[sqlx::test(migrations = "../db/migrations")]
async fn login_with_wrong_password_fails(pool: PgPool) {
    let authn = fresh(pool);
    let email = unique_email("wrong-pw");
    authn.register(&email, "Password123!").await.unwrap();

    let err = authn
        .login(&email, "WrongPass123!")
        .await
        .expect_err("login must fail");
    assert!(matches!(err, AuthnError::InvalidCredentials), "got {err:?}");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn login_with_unknown_email_fails(pool: PgPool) {
    let authn = fresh(pool);
    let err = authn
        .login(&unique_email("unknown"), "Password123!")
        .await
        .expect_err("login must fail");
    assert!(matches!(err, AuthnError::InvalidCredentials), "got {err:?}");
}

#[sqlx::test(migrations = "../db/migrations")]
async fn register_duplicate_email_fails(pool: PgPool) {
    let authn = fresh(pool);
    let email = unique_email("dup");
    authn.register(&email, "Password123!").await.unwrap();

    let err = authn
        .register(&email, "Password123!")
        .await
        .expect_err("register must fail");
    assert!(
        matches!(err, AuthnError::Identity(IdentityError::DuplicateEmail)),
        "got {err:?}"
    );
}

#[sqlx::test(migrations = "../db/migrations")]
async fn verify_token_returns_some_for_existing_user(pool: PgPool) {
    let authn = fresh(pool);
    let email = unique_email("verify-ok");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let token = authn.issue_access_token(&user).unwrap();

    let verified = authn
        .verify_token(&token)
        .await
        .expect("verify must not error")
        .expect("user must be found");
    assert_eq!(verified.id, user.id);
    assert_eq!(verified.email, user.email);
    assert!(
        !verified.email_verified,
        "unverified user must remain unverified across verify_token"
    );
}

#[sqlx::test(migrations = "../db/migrations")]
async fn verify_token_returns_none_for_deleted_user(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("verify-deleted");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let token = authn.issue_access_token(&user).unwrap();

    sqlx::query("delete from users where id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("delete must succeed");

    let verified = authn
        .verify_token(&token)
        .await
        .expect("verify must not error");
    assert!(verified.is_none(), "deleted user must yield Ok(None)");
}

// ─── Refresh tokens (Stage 2b/2d) ───────────────────────────────────────────

/// `issue_refresh_token` persists exactly one row: `used_at` and `revoked_at`
/// NULL (and `revoked_reason` NULL), `expires_at` in the future.
#[sqlx::test(migrations = "../db/migrations")]
async fn issue_refresh_token_persists_row(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("refresh-issue");
    let user = authn.register(&email, "Password123!").await.unwrap();

    let raw = authn
        .issue_refresh_token(&user)
        .await
        .expect("issue_refresh_token");
    assert_eq!(raw.len(), 64, "2 × uuid simple hex");

    let rows: Vec<(bool, bool, bool, bool)> = sqlx::query_as(
        r#"
        select used_at is not null,
               revoked_at is not null,
               revoked_reason is not null,
               expires_at > now()
        from refresh_tokens
        where user_id = $1
        "#,
    )
    .bind(user.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    let (used, revoked, reason_set, live) = rows[0];
    assert!(!used, "fresh token must not be used");
    assert!(!revoked, "fresh token must not be revoked");
    assert!(!reason_set, "fresh token must not have a revocation reason");
    assert!(live, "expires_at must be in the future");
}

/// `rotate_refresh_token` marks the old row used, inserts a new row in the
/// same family, and returns the user.
#[sqlx::test(migrations = "../db/migrations")]
async fn rotate_refresh_token_success(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("refresh-rotate");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let r1 = authn.issue_refresh_token(&user).await.unwrap();

    let family_id: Uuid =
        sqlx::query_scalar("select family_id from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let (r2, rotated_user) = authn.rotate_refresh_token(&r1).await.expect("rotate");
    assert_eq!(rotated_user.id, user.id);
    assert_ne!(r2, r1, "rotation must return a fresh raw token");

    let rows: Vec<(bool, bool)> = sqlx::query_as(
        r#"
        select used_at is not null, revoked_at is not null
        from refresh_tokens
        where user_id = $1
        order by created_at asc
        "#,
    )
    .bind(user.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].0, "old row must have used_at set");
    assert!(!rows[0].1, "old row must not be revoked yet");
    assert!(!rows[1].0, "new row must be unused");
    assert!(!rows[1].1, "new row must not be revoked");

    let families: Vec<Uuid> =
        sqlx::query_scalar("select family_id from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        families.iter().all(|f| *f == family_id),
        "rotation must preserve family_id"
    );
}

/// Reusing an already-used refresh token **after** the grace window revokes
/// the whole family, records `revoked_reason = 'reuse_detected'`, and
/// returns `RefreshReused`.
#[sqlx::test(migrations = "../db/migrations")]
async fn rotate_refresh_token_reuse_revokes_family(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("refresh-reuse");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let r1 = authn.issue_refresh_token(&user).await.unwrap();
    let _r2 = authn
        .rotate_refresh_token(&r1)
        .await
        .expect("first rotate must succeed");

    // Push the used_at well past the grace window.
    sqlx::query(
        r#"
        update refresh_tokens
        set used_at = now() - make_interval(secs => $2)
        where user_id = $1 and used_at is not null
        "#,
    )
    .bind(user.id)
    .bind((REFRESH_GRACE_SECONDS + 60) as f64)
    .execute(&pool)
    .await
    .expect("force old used_at");

    let err = authn
        .rotate_refresh_token(&r1)
        .await
        .expect_err("reuse outside the grace window must be rejected");
    assert!(matches!(err, AuthnError::RefreshReused), "got {err:?}");

    let revoked: i64 = sqlx::query_scalar(
        "select count(*) from refresh_tokens where user_id = $1 and revoked_at is not null",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let total: i64 = sqlx::query_scalar("select count(*) from refresh_tokens where user_id = $1")
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revoked, total, "reuse must revoke the whole family");
    assert!(
        total >= 2,
        "family must have at least two rows after rotate"
    );

    let reasons: Vec<Option<String>> =
        sqlx::query_scalar("select revoked_reason from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        reasons
            .iter()
            .all(|r| r.as_deref() == Some("reuse_detected")),
        "every revoked row must record reuse_detected, got {reasons:?}"
    );
}

/// Stage 2d: presenting an already-used token **within** the grace window is
/// treated as a parallel-request race — `RefreshInvalid`, and the family is
/// **not** revoked.
#[sqlx::test(migrations = "../db/migrations")]
async fn rotate_refresh_token_within_grace_returns_invalid(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("refresh-grace");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let r1 = authn.issue_refresh_token(&user).await.unwrap();
    let (r2, _) = authn
        .rotate_refresh_token(&r1)
        .await
        .expect("first rotate must succeed");

    // Immediately present the same r1 again — within the default grace window.
    let err = authn
        .rotate_refresh_token(&r1)
        .await
        .expect_err("parallel-request race must be rejected");
    assert!(
        matches!(err, AuthnError::RefreshInvalid),
        "within grace must be RefreshInvalid, got {err:?}"
    );

    // Family survives.
    let revoked: i64 = sqlx::query_scalar(
        "select count(*) from refresh_tokens where user_id = $1 and revoked_at is not null",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(revoked, 0, "grace-window race must not revoke the family");

    // The new token (r2) is still usable.
    let _r3 = authn
        .rotate_refresh_token(&r2)
        .await
        .expect("the new token from the first rotate must still be usable");
}

/// Stage 2d: a genuine reuse **after** the grace window still revokes the
/// family; sanity-check the boundary between the two behaviours.
#[sqlx::test(migrations = "../db/migrations")]
async fn rotate_refresh_token_old_reuse_revokes_family(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("refresh-old");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let r1 = authn.issue_refresh_token(&user).await.unwrap();
    let _r2 = authn.rotate_refresh_token(&r1).await.unwrap();

    sqlx::query(
        r#"
        update refresh_tokens
        set used_at = now() - make_interval(secs => $2)
        where user_id = $1 and used_at is not null
        "#,
    )
    .bind(user.id)
    .bind((REFRESH_GRACE_SECONDS + 1) as f64)
    .execute(&pool)
    .await
    .unwrap();

    let err = authn
        .rotate_refresh_token(&r1)
        .await
        .expect_err("reuse past grace must be rejected");
    assert!(matches!(err, AuthnError::RefreshReused), "got {err:?}");

    let revoked: i64 = sqlx::query_scalar(
        "select count(*) from refresh_tokens where user_id = $1 and revoked_at is not null",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let total: i64 = sqlx::query_scalar("select count(*) from refresh_tokens where user_id = $1")
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revoked, total, "past grace, reuse must revoke the family");
}

/// `revoke_refresh_token` (logout) sets `revoked_at` and records
/// `revoked_reason = 'logout'`; a subsequent rotate returns `RefreshInvalid`.
#[sqlx::test(migrations = "../db/migrations")]
async fn revoke_refresh_token_revokes_family(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("refresh-revoke");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let r1 = authn.issue_refresh_token(&user).await.unwrap();

    authn
        .revoke_refresh_token(&r1)
        .await
        .expect("revoke must succeed");

    let revoked: i64 = sqlx::query_scalar(
        "select count(*) from refresh_tokens where user_id = $1 and revoked_at is not null",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(revoked, 1, "logout must revoke the family");

    let reason: Option<String> =
        sqlx::query_scalar("select revoked_reason from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason.as_deref(), Some("logout"));

    let err = authn
        .rotate_refresh_token(&r1)
        .await
        .expect_err("revoked must be rejected");
    assert!(matches!(err, AuthnError::RefreshInvalid), "got {err:?}");
}

/// A token whose hash is not in `refresh_tokens` is rejected as
/// `RefreshInvalid`.
#[sqlx::test(migrations = "../db/migrations")]
async fn rotate_refresh_token_invalid_returns_invalid(pool: PgPool) {
    let authn = fresh(pool);
    let err = authn
        .rotate_refresh_token("not-a-real-token")
        .await
        .expect_err("must reject");
    assert!(matches!(err, AuthnError::RefreshInvalid), "got {err:?}");
}

/// A row whose `expires_at` is in the past is rejected as `RefreshInvalid`.
#[sqlx::test(migrations = "../db/migrations")]
async fn rotate_refresh_token_expired_returns_invalid(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("refresh-expired");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let r1 = authn.issue_refresh_token(&user).await.unwrap();

    sqlx::query(
        "update refresh_tokens set expires_at = now() - interval '1 hour' where user_id = $1",
    )
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap();

    let err = authn
        .rotate_refresh_token(&r1)
        .await
        .expect_err("expired must be rejected");
    assert!(matches!(err, AuthnError::RefreshInvalid), "got {err:?}");
}

/// `revoke_refresh_token` on an unknown raw token is a no-op (idempotent).
#[sqlx::test(migrations = "../db/migrations")]
async fn revoke_refresh_token_unknown_is_noop(pool: PgPool) {
    let authn = fresh(pool);
    authn
        .revoke_refresh_token("unknown-token")
        .await
        .expect("idempotent");
}

// ─── Email verification (Stage 3b) ──────────────────────────────────────────

/// `create_email_verification` persists one unused row with a 24-hour TTL
/// and returns the raw token (64-char hex; only `token_hash` is stored).
#[sqlx::test(migrations = "../db/migrations")]
async fn create_email_verification_persists_row(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("ev-create");
    let user = authn.register(&email, "Password123!").await.unwrap();

    let raw = authn
        .create_email_verification(user.id)
        .await
        .expect("create_email_verification");
    assert_eq!(raw.len(), 64, "2 × uuid simple hex");

    let rows: Vec<(bool, bool)> = sqlx::query_as(
        r#"
        select used_at is not null,
               expires_at between now() + interval '23 hours'
                              and now() + interval '25 hours'
        from email_verifications
        where user_id = $1
        "#,
    )
    .bind(user.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    let (used, ttl_ok) = rows[0];
    assert!(!used, "fresh verification token must not be used");
    assert!(
        ttl_ok,
        "expires_at must be ~{EMAIL_VERIFICATION_TTL_HOURS}h in the future"
    );

    let stored_hash: String =
        sqlx::query_scalar("select token_hash from email_verifications where user_id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_hash.len(), 64, "sha-256 hex");
    assert_ne!(stored_hash, raw, "raw token must not be persisted");
}

/// Single-active invariant: a second `create_email_verification` replaces
/// the previous unused token — only the latest one remains valid.
#[sqlx::test(migrations = "../db/migrations")]
async fn create_email_verification_replaces_previous(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("ev-single-active");
    let user = authn.register(&email, "Password123!").await.unwrap();

    let raw1 = authn.create_email_verification(user.id).await.unwrap();
    let raw2 = authn.create_email_verification(user.id).await.unwrap();
    assert_ne!(raw1, raw2, "second call must produce a new raw token");

    let unused: i64 = sqlx::query_scalar(
        "select count(*) from email_verifications where user_id = $1 and used_at is null",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        unused, 1,
        "single-active invariant: at most one unused token per user"
    );

    // The old raw token is gone: verify_email must reject it.
    let err = authn
        .verify_email(&raw1)
        .await
        .expect_err("replaced token must be rejected");
    assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");

    // The new one works.
    let verified = authn
        .verify_email(&raw2)
        .await
        .expect("new token must verify");
    assert!(verified.email_verified);
}

/// `create_email_verification` on an already-verified user returns
/// `AlreadyVerified` and does not create a row.
#[sqlx::test(migrations = "../db/migrations")]
async fn create_email_verification_on_verified_user_returns_already_verified(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("ev-already");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let raw = authn.create_email_verification(user.id).await.unwrap();
    authn.verify_email(&raw).await.expect("first verify");

    let err = authn
        .create_email_verification(user.id)
        .await
        .expect_err("verified user must be rejected");
    assert!(matches!(err, AuthnError::AlreadyVerified), "got {err:?}");

    let count: i64 =
        sqlx::query_scalar("select count(*) from email_verifications where user_id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count, 1,
        "rejected call must not create another verification row"
    );
}

/// `verify_email` writes `users.email_verified_at`, marks the token used, and
/// returns the now-verified `AuthUser`.
#[sqlx::test(migrations = "../db/migrations")]
async fn verify_email_marks_user_verified_and_token_used(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("ev-verify");
    let user = authn.register(&email, "Password123!").await.unwrap();
    assert!(!user.email_verified);

    let raw = authn.create_email_verification(user.id).await.unwrap();
    let verified = authn.verify_email(&raw).await.expect("verify_email");
    assert!(verified.email_verified);
    assert_eq!(verified.id, user.id);

    let verified_at_set: bool =
        sqlx::query_scalar("select email_verified_at is not null from users where id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(verified_at_set, "users.email_verified_at must be set");

    let used_at_set: bool = sqlx::query_scalar(
        "select used_at is not null from email_verifications where user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(used_at_set, "verification token must be marked used");
}

/// `verify_email` is idempotent: re-presenting the same raw token after a
/// successful verification still returns `Ok(user)` and does not move
/// `users.email_verified_at`.
#[sqlx::test(migrations = "../db/migrations")]
async fn verify_email_is_idempotent(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("ev-idempotent");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let raw = authn.create_email_verification(user.id).await.unwrap();

    let first = authn.verify_email(&raw).await.expect("first verify");
    assert!(first.email_verified);
    let first_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("select email_verified_at from users where id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let second = authn
        .verify_email(&raw)
        .await
        .expect("second verify must be Ok");
    assert!(second.email_verified);

    let second_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("select email_verified_at from users where id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        first_at, second_at,
        "already-verified timestamp must not be overwritten"
    );
}

/// `verify_email` rejects an expired token.
#[sqlx::test(migrations = "../db/migrations")]
async fn verify_email_expired_token_returns_invalid(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("ev-expired");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let raw = authn.create_email_verification(user.id).await.unwrap();

    sqlx::query(
        "update email_verifications set expires_at = now() - interval '1 hour' where user_id = $1",
    )
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap();

    let err = authn
        .verify_email(&raw)
        .await
        .expect_err("expired token must be rejected");
    assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");

    let verified_at_set: bool =
        sqlx::query_scalar("select email_verified_at is not null from users where id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !verified_at_set,
        "expired token must not mark the user verified"
    );
}

/// `verify_email` rejects an unknown token.
#[sqlx::test(migrations = "../db/migrations")]
async fn verify_email_invalid_token_returns_invalid(pool: PgPool) {
    let authn = fresh(pool);
    let err = authn
        .verify_email("not-a-real-token")
        .await
        .expect_err("unknown token must be rejected");
    assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");
}

// ─── Password reset (Stage 3d) ──────────────────────────────────────────────

/// `request_password_reset` persists exactly one unused row per user with a
/// 1-hour TTL; only `token_hash` is stored (raw token never persisted).
#[sqlx::test(migrations = "../db/migrations")]
async fn request_password_reset_persists_row(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-create");
    authn.register(&email, "Password123!").await.unwrap();

    let raw = authn
        .request_password_reset(&email)
        .await
        .expect("request_password_reset must succeed")
        .expect("known email must yield Some(raw)");
    assert_eq!(raw.len(), 64, "2 × uuid simple hex");

    let rows: Vec<(bool, bool)> = sqlx::query_as(
        r#"
        select used_at is not null,
               expires_at between now() + interval '55 minutes'
                              and now() + interval '65 minutes'
        from password_reset_tokens
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    let (used, ttl_ok) = rows[0];
    assert!(!used, "fresh reset token must not be used");
    assert!(
        ttl_ok,
        "expires_at must be ~{PASSWORD_RESET_TTL_HOURS}h in the future"
    );

    let stored_hash: String =
        sqlx::query_scalar("select token_hash from password_reset_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_hash.len(), 64, "sha-256 hex");
    assert_ne!(stored_hash, raw, "raw token must not be persisted");
}

/// Single-active: a second `request_password_reset` replaces the previous
/// unused token — only the latest raw works.
#[sqlx::test(migrations = "../db/migrations")]
async fn request_password_reset_replaces_previous(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-single-active");
    authn.register(&email, "Password123!").await.unwrap();

    let raw1 = authn
        .request_password_reset(&email)
        .await
        .unwrap()
        .expect("first request");
    let raw2 = authn
        .request_password_reset(&email)
        .await
        .unwrap()
        .expect("second request");
    assert_ne!(raw1, raw2, "second call must produce a new raw token");

    let unused: i64 =
        sqlx::query_scalar("select count(*) from password_reset_tokens where used_at is null")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        unused, 1,
        "single-active invariant: at most one unused reset token per user"
    );

    // The old raw token is gone.
    let err = authn
        .reset_password(&raw1, "BrandNew123!")
        .await
        .expect_err("replaced token must be rejected");
    assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");

    // The new one works.
    authn
        .reset_password(&raw2, "BrandNew123!")
        .await
        .expect("new token must reset the password");
}

/// Unknown email is silent (`Ok(None)`) and creates no row.
#[sqlx::test(migrations = "../db/migrations")]
async fn request_password_reset_unknown_email_returns_none(pool: PgPool) {
    let authn = fresh(pool.clone());
    let res = authn
        .request_password_reset(&unique_email("pr-unknown"))
        .await
        .expect("must not error");
    assert!(res.is_none(), "unknown email must yield Ok(None)");

    let count: i64 = sqlx::query_scalar("select count(*) from password_reset_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "no row must be created for unknown email");
}

/// `reset_password` changes the password, bumps `password_changed_at`, marks
/// the token used, and returns the `AuthUser`.
#[sqlx::test(migrations = "../db/migrations")]
async fn reset_password_marks_token_used_and_changes_password(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-reset");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let raw = authn
        .request_password_reset(&email)
        .await
        .unwrap()
        .expect("known email");

    let before: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("select password_changed_at from users where id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let updated = authn
        .reset_password(&raw, "BrandNew123!")
        .await
        .expect("reset_password must succeed");
    assert_eq!(updated.id, user.id);

    let used_at_set: bool =
        sqlx::query_scalar("select used_at is not null from password_reset_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(used_at_set, "reset token must be marked used");

    let after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("select password_changed_at from users where id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        after > before,
        "password_changed_at must be bumped by reset_password"
    );

    authn
        .login(&email, "BrandNew123!")
        .await
        .expect("login with new password must succeed");
}

/// One-shot: replaying the same raw reset token returns `TokenInvalid` and
/// does not change the password again.
#[sqlx::test(migrations = "../db/migrations")]
async fn reset_password_is_one_shot(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-one-shot");
    authn.register(&email, "Password123!").await.unwrap();
    let raw = authn
        .request_password_reset(&email)
        .await
        .unwrap()
        .expect("known email");

    authn
        .reset_password(&raw, "BrandNew123!")
        .await
        .expect("first reset must succeed");

    let err = authn
        .reset_password(&raw, "OtherNew123!")
        .await
        .expect_err("replayed reset token must be rejected");
    assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");

    // Password is still the one set by the first reset.
    authn
        .login(&email, "BrandNew123!")
        .await
        .expect("first reset password must still work");
    let bad = authn
        .login(&email, "OtherNew123!")
        .await
        .expect_err("replayed password must not be set");
    assert!(matches!(bad, AuthnError::InvalidCredentials), "got {bad:?}");
}

/// Expired reset token → `TokenExpired`; the user's password is untouched.
#[sqlx::test(migrations = "../db/migrations")]
async fn reset_password_expired_token_returns_token_expired(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-expired");
    authn.register(&email, "Password123!").await.unwrap();
    let raw = authn
        .request_password_reset(&email)
        .await
        .unwrap()
        .expect("known email");

    sqlx::query("update password_reset_tokens set expires_at = now() - interval '1 hour'")
        .execute(&pool)
        .await
        .unwrap();

    let err = authn
        .reset_password(&raw, "BrandNew123!")
        .await
        .expect_err("expired token must be rejected");
    assert!(matches!(err, AuthnError::TokenExpired), "got {err:?}");

    authn
        .login(&email, "Password123!")
        .await
        .expect("original password must still work after expired-token rejection");
}

/// Unknown raw token → `TokenInvalid`.
#[sqlx::test(migrations = "../db/migrations")]
async fn reset_password_invalid_token_returns_token_invalid(pool: PgPool) {
    let authn = fresh(pool);
    let err = authn
        .reset_password("not-a-real-token", "BrandNew123!")
        .await
        .expect_err("unknown token must be rejected");
    assert!(matches!(err, AuthnError::TokenInvalid), "got {err:?}");
}

/// Short password → `IdentityError::Validation` via `AuthnError::Identity`,
/// **before** the token is consumed.
#[sqlx::test(migrations = "../db/migrations")]
async fn reset_password_short_password_returns_validation(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-short");
    authn.register(&email, "Password123!").await.unwrap();
    let raw = authn
        .request_password_reset(&email)
        .await
        .unwrap()
        .expect("known email");

    let err = authn
        .reset_password(&raw, "short")
        .await
        .expect_err("short password must be rejected");
    assert!(
        matches!(
            err,
            AuthnError::Identity(IdentityError::Validation(_))
        ),
        "got {err:?}"
    );

    // Token is still usable: validation failed before the transaction.
    authn
        .reset_password(&raw, "BrandNew123!")
        .await
        .expect("valid password after validation failure must succeed");
}

/// `reset_password` revokes every refresh-token family of the user and
/// records `revoked_reason = 'password_reset'`. Two logins in parallel
/// (two families) are both invalidated.
#[sqlx::test(migrations = "../db/migrations")]
async fn reset_password_revokes_all_refresh_tokens(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-revoke");
    let user = authn.register(&email, "Password123!").await.unwrap();

    let r1 = authn.issue_refresh_token(&user).await.unwrap();
    let r2 = authn.issue_refresh_token(&user).await.unwrap();
    assert_ne!(r1, r2, "two issue calls must yield different tokens");

    let families_before: i64 = sqlx::query_scalar(
        "select count(distinct family_id) from refresh_tokens where user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(families_before, 2, "two distinct families before reset");

    let raw = authn
        .request_password_reset(&email)
        .await
        .unwrap()
        .expect("known email");
    authn
        .reset_password(&raw, "BrandNew123!")
        .await
        .expect("reset must succeed");

    let revoked: i64 = sqlx::query_scalar(
        "select count(*) from refresh_tokens where user_id = $1 and revoked_at is not null",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let total: i64 =
        sqlx::query_scalar("select count(*) from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        revoked, total,
        "reset_password must revoke every refresh-token row of the user"
    );
    assert!(total >= 2, "two rows must be present");

    let reasons: Vec<Option<String>> =
        sqlx::query_scalar("select revoked_reason from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        reasons
            .iter()
            .all(|r| r.as_deref() == Some("password_reset")),
        "every revoked row must record password_reset, got {reasons:?}"
    );

    // Old refresh tokens are no longer usable.
    let err = authn
        .rotate_refresh_token(&r1)
        .await
        .expect_err("old refresh token must be rejected after reset");
    assert!(matches!(err, AuthnError::RefreshInvalid), "got {err:?}");
}

/// `revoke_all_user_tokens` is a public helper (Stage 3d): revokes every
/// not-yet-revoked refresh token of `user_id` with the given `reason`, and
/// does not touch other users' rows.
#[sqlx::test(migrations = "../db/migrations")]
async fn revoke_all_user_tokens_revokes_every_family_of_user(pool: PgPool) {
    let authn = fresh(pool.clone());
    let email = unique_email("pr-revoke-all");
    let user = authn.register(&email, "Password123!").await.unwrap();
    let other = authn
        .register(&unique_email("pr-revoke-all-other"), "Password123!")
        .await
        .unwrap();

    let _u1 = authn.issue_refresh_token(&user).await.unwrap();
    let _u2 = authn.issue_refresh_token(&user).await.unwrap();
    let _o1 = authn.issue_refresh_token(&other).await.unwrap();

    let affected = authn
        .revoke_all_user_tokens(user.id, Some("password_reset"))
        .await
        .expect("revoke_all_user_tokens must succeed");
    assert_eq!(affected, 2, "two rows of the target user revoked");

    let user_revoked: i64 = sqlx::query_scalar(
        "select count(*) from refresh_tokens where user_id = $1 and revoked_at is not null",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let user_total: i64 =
        sqlx::query_scalar("select count(*) from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(user_revoked, user_total, "every row of the target user revoked");

    let other_revoked: i64 = sqlx::query_scalar(
        "select count(*) from refresh_tokens where user_id = $1 and revoked_at is not null",
    )
    .bind(other.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(other_revoked, 0, "other users' tokens must not be touched");

    let user_reasons: Vec<Option<String>> =
        sqlx::query_scalar("select revoked_reason from refresh_tokens where user_id = $1")
            .bind(user.id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        user_reasons
            .iter()
            .all(|r| r.as_deref() == Some("password_reset")),
        "every revoked row must record the supplied reason"
    );

    // Idempotent: second call revokes nothing.
    let again = authn
        .revoke_all_user_tokens(user.id, Some("password_reset"))
        .await
        .expect("second call must succeed");
    assert_eq!(again, 0, "already-revoked rows must be a no-op");
}