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

use authn::{Authn, AuthnError, REFRESH_GRACE_SECONDS};
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

    let logged = authn
        .login(&email, "Password123!")
        .await
        .expect("login must succeed");
    assert_eq!(logged.id, user.id);
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
/// NULL, `expires_at` in the future.
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

    let rows: Vec<(bool, bool, bool)> = sqlx::query_as(
        r#"
        select used_at is not null,
               revoked_at is not null,
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
    let (used, revoked, live) = rows[0];
    assert!(!used, "fresh token must not be used");
    assert!(!revoked, "fresh token must not be revoked");
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
/// the whole family and returns `RefreshReused`.
///
/// Stage 2d: `used_at` is forced to be older than
/// [`REFRESH_GRACE_SECONDS`] before the second rotation attempt, so the
/// second call is treated as a genuine reuse (not as a parallel-request
/// race).
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
    let family_id: Uuid =
        sqlx::query_scalar("select family_id from refresh_tokens where user_id = $1 limit 1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let _ = family_id;
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

/// `revoke_refresh_token` (logout) sets `revoked_at`; a subsequent rotate
/// returns `RefreshInvalid`.
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