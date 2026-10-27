//! Integration-тесты `authn` на реальной PostgreSQL.
//!
//! `#[sqlx::test]` для каждого теста:
//!   - создаёт изолированную БД на сервере из `DATABASE_URL` (`.env` в корне
//!     workspace читается автоматически благодаря `dotenvy`-фиче `sqlx`);
//!   - накатывает `crates/db/migrations`;
//!   - удаляет БД после теста.
//!
//! Ручной `createdb` больше не нужен. `DATABASE_URL` должен указывать на сервер,
//! где пользователь имеет право `CREATE DATABASE` (postgres-superuser подходит).

use authn::{Authn, AuthnError};
use identity::IdentityError;
use sqlx::PgPool;
use uuid::Uuid;

fn fresh(pool: PgPool) -> Authn {
    Authn::new(pool, "test-jwt-secret-not-for-production")
}

fn unique_email(label: &str) -> String {
    format!("{label}-{}@test.local", Uuid::new_v4())
}

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
    let token = authn.issue_token(&user).unwrap();

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
    let token = authn.issue_token(&user).unwrap();

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