//! `auth` endpoints for `saas-axum` (Stage 5.0-A4.4).
//!
//! Ported from `examples/axum-minimal/src/auth.rs` with one substitution:
//! the router state is `Arc<AxumAppState>` (the adapter's single state
//! type), not `axum-minimal`'s flat `AppState`. The four handlers and
//! their semantics are otherwise identical.
//!
//! **Cookies.** `access_cookie` / `refresh_cookie` / `removal_cookie` from
//! [`crate::middleware::auto_refresh`]; `CookieConfig` carries
//! `Secure` / `SameSite` / `Max-Age`.
//!
//! **Rate limit.** `register` uses `state.rate_limit.try_acquire(email,
//! 3, 1h)` — `InMemoryRateLimiter` by default, `RedisRateLimiter` if a
//! consumer installed one. The 4th call in the window → `AppError::RateLimited`
//! (429 + `Retry-After`).
//!
//! **Verification email.** Best-effort: registration succeeds even if
//! SMTP fails. `EmailResult` in the response body tells the caller which
//! outcome to render (`Sent` / `Failed { reason }` / `Disabled`).
//!
//! **Response shapes.**
//!
//! - `register` → `200` + `{ "user": { … }, "email_result": … }`.
//! - `login`    → `200` + `{ … AuthUser … }`.
//! - `logout`   → `204` (empty body).
//! - `refresh`  → `200` + `{ … AuthUser … }`.
//!
//! All four set `Set-Cookie` headers where applicable; the response body
//! carries no tokens.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use domain::AuthUser;
use metrics::counter;
use serde::{Deserialize, Serialize};

use crate::email::EmailResult;
use crate::error::AppError;
use crate::extract::CurrentUser;
use crate::middleware::auto_refresh::{
    access_cookie, refresh_cookie, removal_cookie, ACCESS_COOKIE, REFRESH_COOKIE,
};
use crate::state::AxumAppState;

// ─── DTOs ───────────────────────────────────────────────────────────────────

/// Body of `POST /auth/register` and `POST /auth/login`.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

/// `register` response: the new user plus the (best-effort) verification
/// email outcome. Shape matches `examples/axum-minimal`'s `RegisterResponse`
/// so a consumer that swaps between the two adapters sees no contract
/// difference.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user: AuthUser,
    pub email_result: EmailResult,
}

// ─── POST /auth/register ────────────────────────────────────────────────────

/// Registers a new user, issues access + refresh tokens, sets both
/// cookies, and attempts to send the verification email (best-effort).
///
/// Order:
/// 1. Rate-limit check (`3 / 1h` per raw submitted address).
/// 2. `state.authn.register` — validates email + password, hashes,
///    inserts the `users` row.
/// 3. Issue access + refresh tokens.
/// 4. Attach `Set-Cookie` for both.
/// 5. Create a verification token and attempt delivery. `AlreadyVerified`
///    right after `register` is unreachable in practice (`email_verified_at`
///    is `NULL` on insert) but is handled: log + `Disabled`.
pub async fn register(
    State(state): State<Arc<AxumAppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 1. Rate limit.
    if let Err(retry_after) = state
        .rate_limit
        .try_acquire(&body.email, 3, Duration::from_secs(3600))
        .await
    {
        counter!("register_total", "status" => "rate_limited").increment(1);
        return Err(AppError::rate_limited(retry_after));
    }

    // 2. Register.
    let user = match state.authn.register(&body.email, &body.password).await {
        Ok(u) => {
            counter!("register_total", "status" => "success").increment(1);
            u
        }
        Err(e) => {
            counter!("register_total", "status" => "failed").increment(1);
            return Err(e.into());
        }
    };

    // 3. Tokens.
    let access = state.authn.issue_access_token(&user)?;
    let refresh = state.authn.issue_refresh_token(&user).await?;

    // 4. Cookies.
    let jar = CookieJar::new()
        .add(access_cookie(access, &state.cookie))
        .add(refresh_cookie(refresh, &state.cookie));

    // 5. Best-effort verification email.
    let email_result = match state.authn.create_email_verification(user.id).await {
        Ok(token) => state.email.send_verification(&user.email, &token).await,
        Err(authn::AuthnError::AlreadyVerified) => {
            tracing::error!(
                user_id = %user.id,
                "register: user already verified immediately after creation; skipping verification email"
            );
            EmailResult::Disabled
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                user_id = %user.id,
                "register: create_email_verification failed; verification email not sent"
            );
            EmailResult::Failed {
                reason: e.to_string(),
            }
        }
    };

    Ok((jar, Json(RegisterResponse { user, email_result })))
}

// ─── POST /auth/login ───────────────────────────────────────────────────────

/// Logs in an existing user, issues access + refresh tokens, sets both
/// cookies.
///
/// `InvalidCredentials` (unknown email or wrong password) maps to 401 via
/// [`AppError`]; the underlying `state.authn.login` already emits
/// `user.login_failed` / `user.login_succeeded` audit events.
pub async fn login(
    State(state): State<Arc<AxumAppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = match state.authn.login(&body.email, &body.password).await {
        Ok(u) => {
            counter!("login_total", "status" => "success").increment(1);
            u
        }
        Err(e) => {
            counter!("login_total", "status" => "failed").increment(1);
            return Err(e.into());
        }
    };

    let access = state.authn.issue_access_token(&user)?;
    let refresh = state.authn.issue_refresh_token(&user).await?;

    let jar = CookieJar::new()
        .add(access_cookie(access, &state.cookie))
        .add(refresh_cookie(refresh, &state.cookie));

    Ok((jar, Json(user)))
}

// ─── POST /auth/logout ──────────────────────────────────────────────────────

/// Clears both cookies and (if a refresh cookie is present) revokes its
/// family in the database.
///
/// Access JWT stays valid until its short `exp`; the refresh family is
/// revoked (`revoked_reason = "logout"`), so the session cannot be
/// extended. An unknown/absent refresh cookie is a silent no-op.
pub async fn logout(
    State(state): State<Arc<AxumAppState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    if let Some(raw) = jar.get(REFRESH_COOKIE).map(|c| c.value().to_string()) {
        state.authn.revoke_refresh_token(&raw).await?;
    }

    let out = CookieJar::new()
        .add(removal_cookie(ACCESS_COOKIE, &state.cookie))
        .add(removal_cookie(REFRESH_COOKIE, &state.cookie));

    Ok((out, StatusCode::NO_CONTENT))
}

// ─── POST /auth/refresh ─────────────────────────────────────────────────────

/// Returns the current authenticated user.
///
/// By the time this handler runs, [`crate::middleware::auto_refresh`] has
/// already verified (or rotated) the tokens — `CurrentUser` only pulls
/// the resolved value from request extensions. `require()` → 401 if the
/// request is anonymous or the session could not be refreshed.
pub async fn refresh(current: CurrentUser) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    Ok(Json(user))
}
