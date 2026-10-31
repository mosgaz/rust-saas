//! Auth handlers for `axum-minimal` (Stage 3g).
//!
//! Mirrors `examples/saas-leptos/src/auth.rs` for the four endpoints in
//! plan §3:
//!
//! - `POST /auth/register` — create user, issue tokens, set cookies,
//!   best-effort verification email. Rate limited `3 / 1h` per email.
//! - `POST /auth/login`    — verify credentials, issue tokens, set cookies.
//! - `POST /auth/logout`   — revoke refresh family (if a cookie is present),
//!   clear both cookies.
//! - `POST /auth/refresh`  — return the current actor (after `auto_refresh`
//!   has rotated tokens if needed).
//!
//! **Cookies.** Managed by this module, not by `authn` — same split as
//! `saas-leptos`. Cookie attributes in 3g: `path = "/"`, `http_only = true`,
//! session lifetime. `Secure` / `SameSite` are Stage 4. The actual
//! `access_token` / `refresh_token` cookies are built by
//! [`crate::middleware::{access_cookie, refresh_cookie, removal_cookie}`].
//!
//! **Rate limit.** `register` is limited to `3 / 1 h` per email address
//! (plan §10: "Rate limit на register — 3/час per email"). The 4th call in
//! the window returns 429 with `Retry-After`. The limiter is
//! `state.rate_limit` (in-memory, per-process — see `rate_limit.rs`).
//!
//! **Best-effort verification email.** Registration succeeds even if the
//! email attempt fails: `EmailResult` is returned in the response body, the
//! business operation is not rolled back. `axum-minimal` ships only
//! [`crate::email::NoopEmailSender`], so the observed outcome is always
//! [`crate::email::EmailResult::Disabled`]; the code path is identical to
//! `saas-leptos`, where a real `SmtpEmailSender` can produce `Sent` /
//! `Failed { reason }`.
//!
//! **No `set_return_url` / `take_return_url`.** Stage 3a's return-URL
//! mechanism exists for the Leptos invitation flow, which is out of scope
//! for 3g (plan §1: invitations are not part of the portability proof).
//!
//! **Response shapes.**
//!
//! - `register` → `200` + `{ "user": { … }, "email_result": { … } }`
//! - `login`    → `200` + `{ "id": …, "email": …, "email_verified": …, "created_at": … }`
//! - `logout`   → `204` (empty body)
//! - `refresh`  → `200` + `{ … AuthUser … }`
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
use serde::{Deserialize, Serialize};

use crate::email::EmailResult;
use crate::error::AppError;
use crate::extract::CurrentUser;
use crate::middleware::{
    access_cookie, refresh_cookie, removal_cookie, ACCESS_COOKIE, REFRESH_COOKIE,
};
use crate::state::AppState;

// ─── Request / response DTOs ───────────────────────────────────────────────

/// Body of `POST /auth/register` and `POST /auth/login`.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

/// `register` returns the new user plus the (best-effort) verification
/// email outcome. Struct (not a tuple) so the JSON is self-describing; the
/// contract carried from `saas-leptos` is the `(AuthUser, EmailResult)`
/// pair, and this is its serialized form.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user: AuthUser,
    pub email_result: EmailResult,
}

// ─── POST /auth/register ────────────────────────────────────────────────────

/// Registers a new user, issues access + refresh tokens, sets both cookies,
/// and attempts to send the verification email (best-effort).
///
/// Order:
/// 1. Rate-limit check (`3 / 1 h` per email, key = raw submitted address —
///    so an attacker probing many addresses is still throttled per address).
/// 2. `authn.register` — validates email + password, hashes, inserts the
///    `users` row.
/// 3. Issue access + refresh tokens.
/// 4. Attach `Set-Cookie` for both.
/// 5. Create a verification token and attempt delivery. `AlreadyVerified`
///    right after `register` is unreachable in practice (`email_verified_at`
///    is `NULL` on insert) but is handled: log + `Disabled`.
///
/// Verification email is sent **after** cookies are set: registration
/// succeeds even if delivery fails. The `EmailResult` in the body tells the
/// caller which outcome to render.
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 1. Rate limit.
    if let Err(retry_after) = state
        .rate_limit
        .try_acquire(&body.email, 3, Duration::from_secs(3600))
    {
        return Err(AppError::rate_limited(retry_after));
    }

    // 2. Register.
    let user = state.authn.register(&body.email, &body.password).await?;

    // 3. Tokens.
    let access = state.authn.issue_access_token(&user)?;
    let refresh = state.authn.issue_refresh_token(&user).await?;

    // 4. Cookies.
    let jar = CookieJar::new()
        .add(access_cookie(access))
        .add(refresh_cookie(refresh));

    // 5. Best-effort verification email. Same handling as `saas-leptos`:
    //    `AlreadyVerified` is logged and degraded to `Disabled`;
    //    other failures are returned as `Failed { reason }` in the body.
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
/// [`AppError`]; the underlying `authn.login` already emits
/// `user.login_failed` / `user.login_succeeded` audit events (Stage 3e —
/// unchanged).
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = state.authn.login(&body.email, &body.password).await?;

    let access = state.authn.issue_access_token(&user)?;
    let refresh = state.authn.issue_refresh_token(&user).await?;

    let jar = CookieJar::new()
        .add(access_cookie(access))
        .add(refresh_cookie(refresh));

    Ok((jar, Json(user)))
}

// ─── POST /auth/logout ──────────────────────────────────────────────────────

/// Clears both cookies and (if a refresh cookie is present) revokes its
/// family in the database.
///
/// Access JWT stays valid until its short `exp`; the refresh family is
/// revoked (`revoked_reason = "logout"`), so the session cannot be
/// extended. An unknown/absent refresh cookie is a silent no-op — the
/// response still clears the client cookies, matching `saas-leptos`
/// behaviour.
pub async fn logout(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    if let Some(raw) = jar.get(REFRESH_COOKIE).map(|c| c.value().to_string()) {
        state.authn.revoke_refresh_token(&raw).await?;
    }

    let out = CookieJar::new()
        .add(removal_cookie(ACCESS_COOKIE))
        .add(removal_cookie(REFRESH_COOKIE));

    Ok((out, StatusCode::NO_CONTENT))
}

// ─── POST /auth/refresh ─────────────────────────────────────────────────────

/// Returns the current authenticated user.
///
/// By the time this handler runs, [`crate::middleware::auto_refresh`] has
/// already verified (or rotated) the tokens — `CurrentUser` only pulls the
/// resolved value from request extensions. `require()` → 401 if the request
/// is anonymous or the session could not be refreshed.
///
/// In `saas-leptos` the analogous `#[server] refresh` is called from the
/// client side after a successful `auto_refresh`-driven rotation, so that
/// new cookies take effect across subsequent requests. In `axum-minimal`
/// cookies are set by `auto_refresh` (on the response) or by `register` /
/// `login`; the caller does not need to do anything extra — this endpoint
/// is a "who am I after refresh?" probe.
pub async fn refresh(current: CurrentUser) -> Result<impl IntoResponse, AppError> {
    let user = current.require()?;
    Ok(Json(user))
}