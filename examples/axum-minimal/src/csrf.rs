//! CSRF protection for `axum-minimal` (Stage 4.1c).
//!
//! Double-submit cookie: a `csrf` cookie (non-HttpOnly, so client JS can
//! read it) + an `X-CSRF-Token` header. Any mutating request must present
//! both, with matching values. The cookie is `SameSite=Lax` so that a
//! cross-origin form submit cannot reach a mutation endpoint even before
//! the header check runs.
//!
//! Two middlewares:
//! - [`csrf_issue`] — runs on the whole router (public + protected). If
//!   the request has no `csrf` cookie, it sets one on the response. This
//!   is how a client bootstraps: the first GET receives the cookie, the
//!   next mutation can echo it back in the header.
//! - [`csrf_guard`] — runs on the protected router only. On
//!   `POST/PUT/PATCH/DELETE` (excluding `/auth/{register,login,logout}`),
//!   rejects with 403 if the cookie is missing, the header is missing, or
//!   the two differ.
//!
//! `SameSite=Lax` on the `csrf` cookie, together with the existing
//! `SameSite=Lax` on `access_token` / `refresh_token`, already blocks
//! cross-site form submits and `<img>`-based GET side effects. The
//! double-submit closes the remaining case: an attacker who can force a
//! top-level navigation (which `Lax` allows) still cannot read the
//! `csrf` cookie from the victim's origin, so the header check fails.
//!
//! Not tied to a session: the token is rotated only by the bootstrap step
//! (first request). Logout does not invalidate it — `SameSite` plus the
//! access-token boundary is what protects logout itself, and logout is
//! idempotent. A future Stage 4.x may rotate the token on login; today
//! the reference keeps one token per browser session lifetime.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use cookie::time::Duration as CookieDuration;

use crate::cookie::CookieConfig;
use crate::state::AppState;

/// Cookie name carrying the double-submit token. Non-HttpOnly by design —
/// the client-side code must read it to fill `X-CSRF-Token`.
pub const CSRF_COOKIE: &str = "csrf";

/// Header name the client must echo the cookie value in.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Auth paths that run on the public router and do not need the guard:
/// `register` / `login` have no session yet; `logout` is idempotent and
/// only revokes a family the caller already owns.
const PUBLIC_AUTH_PATHS: &[&str] = &["/auth/register", "/auth/login", "/auth/logout"];

fn is_mutation(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn is_public_auth(path: &str) -> bool {
    PUBLIC_AUTH_PATHS.contains(&path)
}

fn new_token() -> String {
    // 2 × UUIDv4 simple hex = 64 hex chars — same shape as the refresh /
    // verification tokens, so the debugging tools treat them uniformly.
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn build_cookie(token: String, cfg: &CookieConfig) -> Cookie<'static> {
    Cookie::build((CSRF_COOKIE, token))
        .path("/")
        // Not HttpOnly: the browser client reads this to build the header.
        .http_only(false)
        .secure(cfg.secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(
            cfg.refresh_max_age().as_secs() as i64
        ))
        .build()
}

/// Ensures a `csrf` cookie is present in the response. Runs on **every**
/// route (public + protected), after the handler — if the client did not
/// present a `csrf` cookie, one is generated and `Set-Cookie`d. If the
/// handler already set a `csrf` cookie (none do today, but future-proof),
/// it is left alone.
pub async fn csrf_issue(
    State(app_state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // `/healthz` is a readiness probe: the orchestrator hits it every 10s,
    // and issuing a fresh `csrf` cookie on each hit serves no one. Pass
    // through without touching the response.
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }

    let had_cookie = CookieJar::from_headers(req.headers())
        .get(CSRF_COOKIE)
        .is_some();

    let mut response = next.run(req).await;

    if had_cookie {
        return response;
    }

    let handler_set = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|hv| hv.to_str().ok())
        .any(|s| s.starts_with(CSRF_COOKIE));

    if handler_set {
        return response;
    }

    let cookie = build_cookie(new_token(), &app_state.cookie);
    if let Ok(hv) = HeaderValue::from_str(&cookie.to_string()) {
        response.headers_mut().append(SET_COOKIE, hv);
    }
    response
}

/// Rejects mutating requests whose `X-CSRF-Token` header does not match
/// the `csrf` cookie. Attached only to the protected router.
pub async fn csrf_guard(req: Request, next: Next) -> Response {
    if !is_mutation(req.method()) || is_public_auth(req.uri().path()) {
        return next.run(req).await;
    }

    let jar = CookieJar::from_headers(req.headers());
    let cookie_token = jar.get(CSRF_COOKIE).map(|c| c.value().to_string());
    let header_token = req
        .headers()
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match (cookie_token, header_token) {
        (Some(c), Some(h)) if constant_time_eq(c.as_bytes(), h.as_bytes()) => next.run(req).await,
        _ => {
            // Same body shape as `AppError`: `{"error": "..."}`.
            (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": "csrf token mismatch" })),
            )
                .into_response()
        }
    }
}

/// Length-checked, byte-wise XOR comparison. Avoids an early-exit
/// comparison that could leak the token's prefix through timing. Not a
/// cryptographic boundary on its own — the token is public to the
/// client; this just avoids a trivially observable oracle.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Test-only surface for other modules that need to cross-check the
/// public-auth path list against their own (see `auth_layer::tests`).
/// Enabled only under `cfg(test)`; never compiled into the binary.
#[cfg(test)]
pub mod tests_support {
    /// The same list `csrf_guard` uses to exempt public auth endpoints.
    /// `auth_layer` keeps an identical copy — if the two ever drift, that
    /// is a security bug (one layer would let through what the other
    /// blocks), so a unit test asserts equality.
    pub fn public_auth_paths() -> &'static [&'static str] {
        super::PUBLIC_AUTH_PATHS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_64_hex() {
        let t = new_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(new_token(), new_token());
    }

    #[test]
    fn mutation_detects_all_verbs() {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(is_mutation(&m), "{m} must be a mutation");
        }
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!is_mutation(&m), "{m} must not be a mutation");
        }
    }

    #[test]
    fn public_auth_paths_are_recognized() {
        assert!(is_public_auth("/auth/register"));
        assert!(is_public_auth("/auth/login"));
        assert!(is_public_auth("/auth/logout"));
        assert!(!is_public_auth("/auth/refresh"));
        assert!(!is_public_auth("/tenants"));
    }

    #[test]
    fn constant_time_eq_accepts_equal() {
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn constant_time_eq_rejects_different() {
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
