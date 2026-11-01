//! Auto-refresh middleware (Stage 2b).
//!
//! Runs on every request before Leptos handlers. Responsibilities:
//!
//! 1. Read `access_token` (access JWT) and `refresh_token` (opaque) cookies.
//! 2. If `access_token` verifies — inject `Extension<Option<AuthUser>>`.
//! 3. If `access_token` is missing or expired — try `Authn::rotate_refresh_token`
//!    with `refresh_token`; on success, issue a new access token, set both
//!    cookies on the response, and inject the authenticated user.
//! 4. If no user could be resolved — inject `Extension(None)`.
//!
//! Serialization: refresh happens **at most once per HTTP request**, which
//! avoids a race where two concurrent `#[server]` calls in the same SSR page
//! would each try to rotate the same refresh token (the second would be
//! treated as `RefreshReused`, revoking the family and logging the user out).
//!
//! Coexistence with `#[server] {register, login, logout, refresh}`: if a
//! handler already set a cookie with the same name (`access_token` or
//! `refresh_token`), the middleware's `Set-Cookie` for that name is skipped,
//! so logout (`Max-Age=0`) is not overwritten by a concurrent rotation.
//!
//! `Cache-Control: no-store` is added whenever cookies are (re)issued, so
//! that browsers and proxies do not cache a response carrying `Set-Cookie`.

use std::collections::HashSet;
use std::sync::Arc;

use authn::{Authn, AuthnError};
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, SET_COOKIE};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use cookie::time::Duration as CookieDuration;
use domain::AuthUser;

use crate::cookie::CookieConfig;

/// Access-cookie name (access JWT, short-lived).
pub const ACCESS_COOKIE: &str = "access_token";

/// Refresh-cookie name (opaque, long-lived, rotation with family revocation).
pub const REFRESH_COOKIE: &str = "refresh_token";

/// Builds an `access_token` cookie.
///
/// Attributes (Stage 4.1b):
/// - `HttpOnly` — not readable by JS.
/// - `Secure` — from `CookieConfig::secure`.
/// - `SameSite=Lax` — sent on top-level navigation only.
/// - `Path=/`.
/// - `Max-Age` = `CookieConfig::access_max_age()`. Persistent, so the
///   browser keeps it across restarts until the JWT itself expires.
pub fn access_cookie(token: String, cfg: &CookieConfig) -> Cookie<'static> {
    Cookie::build((ACCESS_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(cfg.secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(cfg.access_max_age().as_secs() as i64))
        .build()
}

/// Builds a `refresh_token` cookie. Same attributes as
/// [`access_cookie`]; `Max-Age` = `CookieConfig::refresh_max_age()`.
pub fn refresh_cookie(token: String, cfg: &CookieConfig) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(cfg.secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(cfg.refresh_max_age().as_secs() as i64))
        .build()
}

/// Builds a removal cookie (`Max-Age=0`, `Expires` in the past). The
/// `Secure` / `SameSite` attributes are carried through so that a browser
/// which stored the original cookie with `Secure` will also accept the
/// deletion.
pub fn removal_cookie(name: &'static str, cfg: &CookieConfig) -> Cookie<'static> {
    let mut c = Cookie::new(name, String::new());
    c.make_removal();
    c.set_path("/");
    c.set_http_only(true);
    c.set_secure(cfg.secure);
    c.set_same_site(SameSite::Lax);
    c
}

/// Auto-refresh layer. See module docs.
pub async fn auto_refresh(
    State((authn, cookie_cfg)): State<(Arc<Authn>, Arc<CookieConfig>)>,
    mut req: Request,
    next: Next,
) -> Response {
    let jar = CookieJar::from_headers(req.headers());
    let access = jar.get(ACCESS_COOKIE).map(|c| c.value().to_string());
    let refresh = jar.get(REFRESH_COOKIE).map(|c| c.value().to_string());

    let mut issued: Vec<Cookie<'static>> = Vec::new();

    let user: Option<AuthUser> = match access {
        Some(tok) => match authn.verify_token(&tok).await {
            Ok(Some(u)) => Some(u),
            Ok(None) => None,
            Err(AuthnError::TokenExpired) => {
                try_refresh(&authn, refresh.as_deref(), &mut issued, &cookie_cfg).await
            }
            Err(_) => None,
        },
        None => try_refresh(&authn, refresh.as_deref(), &mut issued, &cookie_cfg).await,
    };

    req.extensions_mut().insert::<Option<AuthUser>>(user);

    let mut response = next.run(req).await;

    if !issued.is_empty() {
        let existing = set_cookie_names(&response);
        for c in issued {
            if existing.contains(c.name()) {
                continue;
            }
            if let Ok(hv) = HeaderValue::from_str(&c.to_string()) {
                response.headers_mut().append(SET_COOKIE, hv);
            }
        }
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }

    response
}

async fn try_refresh(
    authn: &Authn,
    refresh: Option<&str>,
    issued: &mut Vec<Cookie<'static>>,
    cfg: &CookieConfig,
) -> Option<AuthUser> {
    let raw = refresh?;
    let (new_refresh, user) = authn.rotate_refresh_token(raw).await.ok()?;
    let new_access = authn.issue_access_token(&user).ok()?;
    issued.push(access_cookie(new_access, cfg));
    issued.push(refresh_cookie(new_refresh, cfg));
    Some(user)
}

/// Collects the names of cookies already present in the response's
/// `Set-Cookie` headers.
fn set_cookie_names(response: &Response) -> HashSet<String> {
    let mut names = HashSet::new();
    for hv in response.headers().get_all(SET_COOKIE) {
        if let Ok(s) = hv.to_str() {
            if let Ok(c) = Cookie::parse(s.to_owned()) {
                names.insert(c.name().to_string());
            }
        }
    }
    names
}
// ─── Stage 4.1c: Origin/Host same-origin guard ─────────────────────────────

/// Rejects cross-origin mutation requests on the protected router
/// (`/_server/*` RPC and SSR pages). This is the `saas-leptos`
/// counterpart of `axum-minimal`'s CSRF double-submit:
///
/// - **`axum-minimal`** — `csrf` cookie + `X-CSRF-Token` header
///   (`examples/axum-minimal/src/csrf.rs`).
/// - **`saas-leptos`** — Leptos `#[server]` does not expose a
///   server-function client hook that would let us inject a custom header
///   into every call. Instead, `SameSite=Lax` on `access_token` /
///   `refresh_token` already blocks cross-site form submits and `img`-GET
///   side effects; the remaining hole is a top-level navigation that
///   `Lax` permits. `Origin` is sent by every browser on `POST` /
///   `PUT` / `PATCH` / `DELETE`, so comparing its authority with `Host`
///   closes that hole without touching the Leptos pipeline.
///
/// Contract:
/// - Non-mutating methods pass through.
/// - Missing `Origin` (non-browser clients: `curl`, SSR probes) — pass
///   through. A CSRF attacker is a **browser**, and browsers always send
///   `Origin` on cross-origin mutations.
/// - `Origin` authority ≠ `Host` authority — reject with 403.
/// - `Origin` authority = `Host` authority (ignoring scheme) — pass
///   through.
///
/// Authority comparison ignores the scheme (`https://` vs `http://`) so
/// that a reverse proxy terminating TLS in front of an HTTP backend does
/// not cause false positives. Ports are kept (`localhost:3395` ≠
/// `localhost:3396`), which is the correct semantic for CSRF.
pub async fn same_origin_guard(req: Request, next: Next) -> Response {
    use axum::http::Method;

    let is_mutation = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if !is_mutation {
        return next.run(req).await;
    }

    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // `Origin: null` (opaque origin, e.g. sandboxed iframe or some
    // redirects) — reject explicitly; a legitimate app never sends it.
    if let Some(o) = origin.as_deref() {
        if o == "null" {
            return cross_origin_forbidden();
        }
        let origin_authority = o.splitn(2, "://").nth(1).unwrap_or(o);
        match host.as_deref() {
            Some(h) if origin_authority == h => next.run(req).await,
            Some(_) => cross_origin_forbidden(),
            // No `Host` header (HTTP/1.0 without host, or malformed).
            // Fail closed if we have an `Origin` but no `Host` to compare
            // against — otherwise an attacker could strip `Host` via a
            // proxy misconfiguration.
            None => cross_origin_forbidden(),
        }
    } else {
        // No `Origin` header — non-browser client. Browsers send `Origin`
        // on every `POST`/`PUT`/`PATCH`/`DELETE`; missing `Origin` here
        // means the caller is not a browser, and a CSRF attack requires a
        // browser. Pass through.
        next.run(req).await
    }

}


/// Rejection response for cross-origin mutations — same body shape as
/// `AppError`: `{"error": "..."}`.
fn cross_origin_forbidden() -> Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": "cross-origin request rejected" })),
    )
        .into_response()
}

#[cfg(test)]
mod origin_guard_tests {
    //! Unit-testable pieces of `same_origin_guard`: authority extraction
    //! and the mutation-method predicate. The middleware itself is
    //! exercised end-to-end in the README smoke checklist (curl against a
    //! running instance).

    fn authority(origin: &str) -> &str {
        origin.splitn(2, "://").nth(1).unwrap_or(origin)
    }

    #[test]
    fn authority_strips_scheme() {
        assert_eq!(authority("https://example.com"), "example.com");
        assert_eq!(authority("http://localhost:3395"), "localhost:3395");
    }

    #[test]
    fn authority_keeps_port() {
        assert_ne!(authority("http://localhost:3395"), "localhost:3396");
    }

    #[test]
    fn same_origin_passes() {
        let origin = "http://localhost:3395";
        let host = "localhost:3395";
        assert_eq!(authority(origin), host);
    }

    #[test]
    fn cross_origin_fails() {
        let origin = "https://evil.example";
        let host = "localhost:3395";
        assert_ne!(authority(origin), host);
    }
}
