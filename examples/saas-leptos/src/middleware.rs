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
use axum_extra::extract::cookie::{Cookie, CookieJar};
use domain::AuthUser;

/// Access-cookie name (access JWT, short-lived).
pub const ACCESS_COOKIE: &str = "access_token";

/// Refresh-cookie name (opaque, long-lived, rotation with family revocation).
pub const REFRESH_COOKIE: &str = "refresh_token";

/// Builds an `access_token` cookie (httpOnly, path `/`, session lifetime).
pub fn access_cookie(token: String) -> Cookie<'static> {
    Cookie::build((ACCESS_COOKIE, token))
        .path("/")
        .http_only(true)
        .build()
}

/// Builds a `refresh_token` cookie (httpOnly, path `/`, session lifetime).
pub fn refresh_cookie(token: String) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE, token))
        .path("/")
        .http_only(true)
        .build()
}

/// Builds a removal cookie (`Max-Age=0`, `Expires` in the past).
///
/// `Cookie::make_removal` in `cookie 0.18` is a `&mut self` method; build the
/// empty cookie first, then apply removal, then restore `Path` / `HttpOnly`
/// (they are not affected by `make_removal` but are set here explicitly for
/// symmetry with the set-side cookies).
pub fn removal_cookie(name: &'static str) -> Cookie<'static> {
    let mut c = Cookie::new(name, String::new());
    c.make_removal();
    c.set_path("/");
    c.set_http_only(true);
    c
}

/// Auto-refresh layer. See module docs.
pub async fn auto_refresh(
    State(authn): State<Arc<Authn>>,
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
                try_refresh(&authn, refresh.as_deref(), &mut issued).await
            }
            Err(_) => None,
        },
        None => try_refresh(&authn, refresh.as_deref(), &mut issued).await,
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
) -> Option<AuthUser> {
    let raw = refresh?;
    let (new_refresh, user) = authn.rotate_refresh_token(raw).await.ok()?;
    let new_access = authn.issue_access_token(&user).ok()?;
    issued.push(access_cookie(new_access));
    issued.push(refresh_cookie(new_refresh));
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