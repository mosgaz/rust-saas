//! Auto-refresh middleware (Stage 3g, ported from `saas-leptos`).
//!
//! Runs on every request of the **protected** router before the handlers.
//! Responsibilities:
//!
//! 1. Read `access_token` (access JWT) and `refresh_token` (opaque) cookies.
//! 2. If `access_token` verifies — insert `Option<AuthUser>::Some(user)` into
//!    request extensions.
//! 3. If `access_token` is missing or expired — try
//!    `Authn::rotate_refresh_token` with `refresh_token`; on success, issue a
//!    new access token, append both `Set-Cookie` headers to the response,
//!    and insert `Some(user)`.
//! 4. If no user could be resolved — insert `None`.
//!
//! [`crate::extract::CurrentUser`] (`FromRequestParts`) reads that extension;
//! handlers on protected routes call `CurrentUser::require()` to turn an
//! anonymous request into HTTP 401.
//!
//! **Stage 4.1b:** cookies are built via [`CookieConfig`] — `Secure` (env
//! `COOKIE_SECURE`, default = non-loopback bind address), `SameSite=Lax`,
//! `Max-Age` = access / refresh TTL. `auto_refresh` takes the full
//! [`AppState`] via `State` (not a tuple) — `State<T>` requires
//! `T: FromRef<RouterState>`, and `AppState` already provides
//! `FromRef<AppState> for Arc<Authn>` / `Arc<CookieConfig>`, so extracting
//! both pieces out of one `Arc<AppState>` is a plain clone.

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
use crate::state::AppState;

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
/// - `Max-Age` = `CookieConfig::access_max_age()`.
pub fn access_cookie(token: String, cfg: &CookieConfig) -> Cookie<'static> {
    Cookie::build((ACCESS_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(cfg.secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(cfg.access_max_age().as_secs() as i64))
        .build()
}

/// Builds a `refresh_token` cookie. Same attributes as [`access_cookie`];
/// `Max-Age` = `CookieConfig::refresh_max_age()`.
pub fn refresh_cookie(token: String, cfg: &CookieConfig) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(cfg.secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(cfg.refresh_max_age().as_secs() as i64))
        .build()
}

/// Builds a removal cookie (`Max-Age=0`, `Expires` in the past) carrying
/// `Secure` / `SameSite` from the config.
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
///
/// `State<Arc<AppState>>` — the router state; `Authn` and `CookieConfig` are
/// cloned out of `app_state` once per request. This avoids a tuple
/// `State<(Arc<Authn>, Arc<CookieConfig>)>` (which would need extra
/// `FromRef` impls) while keeping the middleware unit-testable via
/// `AppState`.
pub async fn auto_refresh(
    State(app_state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let authn = app_state.authn.clone();
    let cookie_cfg = app_state.cookie.clone();

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
