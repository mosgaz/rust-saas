//! Cookie configuration for auth cookies (Stage 4.1b).
//!
//! `Secure` is required for HTTPS. The reference dev environment runs over
//! plain HTTP on `127.0.0.1`, so the default is "Secure iff the bind address
//! is not loopback"; `COOKIE_SECURE=1|0` overrides it. A `false` value logs
//! a warning — acceptable only for local development.
//!
//! `SameSite=Lax` is set explicitly (matches the `cookie` crate default, but
//! is part of the contract). `Max-Age` is set on both auth cookies:
//! `access_token` lives for the access TTL, `refresh_token` for the refresh
//! TTL. Both are refreshed on each rotation (see `middleware::auto_refresh`).

use std::net::SocketAddr;
use std::time::Duration;

use chrono::TimeDelta;

/// Resolved cookie policy for the process. Built once in `main.rs` from
/// the bind address and the access/refresh TTL environment variables, then
/// shared as `Arc<CookieConfig>` with the auth handlers and the
/// auto-refresh middleware.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// `true` → `Secure` cookie attribute. Set from `COOKIE_SECURE` env
    /// when present; otherwise defaults to `true` for any non-loopback
    /// bind address.
    pub secure: bool,
    /// Access-token TTL (mirrors `Authn::with_ttl`).
    pub access_ttl: TimeDelta,
    /// Refresh-token TTL (mirrors `Authn::with_ttl`).
    pub refresh_ttl: TimeDelta,
}

impl CookieConfig {
    /// Builds the config from the bind address and env. Must be called with
    /// the same `ACCESS_TOKEN_TTL_MINUTES` / `REFRESH_TOKEN_TTL_DAYS` the
    /// `Authn` instance was built with — otherwise `Max-Age` may not match
    /// the JWT lifetime.
    pub fn from_env(bind: &SocketAddr) -> Self {
        let secure = match std::env::var("COOKIE_SECURE") {
            Ok(v) => matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            Err(_) => !bind.ip().is_loopback(),
        };
        if !secure {
            tracing::warn!(
                "COOKIE_SECURE resolves to false: auth cookies are NOT marked \
                 Secure. Acceptable only for local HTTP development; set \
                 COOKIE_SECURE=1 for any deployment."
            );
        }

        let access_ttl = TimeDelta::minutes(
            std::env::var("ACCESS_TOKEN_TTL_MINUTES")
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(15),
        );
        let refresh_ttl = TimeDelta::days(
            std::env::var("REFRESH_TOKEN_TTL_DAYS")
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(30),
        );

        Self {
            secure,
            access_ttl,
            refresh_ttl,
        }
    }

    /// `Max-Age` for `access_token`.
    pub fn access_max_age(&self) -> Duration {
        self.access_ttl
            .to_std()
            .unwrap_or(Duration::from_secs(15 * 60))
    }

    /// `Max-Age` for `refresh_token`.
    pub fn refresh_max_age(&self) -> Duration {
        self.refresh_ttl
            .to_std()
            .unwrap_or(Duration::from_secs(30 * 24 * 3600))
    }
}
