//! `CurrentUser` — the authenticated user for the current request.
//!
//! Reads `Extension<Option<AuthUser>>` populated by
//! [`crate::middleware::auto_refresh`], which is responsible for verifying
//! the `access_token` cookie and, on expiry, rotating the `refresh_token`.
//! By the time a `#[server]` function runs, the middleware has already done
//! the work — `CurrentUser` only pulls the resolved value.
//!
//! Not an `axum::FromRequestParts` on purpose: keeping it a plain helper
//! avoids pulling `async-trait` into the example's dependencies. Usage:
//!
//! ```ignore
//! let user = crate::extract::CurrentUser::from_request().await?.require()?;
//! ```

use domain::AuthUser;
use leptos::prelude::*;

pub struct CurrentUser(pub Option<AuthUser>);

impl CurrentUser {
    /// Returns the current authenticated user, or `Ok(Self(None))` when the
    /// request has no valid session.
    pub async fn from_request() -> Result<Self, ServerFnError> {
        let user = leptos_axum::extract::<Option<axum::extract::Extension<Option<AuthUser>>>>()
            .await
            .ok()
            .flatten()
            .and_then(|ext| ext.0);
        Ok(Self(user))
    }

    /// Requires an authenticated user; returns HTTP 401 otherwise.
    pub fn require(self) -> Result<AuthUser, ServerFnError> {
        self.0.ok_or_else(crate::error::unauthorized_error)
    }
}