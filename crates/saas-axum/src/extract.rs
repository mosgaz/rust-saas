//! `CurrentUser` — the authenticated user for the current request.
//!
//! Implemented as a real [`axum::extract::FromRequestParts`]. This is a
//! **deliberate deviation from ADR-0002 rev.2 §3.8**, which deferred
//! `FromRequestParts` ("`FromRequestParts` for `saas-leptos` — deferred;
//! the general rule (defense in depth / `AuthLayer`) — Stage 4"). Stage 3g
//! (`examples/axum-minimal`) proved the trait works for a second consumer;
//! `saas-axum` adopts the same pattern for the same reason: the adapter
//! *is* the Axum pipeline, so the extractor is the idiomatic form.
//! `saas-leptos` uses a plain helper (`crate::extract::CurrentUser::from_request().await`)
//! because Leptos `#[server]` functions do not go through Axum's
//! extractor pipeline. Both forms surface the same contract to the caller.
//!
//! **How it works.** [`crate::middleware::auto_refresh`] runs before every
//! handler on the protected router and inserts `Option<AuthUser>` into
//! request extensions:
//!
//! - `Some(user)` — valid access token, or successful refresh rotation.
//! - `None` — anonymous request (no cookie, or invalid/expired token that
//!   could not be refreshed).
//!
//! On routes **without** the middleware (public routes), `extensions.get`
//! returns `None`; `CurrentUser(None)` is produced — same anonymous
//! semantics.
//!
//! **Usage.**
//!
//! ```ignore
//! async fn list_tenants(
//!     State(state): State<Arc<AxumAppState>>,
//!     CurrentUser(user): CurrentUser,
//! ) -> Result<Json<Vec<Tenant>>, AppError> {
//!     let user = user.require()?;          // 401 if anonymous
//!     // …
//! }
//! ```
//!
//! `CurrentUser` exposes its inner `Option<AuthUser>` (`pub` field), so a
//! handler that wants to treat "anonymous" as a valid state can pattern-match
//! directly. Handlers that require an actor call [`CurrentUser::require`] —
//! the only sanctioned way to turn "maybe a user" into "definitely a user".

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use domain::AuthUser;

use crate::error::AppError;

/// The current authenticated user, or `None` for an anonymous request.
///
/// The `pub` field mirrors `examples/axum-minimal::extract::CurrentUser`
/// and `examples/saas-leptos::extract::CurrentUser` so that consumers see
/// the same shape across the two examples and the adapter.
pub struct CurrentUser(pub Option<AuthUser>);

impl CurrentUser {
    /// Returns the authenticated actor, or [`AppError::Unauthorized`] (401)
    /// when the request is anonymous.
    pub fn require(self) -> Result<AuthUser, AppError> {
        self.0.ok_or_else(AppError::unauthorized)
    }
}

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // `auto_refresh` inserts `Option<AuthUser>`; absent means "no
        // middleware ran" (anonymous route) — treat it as anonymous.
        let user = parts
            .extensions
            .get::<Option<AuthUser>>()
            .cloned()
            .flatten();
        Ok(CurrentUser(user))
    }
}
