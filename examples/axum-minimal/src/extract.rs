//! `CurrentUser` — the authenticated user for the current request.
//!
//! Implemented as a real [`axum::extract::FromRequestParts`]. This is a
//! **deliberate deviation from ADR-0002 rev.2 §3.8**, which deferred
//! `FromRequestParts` ("`FromRequestParts` for `saas-leptos` — deferred;
//! the general rule (defense in depth / `AuthLayer`) — Stage 4"). Stage 3g
//! exists to show that the trait works for a second consumer; the deviation
//! is recorded in `handoff §16` and Appendix B §2.48.
//!
//! **How it works.** `crate::middleware::auto_refresh` runs before every
//! handler on the protected router and inserts `Option<AuthUser>` into
//! request extensions:
//!
//! - `Some(user)` — valid access token, or successful refresh rotation.
//! - `None` — anonymous request (no cookie, or invalid/expired token that
//!   could not be refreshed).
//!
//! On routes **without** the middleware (none in 3g — the whole `/auth/*`
//! group except `register`/`login` is behind it), `extensions.get` returns
//! `None`; `CurrentUser(None)` is produced — same anonymous semantics.
//!
//! **Usage.**
//!
//! ```ignore
//! async fn list_tenants(
//!     State(state): State<Arc<AppState>>,
//!     CurrentUser(user): CurrentUser,
//! ) -> Result<Json<Vec<Tenant>>, AppError> {
//!     let user = user.require()?;          // 401 if anonymous
//!     // …
//! }
//! ```
//!
//! `CurrentUser` exposes its inner `Option<AuthUser>` (`pub` field), so a
//! handler that wants to treat "anonymous" as a valid state (e.g. a
//! future `/whoami`) can pattern-match directly. Handlers that require an
//! actor call [`CurrentUser::require`] — the only sanctioned way to turn
//! "maybe a user" into "definitely a user".
//!
//! **Contrast with `saas-leptos`.** `saas-leptos/src/extract.rs` is a plain
//! helper (`CurrentUser::from_request().await`), not a trait impl: Leptos
//! `#[server]` functions do not go through Axum's extractor pipeline, so
//! the trait would not be called. In `axum-minimal` the handler *is* the
//! Axum pipeline, so the idiomatic form is the trait impl — the whole point
//! of the portability proof.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use domain::AuthUser;

use crate::error::AppError;

/// The current authenticated user, or `None` for an anonymous request.
///
/// The `pub` field mirrors `saas-leptos::extract::CurrentUser` so that
/// consumers see the same shape across the two examples.
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