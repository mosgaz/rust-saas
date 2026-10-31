//! Typed mapping of library-crate errors into HTTP responses.
//!
//! Mirrors `examples/saas-leptos/src/error.rs`, with the Axum substitution:
//! `saas-leptos` returns `ServerFnError` and sets the status code through
//! `leptos_axum::ResponseOptions`; `axum-minimal` implements
//! `IntoResponse` directly — no Leptos types, no `ResponseOptions`.
//!
//! Mapping (same statuses as `saas-leptos`):
//!
//! - `Validation`, `InvalidRoleKey`                              -> 400
//! - `Unauthorized`, `InvalidCredentials`, `TokenInvalid`,
//!   `TokenExpired`, `RefreshInvalid`, `RefreshReused`           -> 401
//! - `Forbidden`, `EmailNotVerified`, `TenantSuspended`,
//!   `Protected`, `Immutable`                                    -> 403
//! - `NotFound`, `RoleNotFound`, `PermissionNotFound`            -> 404
//! - `DuplicateEmail`, `AlreadyVerified`                         -> 409
//! - [`AppError::RateLimited`]                                   -> 429
//!   (+ `Retry-After` header)
//! - `Internal`, `Db`                                            -> 500
//!
//! `CoreError::TenantSuspended` maps to 403 with the distinct message
//! `"tenant is suspended"` (its `Display`); a client can distinguish it
//! from a generic `Forbidden` by the body. Same convention as
//! `saas-leptos` (Stage 3f).
//!
//! Response body (JSON, `Content-Type: application/json`):
//!
//! ```json
//! { "error": "tenant is suspended" }
//! { "error": "rate limited; try again in 3421s", "retry_after_secs": 3421 }
//! ```
//!
//! `retry_after_secs` is present only for 429; the same value is also set
//! as the `Retry-After` header.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use access::AccessError;
use authn::AuthnError;
use identity::IdentityError;
use saas::CoreError;

/// One error type for every handler. Wraps the library errors plus two
/// example-local variants:
///
/// - [`AppError::Unauthorized`] — no authenticated actor (`CurrentUser`
///   extractor rejected an anonymous request on a protected route).
/// - [`AppError::RateLimited`] — `register` exceeded its per-email quota;
///   carries `retry_after_secs` for the `Retry-After` header.
#[derive(Debug)]
pub enum AppError {
    Core(CoreError),
    Authn(AuthnError),
    Access(AccessError),
    Identity(IdentityError),
    Unauthorized,
    RateLimited { retry_after_secs: u64 },
}

impl AppError {
    /// "No authenticated actor" (401). Convenience constructor for
    /// handlers / extractors.
    pub fn unauthorized() -> Self {
        Self::Unauthorized
    }

    /// "Rate limited" (429). `retry_after_secs` is the number of seconds
    /// until the window frees a slot.
    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self::RateLimited { retry_after_secs }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Core(e) => write!(f, "{e}"),
            AppError::Authn(e) => write!(f, "{e}"),
            AppError::Access(e) => write!(f, "{e}"),
            AppError::Identity(e) => write!(f, "{e}"),
            AppError::Unauthorized => write!(f, "unauthorized"),
            AppError::RateLimited { retry_after_secs } => {
                write!(f, "rate limited; try again in {retry_after_secs}s")
            }
        }
    }
}

impl std::error::Error for AppError {}

impl From<CoreError> for AppError {
    fn from(e: CoreError) -> Self {
        AppError::Core(e)
    }
}

impl From<AuthnError> for AppError {
    fn from(e: AuthnError) -> Self {
        AppError::Authn(e)
    }
}

impl From<AccessError> for AppError {
    fn from(e: AccessError) -> Self {
        AppError::Access(e)
    }
}

impl From<IdentityError> for AppError {
    fn from(e: IdentityError) -> Self {
        AppError::Identity(e)
    }
}

/// Status code for `CoreError` (same mapping as `saas-leptos`).
fn status_for_core(e: &CoreError) -> StatusCode {
    match e {
        CoreError::Validation(_) => StatusCode::BAD_REQUEST,
        CoreError::Unauthorized => StatusCode::UNAUTHORIZED,
        CoreError::Forbidden
        | CoreError::EmailNotVerified
        | CoreError::TenantSuspended => StatusCode::FORBIDDEN,
        CoreError::NotFound => StatusCode::NOT_FOUND,
        CoreError::Internal(_) | CoreError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn status_for_identity(e: &IdentityError) -> StatusCode {
    match e {
        IdentityError::Validation(_) => StatusCode::BAD_REQUEST,
        IdentityError::NotFound => StatusCode::NOT_FOUND,
        IdentityError::DuplicateEmail => StatusCode::CONFLICT,
        IdentityError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn status_for_authn(e: &AuthnError) -> StatusCode {
    match e {
        AuthnError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        AuthnError::TokenInvalid | AuthnError::TokenExpired => StatusCode::UNAUTHORIZED,
        AuthnError::RefreshInvalid | AuthnError::RefreshReused => StatusCode::UNAUTHORIZED,
        AuthnError::AlreadyVerified => StatusCode::CONFLICT,
        AuthnError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        AuthnError::Identity(inner) => status_for_identity(inner),
        AuthnError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn status_for_access(e: &AccessError) -> StatusCode {
    match e {
        AccessError::Validation(_) | AccessError::InvalidRoleKey(_) => StatusCode::BAD_REQUEST,
        AccessError::Forbidden | AccessError::Protected | AccessError::Immutable => {
            StatusCode::FORBIDDEN
        }
        AccessError::RoleNotFound(_) | AccessError::PermissionNotFound(_, _) => {
            StatusCode::NOT_FOUND
        }
        AccessError::Internal(_) | AccessError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_secs: Option<u64>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, retry_after) = match &self {
            AppError::Core(e) => (status_for_core(e), e.to_string(), None),
            AppError::Authn(e) => (status_for_authn(e), e.to_string(), None),
            AppError::Access(e) => (status_for_access(e), e.to_string(), None),
            AppError::Identity(e) => (status_for_identity(e), e.to_string(), None),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized".to_string(),
                None,
            ),
            AppError::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!("rate limited; try again in {retry_after_secs}s"),
                Some(*retry_after_secs),
            ),
        };

        let body = ErrorBody {
            error: message,
            retry_after_secs: retry_after,
        };
        let mut response = (status, Json(body)).into_response();
        if let Some(secs) = retry_after {
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        response
    }
}