//! Email delivery abstraction for `saas-axum`.
//!
//! `examples/axum-minimal` ships its own copy of this module; `saas-axum`
//! must be independent (examples are outside the workspace, and the
//! adapter cannot depend on an example). Content is the minimal subset
//! PR-1 needs:
//!
//! - [`EmailSender`] trait — object-safe via `#[async_trait]`, stored as
//!   `Arc<dyn EmailSender>` in [`crate::state::AxumAppState`].
//! - [`EmailResult`] — DTO returned to the caller (`register` in A4.4).
//! - [`NoopEmailSender`] — the only implementation shipped here.
//!   `SmtpEmailSender` (lettre) stays consumer-local; `saas-axum` does not
//!   depend on `lettre` (design constraint, see `lib.rs`).
//!
//! **Not in PR-1:** `send_invitation` / `send_password_reset` — those
//! methods belong to `examples/saas-leptos` (`EmailSender` there has three
//! methods). `saas-axum` will grow them in A4.4 if/when endpoints that
//! need them are added. The trait is kept single-method for now so that
//! `NoopEmailSender` is trivially implementable.
//!
//! **No token leakage.** `NoopEmailSender` logs only the recipient and
//! the fact of a skipped send — never the raw token.

use serde::{Deserialize, Serialize};

/// Outcome of an outbound email.
///
/// Same shape as `examples/axum-minimal::email::EmailResult` and
/// `examples/saas-leptos::email::EmailResult` so that a consumer swapping
/// between the two examples sees no contract difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmailResult {
    /// Handed off to the SMTP transport without error.
    Sent,
    /// Transport or message-construction error.
    Failed { reason: String },
    /// Email delivery is disabled (`NoopEmailSender`); the message was not
    /// sent. Used when no SMTP transport is configured; not a failure.
    Disabled,
}

/// Server-side email transport.
///
/// Object-safe thanks to `#[async_trait]`; stored in
/// [`crate::state::AxumAppState`] as `Arc<dyn EmailSender>`. `saas-axum`
/// ships only [`NoopEmailSender`]; a consumer can plug in a real sender
/// (`SmtpEmailSender` in `examples/saas-leptos`) without changing the
/// state struct — the trait is the only surface.
#[async_trait::async_trait]
pub trait EmailSender: Send + Sync {
    /// Sends a "verify your email" link to `to`.
    ///
    /// Never panics; transport errors are returned as
    /// [`EmailResult::Failed`] (registration itself still succeeds).
    /// Implementations must not log the raw token or the URL.
    async fn send_verification(&self, to: &str, token: &str) -> EmailResult;
}

/// No-op sender: logs a warning and reports [`EmailResult::Disabled`].
///
/// Does **not** log the token — only the recipient and the fact of a
/// skipped send.
pub struct NoopEmailSender;

#[async_trait::async_trait]
impl EmailSender for NoopEmailSender {
    async fn send_verification(&self, to: &str, _token: &str) -> EmailResult {
        tracing::warn!(
            to = %to,
            "email delivery disabled (NoopEmailSender): saas-axum has no SMTP transport; \
             verification link not sent"
        );
        EmailResult::Disabled
    }
}
