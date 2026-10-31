//! Email delivery abstraction for `axum-minimal` (Stage 3g).
//!
//! `saas-leptos` has three transport methods (`send_verification`,
//! `send_invitation`, `send_password_reset`); `axum-minimal` covers only the
//! endpoints in plan §3 (`register`, `login`, `logout`, `refresh`,
//! `GET/POST /tenants`, `GET/POST /workspaces`, `GET/POST /documents`,
//! `GET /audit`). Registration attempts a verification email; invitations
//! and password reset are out of scope for 3g (plan §1: "Invitation flow,
//! member management, role management — не нужны для доказательства
//! переносимости"; password reset and SMTP transport are also out of scope).
//!
//! **`NoopEmailSender` only.** `SmtpEmailSender` (lettre) is deliberately
//! omitted: `axum-minimal` is a portability proof, not a product. The
//! `EmailSender` trait exists so a future consumer can plug in a real
//! transport without changing `AppState`; `NoopEmailSender` is the only
//! implementation shipped here.
//!
//! **`EmailResult`** is kept identical to `saas-leptos` (same variants,
//! same serialization) so that a consumer swapping the two examples sees no
//! contract difference. `register` returns it to the caller (JSON) so the
//! portability proof covers the same shape as `saas-leptos`'s
//! `#[server] register`.
//!
//! Delivery failures do **not** propagate as `Result::Err`: registration
//! must succeed even if SMTP is down (in 3g there is no SMTP, so the only
//! outcome is [`EmailResult::Disabled`]). `NoopEmailSender` logs only the
//! recipient and the fact of a skipped send — **never** the token.

use serde::{Deserialize, Serialize};

/// Outcome of an outbound email. Same shape as `saas-leptos::email::EmailResult`
/// (Stage 3b) — the variants are part of the cross-example contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmailResult {
    /// Handed off to the SMTP transport without error.
    Sent,
    /// Transport or message-construction error.
    Failed { reason: String },
    /// Email delivery is disabled (`NoopEmailSender`); the message was not
    /// sent. Used when `SMTP_URL` is unset; not a failure.
    Disabled,
}

/// Server-side email transport.
///
/// Object-safe thanks to `#[async_trait]`; stored in `AppState` as
/// `Arc<dyn EmailSender>`. `axum-minimal` ships only
/// [`NoopEmailSender`]; a future consumer can add an SMTP implementation
/// without touching `AppState`.
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
/// skipped send. Defense against accidentally enabling this in production.
pub struct NoopEmailSender;

#[async_trait::async_trait]
impl EmailSender for NoopEmailSender {
    async fn send_verification(&self, to: &str, _token: &str) -> EmailResult {
        tracing::warn!(
            to = %to,
            "email delivery disabled (NoopEmailSender): SMTP transport not implemented in axum-minimal; verification link not sent"
        );
        EmailResult::Disabled
    }
}