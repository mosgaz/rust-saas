//! Email delivery for verification links (Stage 3b), invitation links
//! (Stage 3c), and password-reset links (Stage 3d).
//!
//! [`EmailResult`] is compiled under both `ssr` and `hydrate` (the UI shows
//! it after registration and after creating an addressed invitation) and has
//! no dependency on `lettre`.
//!
//! The transport layer ([`EmailSender`], [`SmtpEmailSender`],
//! [`NoopEmailSender`]) is **server-only** (`#[cfg(feature = "ssr")]`);
//! `hydrate` never sees `lettre`.
//!
//! `SmtpEmailSender` is configured from `SMTP_URL` and `BASE_URL` in
//! `main.rs`; `NoopEmailSender` returns [`EmailResult::Disabled`] and logs a
//! warning (used when `SMTP_URL` is unset — CI, quick local runs without
//! Mailpit).
//!
//! Delivery failures do **not** propagate as `Result::Err`: registration
//! must succeed even if SMTP is down. The UI distinguishes `Sent` /
//! `Failed` / `Disabled` and offers a resend button on `Failed`.
//!
//! Stage 3c adds [`EmailSender::send_invitation`] for **addressed**
//! invitations (`invitation.email IS NOT NULL`). The method takes the raw
//! invitation token — symmetrically to `send_verification(to, token)` — and
//! the transport builds `{BASE_URL}/invitations/{token}` itself (the
//! `base_url` is a constructor argument of `SmtpEmailSender`, not a
//! per-call parameter; `AppState` does not need to know it).
//! `NoopEmailSender` never logs the token or the URL, only the recipient
//! and the fact of a skipped send.
//!
//! Stage 3d adds [`EmailSender::send_password_reset`] for the forgot-password
//! flow: `{BASE_URL}/reset-password/{token}`, subject "Reset your password".
//! The SMTP transport is built with a 10-second `.timeout(...)` so a slow
//! provider cannot stall a `#[server]` call; the timeout covers the whole
//! send attempt (see `SmtpEmailSender::new`). Like the other two, a failed
//! send does not fail the business operation — `request_password_reset`
//! returns `Ok(())` regardless, and the UI shows a generic "if the address
//! exists, we sent a link" message.

use serde::{Deserialize, Serialize};

/// Outcome of an outbound email (verification, invitation, or password
/// reset).
///
/// Returned by `#[server] register` (Stage 3b), by `#[server]
/// create_invitation` (Stage 3c, addressed invitations), and by
/// `#[server] request_password_reset` (Stage 3d) so the UI can render
/// "sent", "failed, retry?", or "disabled (no SMTP)" without treating a
/// transport failure as a business error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmailResult {
    /// Handed off to the SMTP transport without error.
    Sent,
    /// Transport or message-construction error. `reason` is the `Display`
    /// string from `lettre` (connection refused, auth failure, bad
    /// recipient, etc.).
    Failed { reason: String },
    /// Email delivery is disabled (`NoopEmailSender`); the message was not
    /// sent. Used when `SMTP_URL` is unset; not a failure.
    Disabled,
}

#[cfg(feature = "ssr")]
mod ssr {
    //! Server-only transport implementations (lettre).

    use std::time::Duration;

    use lettre::message::Mailbox;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    use super::EmailResult;

    /// Server-side email transport.
    ///
    /// Stored in `AppState` as `Arc<dyn EmailSender>` (see `state.rs`). The
    /// trait is object-safe thanks to `#[async_trait]`.
    #[async_trait::async_trait]
    pub trait EmailSender: Send + Sync {
        /// Sends a "verify your email" link to `to`, containing
        /// `{base_url}/verify/{token}`.
        ///
        /// Never panics; transport errors are returned as
        /// [`EmailResult::Failed`] (registration itself still succeeds).
        async fn send_verification(&self, to: &str, token: &str) -> EmailResult;

        /// Sends an invitation link to `to` (Stage 3c, addressed
        /// invitations), containing `{base_url}/invitations/{token}`.
        ///
        /// `token` is the raw invitation token returned by
        /// `saas::invitation::create_invitation`; only its hash is persisted
        /// in the database. Transports must not log the raw token or the
        /// URL (`NoopEmailSender` logs only `to` and the skip reason).
        ///
        /// Never panics; transport errors are returned as
        /// [`EmailResult::Failed`] (the invitation row is already inserted
        /// and the caller shows the failure in the UI).
        async fn send_invitation(&self, to: &str, token: &str) -> EmailResult;

        /// Sends a password-reset link to `to` (Stage 3d), containing
        /// `{base_url}/reset-password/{token}`.
        ///
        /// `token` is the raw password-reset token returned by
        /// `authn::request_password_reset`; only its hash is persisted in
        /// the database. Transports must not log the raw token or the URL
        /// (`NoopEmailSender` logs only `to` and the skip reason).
        ///
        /// Never panics; transport errors are returned as
        /// [`EmailResult::Failed`] (the reset token is already stored;
        /// `request_password_reset` returns `Ok(())` regardless so the
        /// caller cannot use the SMTP outcome as an email-enumeration
        /// signal).
        async fn send_password_reset(&self, to: &str, token: &str) -> EmailResult;
    }

    /// Real SMTP sender (lettre async transport with `rustls`).
    pub struct SmtpEmailSender {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
        base_url: String,
    }

    impl SmtpEmailSender {
        /// Builds a sender from:
        /// - `smtp_url` — `smtp://localhost:1025` (Mailpit) or
        ///   `smtps://user:pass@host:465`;
        /// - `from` — sender address (`noreply@example.test`);
        /// - `base_url` — public origin of the app, used to construct the
        ///   verify, invitation, and password-reset links
        ///   (`http://127.0.0.1:3395`).
        ///
        /// The transport is built with a 10-second `.timeout(...)` so a
        /// slow or unreachable provider cannot stall a `#[server]` call
        /// (§IV.20). The timeout covers the whole `send` attempt (connect
        /// + greeting + message + QUIT).
        ///
        /// Returns `Err(String)` on invalid configuration so `main.rs` can
        /// fail fast at startup.
        pub fn new(smtp_url: &str, from: &str, base_url: &str) -> Result<Self, String> {
            let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url)
                .map_err(|e| format!("invalid SMTP_URL: {e}"))?
                .timeout(Some(Duration::from_secs(10)))
                .build();
            let from: Mailbox = from
                .parse()
                .map_err(|e| format!("invalid sender address ({from}): {e}"))?;
            Ok(Self {
                transport,
                from,
                base_url: base_url.trim_end_matches('/').to_string(),
            })
        }
    }

    #[async_trait::async_trait]
    impl EmailSender for SmtpEmailSender {
        async fn send_verification(&self, to: &str, token: &str) -> EmailResult {
            let to_mailbox: Mailbox = match to.parse() {
                Ok(m) => m,
                Err(e) => {
                    return EmailResult::Failed {
                        reason: format!("invalid recipient {to}: {e}"),
                    };
                }
            };
            let verify_url = format!("{}/verify/{}", self.base_url, token);
            let body = format!(
                "Welcome to Rust SAAS.\n\n\
                 Confirm your email by opening:\n\n    {verify_url}\n\n\
                 The link expires in 24 hours.\n"
            );
            let message = match Message::builder()
                .from(self.from.clone())
                .to(to_mailbox)
                .subject("Verify your email")
                .body(body)
            {
                Ok(m) => m,
                Err(e) => {
                    return EmailResult::Failed {
                        reason: format!("failed to build message: {e}"),
                    };
                }
            };
            match self.transport.send(message).await {
                Ok(_) => EmailResult::Sent,
                Err(e) => EmailResult::Failed {
                    reason: e.to_string(),
                },
            }
        }

        async fn send_invitation(&self, to: &str, token: &str) -> EmailResult {
            let to_mailbox: Mailbox = match to.parse() {
                Ok(m) => m,
                Err(e) => {
                    return EmailResult::Failed {
                        reason: format!("invalid recipient {to}: {e}"),
                    };
                }
            };
            let invitation_url = format!("{}/invitations/{}", self.base_url, token);
            let body = format!(
                "You have been invited to Rust SAAS.\n\n\
                 Accept the invitation by opening:\n\n    {invitation_url}\n\n\
                 If you were not expecting this email, you can ignore it.\n"
            );
            let message = match Message::builder()
                .from(self.from.clone())
                .to(to_mailbox)
                .subject("You're invited to Rust SAAS")
                .body(body)
            {
                Ok(m) => m,
                Err(e) => {
                    return EmailResult::Failed {
                        reason: format!("failed to build message: {e}"),
                    };
                }
            };
            match self.transport.send(message).await {
                Ok(_) => EmailResult::Sent,
                Err(e) => EmailResult::Failed {
                    reason: e.to_string(),
                },
            }
        }

        async fn send_password_reset(&self, to: &str, token: &str) -> EmailResult {
            let to_mailbox: Mailbox = match to.parse() {
                Ok(m) => m,
                Err(e) => {
                    return EmailResult::Failed {
                        reason: format!("invalid recipient {to}: {e}"),
                    };
                }
            };
            let reset_url = format!("{}/reset-password/{}", self.base_url, token);
            let body = format!(
                "We received a request to reset the password for your Rust SAAS account.\n\n\
                 Set a new password by opening:\n\n    {reset_url}\n\n\
                 The link expires in 1 hour and can be used once. \
                 If you did not request a password reset, you can ignore this email.\n"
            );
            let message = match Message::builder()
                .from(self.from.clone())
                .to(to_mailbox)
                .subject("Reset your password")
                .body(body)
            {
                Ok(m) => m,
                Err(e) => {
                    return EmailResult::Failed {
                        reason: format!("failed to build message: {e}"),
                    };
                }
            };
            match self.transport.send(message).await {
                Ok(_) => EmailResult::Sent,
                Err(e) => EmailResult::Failed {
                    reason: e.to_string(),
                },
            }
        }
    }

    /// No-op sender: logs a warning and reports [`EmailResult::Disabled`].
    /// Does **not** log the token (verification, invitation, or password
    /// reset) — only the recipient and the fact of a skipped send. Defense
    /// against accidentally enabling this in production. For dev, configure
    /// Mailpit and `SMTP_URL`.
    pub struct NoopEmailSender;

    #[async_trait::async_trait]
    impl EmailSender for NoopEmailSender {
        async fn send_verification(&self, to: &str, _token: &str) -> EmailResult {
            tracing::warn!(
                to = %to,
                "email delivery disabled (NoopEmailSender): SMTP_URL not configured; verification link not sent"
            );
            EmailResult::Disabled
        }

        async fn send_invitation(&self, to: &str, _token: &str) -> EmailResult {
            tracing::warn!(
                to = %to,
                "email delivery disabled (NoopEmailSender): SMTP_URL not configured; invitation link not sent"
            );
            EmailResult::Disabled
        }

        async fn send_password_reset(&self, to: &str, _token: &str) -> EmailResult {
            tracing::warn!(
                to = %to,
                "email delivery disabled (NoopEmailSender): SMTP_URL not configured; password-reset link not sent"
            );
            EmailResult::Disabled
        }
    }
}

#[cfg(feature = "ssr")]
pub use ssr::{EmailSender, NoopEmailSender, SmtpEmailSender};