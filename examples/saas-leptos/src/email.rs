//! Email delivery for verification links (Stage 3b) and invitation links
//! (Stage 3c).
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

use serde::{Deserialize, Serialize};

/// Outcome of an outbound email (verification or invitation).
///
/// Returned by `#[server] register` (Stage 3b) and by
/// `#[server] create_invitation` (Stage 3c, addressed invitations) so the
/// UI can render "sent", "failed, retry?", or "disabled (no SMTP)" without
/// treating a transport failure as a business error.
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
        ///   verify and invitation links (`http://127.0.0.1:3395`).
        ///
        /// Returns `Err(String)` on invalid configuration so `main.rs` can
        /// fail fast at startup.
        pub fn new(smtp_url: &str, from: &str, base_url: &str) -> Result<Self, String> {
            let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url)
                .map_err(|e| format!("invalid SMTP_URL: {e}"))?
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
    }

    /// No-op sender: logs a warning and reports [`EmailResult::Disabled`].
    /// Does **not** log the token (verification or invitation) — only the
    /// recipient and the fact of a skipped send. Defense against
    /// accidentally enabling this in production. For dev, configure Mailpit
    /// and `SMTP_URL`.
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
    }
}

#[cfg(feature = "ssr")]
pub use ssr::{EmailSender, NoopEmailSender, SmtpEmailSender};