//! The token a consumer presents on connect.

use super::{Password, TicketSecret};

/// The 32 bytes a bridge consumer presents on connect and a producer
/// expects: the raw ticket secret (no password), or its Argon2id stretch
/// salted by the secret (passworded) — same wire size either way, so a
/// directory ad (which carries the secret) is not enough to redeem a
/// passworded ticket.
///
/// # Examples
///
/// A ticket with a password derives a different token from the same secret.
///
/// ```
/// use habilis_network_protocol::{Password, TicketAuth, TicketSecret};
///
/// let secret = TicketSecret::from([4u8; 32]);
/// let open = TicketAuth::blob(&secret, None);
/// assert!(!open.password_protected);
///
/// let guarded = TicketAuth::blob(&secret, Some(&Password::new("pw".to_owned())));
/// assert!(guarded.password_protected);
/// assert_ne!(open.token.as_bytes(), guarded.token.as_bytes());
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct TicketAuth {
    /// The secret that the consumer presents.
    pub token: TicketSecret,
    /// Whether the ticket also needs the password.
    pub password_protected: bool,
}

impl TicketAuth {
    /// The token for a **blob** ticket. `label` is what keeps ticket kinds apart:
    /// two kinds sharing a secret must never derive the same passworded token, so
    /// an application minting its own ticket kind passes its own label through
    /// [`Self::derive`] rather than reusing this one.
    #[must_use]
    pub fn blob(secret: &TicketSecret, password: Option<&Password>) -> Self {
        Self::derive(secret, password, b"blob-ticket")
    }

    /// Derive a ticket token under a caller-chosen `label`.
    ///
    /// The label is a **byte-domain**: it is stretched into the token, so it
    /// reaches the wire and is fixed for the life of that ticket kind. Pick one
    /// distinct per kind; reusing another kind's label collapses the separation
    /// [`Self::blob`] documents.
    #[must_use]
    pub fn derive(secret: &TicketSecret, password: Option<&Password>, label: &[u8]) -> Self {
        match password {
            Some(password) => Self {
                token: TicketSecret::from(super::password::stretch_password(
                    password,
                    secret.as_bytes(),
                    label,
                )),
                password_protected: true,
            },
            None => Self {
                token: secret.clone(),
                password_protected: false,
            },
        }
    }
}

impl std::fmt::Debug for TicketAuth {
    // The token is the live credential — redact it, keep the flag.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TicketAuth")
            .field("token", &"***")
            .field("password_protected", &self.password_protected)
            .finish()
    }
}
