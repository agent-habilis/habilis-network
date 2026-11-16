//! Why an event is refused, or a signing key is not one.

use std::error::Error;
use std::fmt;

/// Why an event is refused, or a signing key is not one.
///
/// # Examples
///
/// An event whose content changed after it was signed no longer matches its id.
///
/// ```
/// use habilis_network_iroh_nostr_address_lookup::{Event, EventError, Keys};
///
/// let keys = Keys::generate();
/// let mut event = Event::sign(&keys, 1_700_000_000, &[9u8; 32], "hello".to_owned());
/// event.content = "bye".to_owned();
/// assert!(matches!(event.verify_id(), Err(EventError::IdMismatch)));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum EventError {
    /// The bytes are not a secp256k1 secret key: zero, or not below the curve order.
    InvalidSecretKey,
    /// The id of the event is not the hash of its fields.
    IdMismatch,
    /// A field of the event does not decode. `step` names it.
    Malformed {
        /// The field that failed to decode.
        step: &'static str,
    },
    /// The signature does not verify against the public key of the event.
    BadSignature,
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey => formatter.write_str("invalid secp256k1 secret key"),
            Self::IdMismatch => formatter.write_str("event id does not match its fields"),
            Self::Malformed { step } => formatter.write_str(step),
            Self::BadSignature => formatter.write_str("bad signature"),
        }
    }
}

impl Error for EventError {}
