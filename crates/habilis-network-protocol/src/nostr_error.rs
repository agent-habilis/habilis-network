//! Why a Nostr signal or a Nostr relay list is refused.
//!
//! The variants name each check of [`Opener::open`](crate::nostr::Opener::open)
//! in the order it runs, and each relay-list check of
//! [`parse_nostr_urls`](crate::meshes::parse_nostr_urls).

use std::error::Error;
use std::fmt;

use crate::nostr::{MAX_ADDRS, SignalKind};

/// Why a Nostr signal or a Nostr relay list is refused.
///
/// # Examples
///
/// A signal that is not base64 returns this error.
///
/// ```
/// use habilis_network_protocol::iroh_base::SecretKey;
/// use habilis_network_protocol::nostr::{NostrKeys, Opener};
/// use habilis_network_protocol::nostr_error::NostrError;
/// use habilis_network_protocol::TopicId;
///
/// let keys = NostrKeys::derive(&TopicId::from_bytes([1u8; 32]));
/// let me = SecretKey::generate().public();
/// let error = Opener::new(keys, me).open("not base64!", 0).unwrap_err();
/// assert!(matches!(error, NostrError::NotBase64));
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum NostrError {
    /// The content of the event is not base64.
    NotBase64,
    /// The content does not open with the seal key of this mesh.
    NotSealed,
    /// A part of the envelope or the body does not decode. `step` names it.
    Malformed {
        /// The part that failed to decode.
        step: &'static str,
    },
    /// The signature is not 64 bytes, or it does not match the sender.
    BadSignature,
    /// The body names a version this build does not know.
    UnknownVersion(u8),
    /// The sender's clock is `seconds` away from ours, past the window.
    ClockSkew {
        /// The distance between the two clocks, in seconds.
        seconds: u64,
    },
    /// The signal came from this member.
    OwnSignal,
    /// The signal has the fields its kind does not allow, or misses one it needs.
    WrongFields {
        /// The kind of the signal.
        kind: SignalKind,
    },
    /// The signal carries more addresses than the ceiling.
    TooManyAddresses {
        /// The number of addresses the signal carries.
        count: usize,
    },
    /// The signal is addressed to another member.
    AddressedElsewhere,
    /// The signal was already opened within the replay window.
    Replayed,
    /// A custom relay list is empty.
    EmptyRelayList,
    /// A custom relay list has more relays than the wire ceiling.
    RelayListTooLong {
        /// The number of relays in the list.
        count: usize,
    },
    /// A relay URL is longer than the wire ceiling, in bytes.
    RelayUrlTooLong {
        /// The length of the URL, in bytes.
        bytes: usize,
    },
    /// A relay entry is empty, or it is not a `ws://` or `wss://` URL.
    BadRelayUrl {
        /// The entry as the caller wrote it.
        entry: String,
    },
    /// A custom relay list names one relay twice.
    DuplicateRelay {
        /// The relay that is named twice.
        entry: String,
    },
    /// A custom relay list is not in ascending order, so the same relays could
    /// make more than one mesh id.
    UnsortedRelayList,
}

impl fmt::Display for NostrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase64 => formatter.write_str("content is not base64"),
            Self::NotSealed => formatter.write_str("not sealed for this mesh"),
            Self::Malformed { step } => formatter.write_str(step),
            Self::BadSignature => formatter.write_str("signature does not match the sender"),
            Self::UnknownVersion(version) => {
                write!(formatter, "unknown signal version {version}")
            }
            Self::ClockSkew { seconds } => {
                write!(formatter, "signal is {seconds} s off our clock")
            }
            Self::OwnSignal => formatter.write_str("our own signal"),
            Self::WrongFields { kind } => {
                write!(formatter, "malformed {kind:?}: wrong fields for its kind")
            }
            Self::TooManyAddresses { count } => {
                write!(
                    formatter,
                    "signal carries {count} addresses, the ceiling is {MAX_ADDRS}"
                )
            }
            Self::AddressedElsewhere => formatter.write_str("signal addressed to another member"),
            Self::Replayed => formatter.write_str("replayed signal"),
            Self::EmptyRelayList => formatter.write_str("custom nostr relay list is empty"),
            Self::RelayListTooLong { count } => {
                write!(formatter, "nostr relay list too long: {count} relays")
            }
            Self::RelayUrlTooLong { bytes } => {
                write!(formatter, "nostr relay URL too long: {bytes} bytes")
            }
            Self::BadRelayUrl { entry } => {
                write!(
                    formatter,
                    "nostr relay URL {entry:?} is not a ws:// or wss:// URL"
                )
            }
            Self::DuplicateRelay { entry } => {
                write!(formatter, "nostr relay {entry} is named twice")
            }
            Self::UnsortedRelayList => {
                formatter.write_str("custom nostr relay list must be in ascending order")
            }
        }
    }
}

impl Error for NostrError {}
