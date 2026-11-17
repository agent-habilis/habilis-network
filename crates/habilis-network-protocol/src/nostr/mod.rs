//! What a mesh puts on Nostr: the tags it listens on, the relays it ranks, and
//! the sealed, signed signal every event carries.
//!
//! Everything is derived from the gossip topic id, so a peer without the
//! password or the invite (which the topic binds) cannot even find the room.
//! The Nostr key an event is signed with is random and proves nothing; the
//! Ed25519 signature by the sender's iroh endpoint key, inside the seal, is
//! what makes `from` true. Without it anyone holding the mesh id could offer
//! as another member and tear down that member's session.

mod body;
mod nostr_keys;
mod opener;
mod relays;
mod signal;
mod signal_kind;

pub(crate) use body::MAX_ADDRS;
pub use nostr_keys::NostrKeys;
pub use opener::{Opener, REPLAY_WINDOW_SECS};
pub use relays::PINNED_RELAYS;
pub use signal::{Signal, seal};
pub use signal_kind::SignalKind;
