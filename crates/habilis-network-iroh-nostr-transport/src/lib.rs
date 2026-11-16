//! Nostr as an iroh custom transport: QUIC datagrams carried in ephemeral Nostr events.
//!
//! It is the last rung before `Other`. The frame, the budget, the counters and the receive path
//! are the core of the gossip transport, built for the Nostr transport id. The sink is the data
//! lane of the Nostr relay client.
//!
//! # Examples
//!
//! A transport listens on the tag of its own endpoint and sends to the tag of a peer. The doc
//! test compiles it but does not run it.
//!
//! ```no_run
//! use habilis_network_iroh_nostr_transport::NostrTransport;
//! use habilis_network_protocol::TopicId;
//! use habilis_network_protocol::nostr::NostrKeys;
//! use iroh::SecretKey;
//!
//! # fn demo() {
//! let keys = NostrKeys::derive(&TopicId::from_bytes([9u8; 32]));
//! let id = SecretKey::from_bytes(&[1u8; 32]).public();
//! let relays = vec!["wss://relay.example".parse().expect("a relay URL")];
//! let transport = NostrTransport::open(id, keys, relays);
//! let _custom = transport.handle().custom_transport();
//! # }
//! ```

mod data_sink;
mod nostr_transport;

pub use nostr_transport::{NOSTR_BUDGET_BYTES_PER_SEC, NostrTransport};
