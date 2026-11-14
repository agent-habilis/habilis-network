//! Fixtures every unit-test module in this crate was writing for itself.
//!
//! `fresh_state` in particular was copy-pasted into six modules, which is what
//! made [`StateInit`] painful to extend: one new field meant editing six test
//! modules that had no reason to know about it. One home instead.

use crate::transport;
#[cfg(feature = "host")]
use std::net;
#[cfg(feature = "host")]
use tokio::runtime;
mod lane_node;
mod log_capture;
mod wire_counter;

use std::sync::Arc;

use iroh::{EndpointId, SecretKey};
use sha2::{Digest as _, Sha256};

use crate::daemon::state::{
    EventLoopState, FrameOverheads, MeshChunks, MeshSecrets, RunKeys, StateInit,
};
use crate::protocol::identity::Identity;
use crate::protocol::{AuthorKey, Channel, MeshId, Nickname, SymmetricKey, peer_addr_error};
use crate::util::clock::Instant;

use iroh::address_lookup::memory;

#[cfg(feature = "host")]
pub(crate) use lane_node::LaneNode;
#[cfg(feature = "multihop")]
pub(crate) use log_capture::LogCapture;
pub(crate) use wire_counter::{FrameClass, WireCounter};

/// A bare state with a fresh identity: no state file, no secrets, no per-peer
/// gate. The starting point for a test that only cares about one field.
pub(crate) fn fresh_state() -> EventLoopState {
    fresh_state_with_book(memory::MemoryLookup::new())
}

/// [`fresh_state`] with the given address book.
pub(crate) fn fresh_state_with_book(address_book: memory::MemoryLookup) -> EventLoopState {
    fresh_state_that_waits_with_book(address_book)
}

/// [`fresh_state`] for a node with no member key: a client that proves no nickname, which answers
/// no proof request.
pub(crate) fn fresh_state_without_member_key() -> EventLoopState {
    fresh_state_that_waits_with_book_and_member(
        memory::MemoryLookup::new(),
        false,
        MeshSecrets::default(),
    )
}

/// [`fresh_state`] for a mesh with a password, whose mesh key is `key`.
pub(crate) fn fresh_state_with_mesh_key(key: SymmetricKey) -> EventLoopState {
    let secrets = MeshSecrets {
        password: None,
        key: Some(key),
    };
    fresh_state_that_waits_with_book_and_member(memory::MemoryLookup::new(), true, secrets)
}

fn fresh_state_that_waits_with_book(address_book: memory::MemoryLookup) -> EventLoopState {
    fresh_state_that_waits_with_book_and_member(address_book, true, MeshSecrets::default())
}

fn fresh_state_that_waits_with_book_and_member(
    address_book: memory::MemoryLookup,
    member_key: bool,
    secrets: MeshSecrets,
) -> EventLoopState {
    EventLoopState::new(
        StateInit {
            #[cfg(feature = "host")]
            state_file: None,
            chunks: MeshChunks::open(None).expect("a store in memory"),
            overheads: FrameOverheads {
                state: habilis_network_doc::frame_overhead(
                    Channel::State,
                    &MeshId::from("test"),
                    &Nickname::from("test"),
                ),
                meta: habilis_network_doc::frame_overhead(
                    Channel::Meta,
                    &MeshId::from("test"),
                    &Nickname::from("test"),
                ),
                page: habilis_network_doc::page_frame_overhead(
                    &MeshId::from("test"),
                    &Nickname::from("test"),
                ),
            },
            // the keys are shared with the loop and its handlers, which hold clones
            keys: RunKeys {
                member_new: false,
                // shared with the loop and its handlers, which hold clones
                session: Arc::new(Identity::generate()),
                // shared with the loop and its handlers, which hold clones
                member: member_key.then(|| Arc::new(Identity::generate())),
                run: 1,
                key_lock: None,
                keys_state: None,
            },
            secrets,
            webrtc_admission: transport::SignalAdmission::new(transport::MAX_DIRECT_PEERS),
            address_book,
            webrtc_ice: transport::IceProfile::default(),
        },
        Instant::now(),
    )
}

/// The JSON body of a `PeerInfo` for `address`, with a seal key: the body of this wire version
/// names one, and a receiver refuses a body that does not.
pub(crate) fn address_json_with_seal(address: &iroh::EndpointAddr) -> serde_json::Value {
    let mut json = peer_addr_error::endpoint_addr_to_json(address);
    let seal = x25519_dalek::PublicKey::from([9u8; 32]);
    json["seal"] = serde_json::Value::String(bs58::encode(seal.as_bytes()).into_string());
    json
}

/// A nickname, panicking on an invalid one — a test fixture, so a bad literal
/// should fail loudly at the assertion rather than be handled.
pub(crate) fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid test nickname")
}

/// The author key that the roster fixtures give to `nickname`: the same text always gives the
/// same key, and two texts give two keys. The key is the SHA-256 of the whole text, so a nickname
/// of any valid length keeps its own key.
pub(crate) fn test_key(nickname: &str) -> AuthorKey {
    AuthorKey::from_bytes(Sha256::digest(nickname.as_bytes()).into())
}

/// The longest mesh id that a real mesh makes, from a 32-char name and a long relay URL: about 511 bytes.
pub(crate) fn longest_mesh_id() -> MeshId {
    use crate::protocol::{Lookup, Mesh, MeshConfig, MeshName, RelayLadder, Seed};

    let name = MeshName::try_new(&"a".repeat(32)).expect("a 32-char name");
    let mut best = None;
    for host in 1..400 {
        let url = format!("https://{}.example.com/", "r".repeat(host));
        let parsed: Result<RelayLadder, _> = url.parse();
        let Ok(ladder) = parsed else {
            continue;
        };
        let Ok(config) = MeshConfig::resolve(&[Lookup::Relay], Some(ladder), &[]) else {
            continue;
        };
        let Ok(mesh) = Mesh::try_new(Seed::new([4u8; 32]), name.clone(), config) else {
            continue;
        };
        let text = mesh.to_string();
        if text.len() > 512 {
            break;
        }
        if let Ok(id) = MeshId::try_new(&text) {
            best = Some(id);
        }
    }
    best.expect("a long valid mesh id")
}

/// A deterministic endpoint id from `seed`, so a test can name the same peer
/// twice and assert on identity.
pub(crate) fn endpoint_id(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

/// A relay url for a loopback listener that never accepts: the relay
/// handshake hangs, as it does on a rung that is slow to answer. Keep the
/// listener alive for as long as the url is in use.
#[cfg(feature = "host")]
pub(crate) fn silent_relay_rung() -> (net::TcpListener, iroh::RelayUrl) {
    let silent =
        net::TcpListener::bind((net::Ipv4Addr::LOCALHOST, 0)).expect("a silent loopback listener");
    let address = silent.local_addr().expect("its address");
    let rung: iroh::RelayUrl = format!("http://{address}").parse().expect("a relay url");
    (silent, rung)
}

/// Run `body` on a fresh current-thread runtime, drop the runtime as
/// returning from `main` does, and return every ERROR logged meanwhile. That
/// drop is where iroh logs `Endpoint dropped without calling` for an endpoint
/// a task still held open.
#[cfg(feature = "host")]
pub(crate) fn errors_through_runtime_drop(body: impl Future<Output = ()>) -> String {
    let (logs, _guard) = LogCapture::start(tracing::Level::ERROR);
    let runtime = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(body);
    drop(runtime);
    logs.text()
}

/// A capture must see an event even when a thread with no subscriber of its own hit the same
/// callsite first. Run it alone in its process (`--exact`): then the capture is the only
/// dispatcher there is, the case that `tracing` answers from the calling thread's default alone.
#[cfg(feature = "multihop")]
mod log_capture_tests {
    use super::LogCapture;

    use std::thread;
    fn first_event() {
        tracing::debug!(target: "log-capture-test", "first event");
    }

    fn second_event() {
        tracing::debug!(target: "log-capture-test", "second event");
    }

    fn third_event() {
        tracing::debug!(target: "log-capture-test", "third event");
    }

    #[test]
    fn an_event_that_a_thread_without_a_subscriber_hit_first_still_reaches_the_capture() {
        let _trace_guard = ::habilis_network_test_tracing::init();
        let (logs, _guard) = LogCapture::start(tracing::Level::DEBUG);
        thread::spawn(|| {
            first_event();
            second_event();
            third_event();
        })
        .join()
        .expect("the other thread runs");
        first_event();
        second_event();
        third_event();
        let text = logs.text();
        let seen: usize = ["first event", "second event", "third event"]
            .iter()
            .filter(|line| text.contains(**line))
            .count();
        assert_eq!(seen, 3, "the capture saw {seen} of 3 events: {text}");
    }
}

/// Two valid nicknames must not share a key, or two fixture peers merge in the peer set and the
/// name map. A nickname holds up to 32 characters, so the key is a digest of the whole text.
#[cfg(test)]
mod test_key_tests {
    #[test]
    fn a_nickname_that_repeats_another_gets_its_own_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let thirty_two = "x".repeat(32);
        for (short, long) in [("a", "aa"), ("ab", "abab"), ("x", thirty_two.as_str())] {
            assert_ne!(
                super::test_key(short),
                super::test_key(long),
                "{short:?} and {long:?} share a key"
            );
        }
    }

    #[test]
    fn the_same_nickname_always_gives_the_same_key() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            super::test_key("swift-cedar"),
            super::test_key("swift-cedar"),
            "the same text gave two keys"
        );
    }
}
