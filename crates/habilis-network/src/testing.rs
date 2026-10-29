//! Fixtures every unit-test module in this crate was writing for itself.
//!
//! `fresh_state` in particular was copy-pasted into six modules, which is what
//! made [`StateInit`] painful to extend: one new field meant editing six test
//! modules that had no reason to know about it. One home instead.

mod lane_node;
mod log_capture;

use std::sync::Arc;

use iroh::{EndpointId, SecretKey};

use crate::daemon::state::{EventLoopState, MeshSecrets, StateInit};
use crate::protocol::identity::Identity;
use crate::protocol::{AuthorKey, Nickname};
use crate::util::clock::Instant;

use iroh::address_lookup::memory;

pub(crate) use lane_node::LaneNode;
pub(crate) use log_capture::LogCapture;
/// The key of the test author `name`: its bytes, zero-padded to 32. Two names keep the order
/// that their bytes have, and a test reads the name back in a failure message.
pub(crate) fn author_of(name: &str) -> AuthorKey {
    let mut bytes = [0u8; 32];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    AuthorKey::from(bytes)
}

/// A bare state with a fresh identity: no state file, no secrets, no per-peer
/// gate. The starting point for a test that only cares about one field.
pub(crate) fn fresh_state() -> EventLoopState {
    fresh_state_with_book(memory::MemoryLookup::new())
}

/// [`fresh_state`] with the given address book.
pub(crate) fn fresh_state_with_book(address_book: memory::MemoryLookup) -> EventLoopState {
    EventLoopState::new(
        StateInit {
            #[cfg(feature = "host")]
            state_file: None,
            // the identity is shared with the loop and its handlers, which hold clones
            identity: Arc::new(Identity::generate()),
            secrets: MeshSecrets::default(),
            per_peer_gate: None,
            webrtc_admission: crate::transport::SignalAdmission::new(
                crate::transport::MAX_DIRECT_PEERS,
            ),
            address_book,
            webrtc_ice: crate::transport::IceProfile::default(),
        },
        Instant::now(),
    )
}

/// A nickname, panicking on an invalid one — a test fixture, so a bad literal
/// should fail loudly at the assertion rather than be handled.
pub(crate) fn nick(name: &str) -> Nickname {
    Nickname::try_new(name).expect("valid test nickname")
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
pub(crate) fn silent_relay_rung() -> (std::net::TcpListener, iroh::RelayUrl) {
    let silent = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("a silent loopback listener");
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
    let runtime = tokio::runtime::Builder::new_current_thread()
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
    use habilis_network_test_tracing::test;

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
        let (logs, _guard) = LogCapture::start(tracing::Level::DEBUG);
        std::thread::spawn(|| {
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
