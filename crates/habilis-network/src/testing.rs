//! Fixtures every unit-test module in this crate was writing for itself.
//!
//! `fresh_state` in particular was copy-pasted into six modules, which is what
//! made [`StateInit`] painful to extend: one new field meant editing six test
//! modules that had no reason to know about it. One home instead.

use std::sync::Arc;

use iroh::{EndpointId, SecretKey};

use crate::daemon::state::{EventLoopState, MeshSecrets, StateInit};
use crate::protocol::Nickname;
use crate::protocol::identity::Identity;
use crate::util::clock::Instant;

/// A bare state with a fresh identity: no state file, no secrets, no per-peer
/// gate. The starting point for a test that only cares about one field.
pub(crate) fn fresh_state() -> EventLoopState {
    fresh_state_with_book(iroh::address_lookup::memory::MemoryLookup::new())
}

/// [`fresh_state`] with the given address book.
pub(crate) fn fresh_state_with_book(
    address_book: iroh::address_lookup::memory::MemoryLookup,
) -> EventLoopState {
    EventLoopState::new(
        StateInit {
            #[cfg(feature = "host")]
            state_file: None,
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
    Nickname::new(name.to_owned()).expect("valid test nickname")
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
    let rung = format!("http://{}", silent.local_addr().expect("its address"))
        .parse()
        .expect("a relay url");
    (silent, rung)
}

/// The logs that a test captured from its own thread, see [`LogCapture::start`].
#[cfg(feature = "multihop")]
#[derive(Clone, Default)]
pub(crate) struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(feature = "multihop")]
impl LogCapture {
    /// Capture every event up to `level` that the calling thread logs, until the guard drops.
    pub(crate) fn start(level: tracing::Level) -> (Self, tracing::subscriber::DefaultGuard) {
        // While one dispatcher is the only one registered, `tracing` answers the interest of a
        // callsite from the default of the thread that hits it first. A parallel test thread
        // with no default of its own then caches "never" on a callsite that this capture
        // needs, and the event is dropped. A second dispatcher, kept for the whole process,
        // makes `tracing` ask every registered dispatcher instead.
        static SECOND_DISPATCHER: std::sync::OnceLock<tracing::Dispatch> =
            std::sync::OnceLock::new();
        SECOND_DISPATCHER
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        let capture = Self::default();
        let writer = capture.clone();
        let guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_max_level(level)
                .finish(),
        );
        (capture, guard)
    }

    /// Everything that was captured so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
    }
}

#[cfg(feature = "multihop")]
impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

/// A real endpoint with a `WebRTC` handle, a gossip sender and everything a [`HandlerCtx`] borrows,
/// for a test that goes through the code that offers a session. The peer `bob` is a lane peer: it
/// has a relay address and no IP, so no frame can be sent to it before its session.
///
/// [`HandlerCtx`]: crate::daemon::ctx::HandlerCtx
#[cfg(feature = "host")]
pub(crate) struct LaneNode {
    pub(crate) endpoint: iroh::Endpoint,
    pub(crate) handle: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    pub(crate) bob: EndpointId,
    gossip: iroh_gossip::net::Gossip,
    sender: crate::transport::MeshSender,
    mesh: crate::protocol::MeshId,
    identity: Identity,
    our_pubkey: String,
    author: Nickname,
    sink: crate::gossip::event::SilentSink,
}

#[cfg(feature = "host")]
impl LaneNode {
    pub(crate) async fn start() -> Self {
        use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};
        use iroh::endpoint::presets;

        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let endpoint = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_address_lookup()
            .add_custom_transport(handle.transport())
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let identity = Identity::generate();
        Self {
            endpoint,
            handle,
            bob: endpoint_id(77),
            gossip,
            sender: crate::transport::MeshSender::new(gossip_sender),
            mesh: crate::protocol::MeshId::from("test"),
            our_pubkey: crate::protocol::identity::encode_pubkey(&identity.public()),
            identity,
            author: nick("alice"),
            sink: crate::gossip::event::SilentSink,
        }
    }

    /// Stops the gossip actor: a request to the sender returns an error from here on.
    pub(crate) async fn stop_gossip(&self) {
        let _ = self.gossip.shutdown().await;
    }

    pub(crate) fn ctx(&self) -> crate::daemon::ctx::HandlerCtx<'_> {
        crate::daemon::ctx::HandlerCtx {
            sender: &self.sender,
            endpoint: &self.endpoint,
            mesh: &self.mesh,
            author: &self.author,
            identity: &self.identity,
            our_pubkey: &self.our_pubkey,
            max_peers: 16,
            rendezvous_id: endpoint_id(9),
            external_msg_tx: None,
            sink: &self.sink,
        }
    }

    /// A state that has this node's `WebRTC` handle and knows `bob` by a relay address.
    pub(crate) fn state(&self) -> EventLoopState {
        let mut state = fresh_state();
        state.webrtc = Some(self.handle.clone());
        state.local_udp_transport = false;
        state.unicast_pool = crate::transport::UnicastPool::new(self.endpoint.clone(), false);
        state.peer_endpoints.insert(
            nick("bob"),
            iroh::EndpointAddr::new(self.bob)
                .with_relay_url("https://relay.invalid".parse().expect("relay url")),
        );
        state
    }

    pub(crate) fn frame_to_bob(&self) -> crate::protocol::Message {
        crate::protocol::Message::new_pong(
            &self.mesh,
            &self.author,
            nick("bob"),
            &crate::protocol::MessageId::random(),
        )
    }
}

/// A capture must see an event even when a thread with no subscriber of its own hit the same
/// callsite first. Run it alone in its process (`--exact`): then the capture is the only
/// dispatcher there is, the case that `tracing` answers from the calling thread's default alone.
#[cfg(feature = "multihop")]
mod log_capture_tests {
    use super::LogCapture;

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
        let seen = ["first event", "second event", "third event"]
            .iter()
            .filter(|line| text.contains(**line))
            .count();
        assert_eq!(seen, 3, "the capture saw {seen} of 3 events: {text}");
    }
}
