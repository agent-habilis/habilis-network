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
    EventLoopState::new(
        StateInit {
            state_file: None,
            identity: Arc::new(Identity::generate()),
            secrets: MeshSecrets::default(),
            per_peer_gate: None,
            webrtc_admission: crate::transport::SignalAdmission::new(
                crate::transport::MAX_DIRECT_PEERS,
            ),
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

/// Run `body` on a fresh current-thread runtime, drop the runtime as
/// returning from `main` does, and return every ERROR logged meanwhile. That
/// drop is where iroh logs `Endpoint dropped without calling` for an endpoint
/// a task still held open.
#[cfg(feature = "host")]
pub(crate) fn errors_through_runtime_drop(body: impl Future<Output = ()>) -> String {
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let logs = Captured::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::ERROR)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(body);
    drop(runtime);
    let logs = logs.0.lock().expect("log buffer");
    String::from_utf8_lossy(&logs).into_owned()
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
            sender: crate::transport::MeshSender::new(gossip_sender),
            mesh: crate::protocol::MeshId::from("test"),
            our_pubkey: crate::protocol::identity::encode_pubkey(&identity.public()),
            identity,
            author: nick("alice"),
            sink: crate::gossip::event::SilentSink,
        }
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
        crate::protocol::Message::new_pong(&self.mesh, &self.author, nick("bob"))
    }
}
