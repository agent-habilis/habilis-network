#[cfg(feature = "host")]
use crate::transport::UdpTransport;

#[cfg(feature = "host")]
use iroh::{EndpointId, SecretKey};

#[cfg(feature = "host")]
use crate::daemon::state::EventLoopState;
#[cfg(feature = "host")]
use crate::protocol::identity::Identity;
#[cfg(feature = "host")]
use crate::protocol::{AuthorKey, Nickname};

#[cfg(feature = "host")]
#[cfg(feature = "host")]
use crate::daemon::handler_ctx;
#[cfg(feature = "host")]
#[cfg(feature = "host")]
use crate::gossip::event;
#[cfg(feature = "host")]
#[cfg(feature = "host")]
use crate::protocol::messages;

#[cfg(feature = "host")]
#[cfg(feature = "host")]
use crate::protocol;
#[cfg(feature = "host")]
#[cfg(feature = "host")]
use crate::transport;
#[cfg(feature = "host")]
#[cfg(feature = "host")]
use iroh_gossip::net;
#[cfg(feature = "host")]
#[cfg(feature = "host")]
use iroh_gossip::proto;
/// A real endpoint with a `WebRTC` handle, a gossip sender and everything a [`HandlerCtx`] borrows,
/// for a test that goes through the code that offers a session. The peer `bob` is a lane peer: it
/// has a relay address and no IP, so no frame can be sent to it before its session.
///
/// [`HandlerCtx`]: crate::daemon::handler_ctx::HandlerCtx
#[cfg(feature = "host")]
pub(crate) struct LaneNode {
    pub(crate) endpoint: iroh::Endpoint,
    pub(crate) handle: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    pub(crate) bob: EndpointId,
    pub(crate) gossip: net::Gossip,
    pub(crate) sender: transport::MeshSender,
    pub(crate) mesh: protocol::MeshId,
    pub(crate) identity: Identity,
    pub(crate) our_pubkey: AuthorKey,
    pub(crate) author: Nickname,
    pub(crate) sink: event::SilentSink,
}

#[cfg(feature = "host")]
impl LaneNode {
    pub(crate) async fn start() -> Self {
        use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};
        use iroh::endpoint::presets;

        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let transport = handle.transport();
        let base = iroh::Endpoint::builder(presets::Minimal).secret_key(key);
        let builder = base
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_address_lookup()
            .add_custom_transport(transport);
        let endpoint = builder.bind().await.expect("bind a loopback endpoint");
        let gossip = net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let identity = Identity::generate();
        Self {
            endpoint,
            handle,
            bob: super::endpoint_id(77),
            gossip,
            sender: transport::MeshSender::new(gossip_sender),
            mesh: protocol::MeshId::from("test"),
            our_pubkey: identity.author_key(),
            identity,
            author: super::nick("alice"),
            sink: event::SilentSink,
        }
    }

    /// Stops the gossip actor: a request to the sender returns an error from here on.
    pub(crate) async fn stop_gossip(&self) {
        let _ = self.gossip.shutdown().await;
    }

    pub(crate) fn context(&self) -> handler_ctx::HandlerCtx<'_> {
        handler_ctx::HandlerCtx {
            sender: &self.sender,
            endpoint: &self.endpoint,
            mesh: &self.mesh,
            author: &self.author,
            identity: &self.identity,
            our_pubkey: self.our_pubkey,
            max_peers: 16,
            rendezvous_id: super::endpoint_id(9),
            external_msg_tx: None,
            sink: &self.sink,
        }
    }

    /// A state that has this node's `WebRTC` handle and knows `bob` by a relay address.
    pub(crate) fn state(&self) -> EventLoopState {
        let mut state = super::fresh_state();
        state.webrtc = Some(self.handle.clone());
        state.local_udp_transport = UdpTransport::Absent;
        state.unicast_pool = transport::UnicastPool::new(self.endpoint.clone(), false);
        state.peer_endpoints.insert(
            super::nick("bob"),
            iroh::EndpointAddr::new(self.bob)
                .with_relay_url("https://relay.invalid".parse().expect("relay url")),
        );
        state
    }

    pub(crate) fn frame_to_bob(&self) -> messages::Verified {
        protocol::Message::new_pong(
            &self.mesh,
            &self.author,
            super::nick("bob"),
            &protocol::MessageId::random(),
        )
        .sign(&self.identity)
    }
}
