use crate::transport::UdpTransport;

use iroh::{EndpointId, SecretKey};

use crate::daemon::state::EventLoopState;
use crate::protocol::identity::Identity;
use crate::protocol::{AuthorKey, Nickname};

#[cfg(feature = "host")]
use crate::daemon::handler_ctx;
#[cfg(feature = "host")]
use crate::gossip::event;
#[cfg(feature = "host")]
use crate::protocol::message;

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
    pub(crate) gossip: iroh_gossip::net::Gossip,
    pub(crate) sender: crate::transport::MeshSender,
    pub(crate) mesh: crate::protocol::MeshId,
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
            bob: super::endpoint_id(77),
            gossip,
            sender: crate::transport::MeshSender::new(gossip_sender),
            mesh: crate::protocol::MeshId::from("test"),
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

    pub(crate) fn ctx(&self) -> handler_ctx::HandlerCtx<'_> {
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
        state.unicast_pool = crate::transport::UnicastPool::new(self.endpoint.clone(), false);
        state.peer_endpoints.insert(
            super::nick("bob"),
            iroh::EndpointAddr::new(self.bob)
                .with_relay_url("https://relay.invalid".parse().expect("relay url")),
        );
        state
    }

    pub(crate) fn frame_to_bob(&self) -> message::Verified {
        crate::protocol::Message::new_pong(
            &self.mesh,
            &self.author,
            super::nick("bob"),
            &crate::protocol::MessageId::random(),
        )
        .sign(&self.identity)
    }
}
