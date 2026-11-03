//! The wire cost of one minute on a mesh of 5 peers, as bytes: metadata against data. Tests only.
//! The file uses no API that is new in PR 47 except the sender tap and `WireCounter`, so the same
//! scenario runs on f7cd9bb (with the tap ported) and on the fixed rev.

use std::time::Duration;

use iroh_gossip::net::Gossip;
use iroh_gossip::proto;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip::app::{AppClass, InboundApp, NodeApp};
use crate::gossip::event::SilentSink;
use crate::lifecycle::{PresenceEvent, handle_presence, heartbeat, observe};
use crate::lookup::{TransportOpts, build_peer_multihop};
use crate::protocol::identity::Identity;
use crate::protocol::meshes::LookupOpts;
use crate::protocol::messages::Authored;
use crate::protocol::{
    AppFrameParams, AppTag, MeshId, Message, MessageBody, PresenceSubtype, UnixSecs, Verified,
};
use crate::testing::{FrameClass, WireCounter, endpoint_id, fresh_state, nick};
use crate::transport::{MeshSender, PayloadPath};
use crate::util::clock::Instant;
use crate::{gossip, protocol};

struct Inert;

#[async_trait::async_trait]
impl NodeApp for Inert {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::BEAT.union(AppClass::VALID)
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        false
    }
}

/// A data frame of `len` payload bytes, signed by `identity`.
fn data_frame(mesh: &MeshId, us: &protocol::Nickname, identity: &Identity, len: usize) -> Verified {
    let mut message = Message::new_app(
        mesh,
        us,
        AppFrameParams::new(
            AppTag::try_new("app_msg").expect("a valid app tag"),
            None,
            None,
            MessageBody::from("x".repeat(len).as_str()),
        ),
    );
    message.timestamp = UnixSecs::now();
    message.sign(identity)
}

/// 5 peers join, this node sends 5 data frames of 512 bytes, then 60 s pass with nothing to send
/// but the keepalive. Every byte that is not in a data frame is metadata. The numbers go to
/// stderr, one line, for the table of the report.
#[test]
fn wire_cost_of_one_minute_with_5_peers() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let (endpoint, handle, _webrtc) = build_peer_multihop(
            &LookupOpts::loopback(),
            TransportOpts::default(),
            None,
            PayloadPath::DirectOnly,
        )
        .await
        .expect("a peer binds");
        handle.close().await;
        let gossip_handle = Gossip::builder().spawn(endpoint.clone());
        let topic = gossip_handle
            .subscribe(proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = MeshSender::new(gossip_sender);
        let (mesh, identity, us, sink) = (
            MeshId::from("test"),
            Identity::generate(),
            nick("us"),
            SilentSink,
        );
        let context = HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &us,
            identity: &identity,
            our_pubkey: identity.author_key(),
            max_peers: 16,
            rendezvous_id: endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = fresh_state();
        let mut app = Inert;

        for name in [
            "swift-cedar",
            "lost-heron",
            "calm-otter",
            "bold-finch",
            "wild-crane",
        ] {
            let joined = Message::new_joined(&mesh, &nick(name)).sign(&Identity::generate());
            let observed = observe(&joined, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &joined,
                    subtype: PresenceSubtype::Joined,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;
        }
        for _ in 0..5 {
            gossip::broadcast_msg(&sender, &data_frame(&mesh, &us, &identity, 512)).await;
        }
        let mut since_send = 0u64;
        for _ in 0..60 {
            since_send += 1;
            state.last_sent_at = Instant::now()
                .checked_sub(Duration::from_secs(since_send))
                .expect("the monotonic clock has run past 60 s since boot");
            let before = sender.broadcast_frames().len();
            heartbeat::tick_alive(&mut state, &sender, &mesh, &us).await;
            if sender.broadcast_frames().len() > before {
                since_send = 0;
            }
        }

        let mut frames = sender.broadcast_frames();
        frames.extend(state.unicast_pool.sent_frames());
        let counter = WireCounter::of(&frames);
        eprintln!("WIRE one minute, 5 peers: {counter}");
        assert_eq!(
            counter.frames(FrameClass::Joined),
            0,
            "this node announced its own joined again for an arrival: {counter}"
        );
        assert_eq!(
            counter.frames(FrameClass::Alive),
            2,
            "the idle minute needs one keepalive per ALIVE_INTERVAL: {counter}"
        );
        assert_eq!(
            counter.frames(FrameClass::Data),
            5,
            "the 5 data frames of the workload were not all counted: {counter}"
        );
        endpoint.close().await;
    });
}
