//! The application broadcast bytes of one minute with 5 peers announced locally: metadata against
//! data. Tests only. The node has no gossip neighbors, so the per-neighbor sends and the relayed
//! frames of a real mesh are not counted.
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
    peer_addr_error,
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

/// The bytes of one `PeerInfo` frame that do not depend on the address of the node: the envelope,
/// the nickname, the stamp, the proof and the signature.
const ANNOUNCE_FIXED_BYTES: usize = 549;

/// The bytes that the address of the node adds to a `PeerInfo` frame. The body holds the address
/// as a JSON string inside a JSON string, so the count is that of the escaped text. A port of 4
/// digits or a second address on the host moves this count, and nothing else.
fn announce_address_bytes(endpoint: &iroh::Endpoint) -> usize {
    let address = peer_addr_error::endpoint_addr_to_json(&endpoint.addr()).to_string();
    serde_json::to_string(&address)
        .expect("a string serializes")
        .len()
}

/// The unmeshed minute sends no membership, document or other frame. The bytes of the data frames
/// and of the keepalives are exact: 15 runs gave the same line. The bytes of the 5 `PeerInfo` frames
/// are the fixed part of the frame plus the address of the node, which the host decides. A change
/// to the wire form moves them.
fn assert_no_other_frame_and_exact_bytes(counter: &WireCounter, address_bytes: usize) {
    for class in [
        FrameClass::Membership,
        FrameClass::Document,
        FrameClass::Other,
    ] {
        assert_eq!(
            counter.frames(class),
            0,
            "the unmeshed minute sent a {class:?} frame: {counter}"
        );
    }
    let announce = 5 * (ANNOUNCE_FIXED_BYTES + address_bytes);
    for (class, bytes) in [
        (FrameClass::Data, 4655),
        (FrameClass::Announce, announce),
        (FrameClass::Alive, 852),
    ] {
        assert_eq!(
            counter.bytes(class),
            bytes,
            "the {class:?} bytes of the minute moved: {counter}"
        );
    }
    assert_eq!(
        counter.total_bytes(),
        4655 + announce + 852,
        "the bytes of the minute moved: {counter}"
    );
}

/// 5 peers join, this node sends 5 data frames of 512 bytes, then 60 s pass with nothing to send
/// but the keepalive. Every broadcast byte that is not in a data frame is metadata. The fixture is
/// not meshed and the idle loop calls only `heartbeat::tick_alive`: the minute excludes the
/// link-state vector that a meshed node broadcasts while idle, so it
/// is a lower bound for that node. Directed (point-to-point) sends are not measured: the unicast
/// pool of the fixture is detached and writes no frame. The numbers go to stderr, one line, for
/// the table of the report.
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

        let frames = sender.broadcast_frames();
        let counter = WireCounter::of(&frames);
        let parsed = frames
            .iter()
            .filter_map(|bytes| Message::parse_wire(bytes).ok());
        let data = parsed.filter(|(message, _)| FrameClass::of(&message.kind) == FrameClass::Data);
        let data_bodies: Vec<usize> = data
            .map(|(message, _)| message.body.as_str().len())
            .collect();
        eprintln!("WIRE one minute, 5 peers: {counter}");
        assert_eq!(
            counter.frames(FrameClass::Joined),
            0,
            "this node announced its own joined again for an arrival: {counter}"
        );
        assert_eq!(
            counter.frames(FrameClass::Announce),
            5,
            "each arrival needs exactly one PeerInfo dial hint: {counter}"
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
        assert_no_other_frame_and_exact_bytes(&counter, announce_address_bytes(&endpoint));
        assert_eq!(
            data_bodies,
            vec![512; 5],
            "a data frame of the workload does not carry a 512-byte body: {counter}"
        );
        endpoint.close().await;
    });
}
