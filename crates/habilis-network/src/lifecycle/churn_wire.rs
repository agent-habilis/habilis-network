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

/// The bytes of one `PeerInfo` frame that the host and the key of the node do not decide: the
/// envelope, the nickname, the stamp, the proof and the signature. The address of the node and the
/// Base58 text of its seal key vary per run, so each frame counts them from its own body.
const ANNOUNCE_FIXED_BYTES: usize = 563;

/// The bytes that one `PeerInfo` frame has on top of [`ANNOUNCE_FIXED_BYTES`], read back from the
/// frame itself.
///
/// The address: the body holds it as a JSON string inside a JSON string, so the count is that of the
/// escaped text. The node sends the address that it has when it sends the frame, and the host can
/// change it between two frames (a port of 4 digits, a second address).
///
/// The seal key: its Base58 text is about 44 characters, fewer for a small key (43 in about 6% of
/// the runs). A count taken once, or a constant for 44, is 1 byte per frame too many in a run with a
/// key of 43. The text must be the Base58 of 32 bytes, which the engine decodes: another encoding is
/// a change of the wire form, and the count must not absorb it.
fn varying_bytes_of(frame: &Message) -> usize {
    let body: serde_json::Value =
        serde_json::from_str(frame.body.as_str()).expect("a PeerInfo body is JSON");
    let address = serde_json::json!({
        "id": body["id"],
        "ips": body["ips"],
        "relay": body["relay"],
    })
    .to_string();
    let escaped_address = serde_json::to_string(&address)
        .expect("a string serializes")
        .len();
    gossip::peer_info_seal_key(&body).expect("a PeerInfo seal is the Base58 of 32 bytes");
    let seal = body["seal"]
        .as_str()
        .expect("a PeerInfo names its seal key");
    escaped_address + seal.len()
}

/// The bytes that the `PeerInfo` frames among `frames` have on top of their fixed part, each read
/// from its own frame.
fn announce_varying_bytes(frames: &[Vec<u8>]) -> usize {
    let parsed = frames.iter().filter_map(|bytes| Message::parse(bytes).ok());
    let announces = parsed.filter(|message| FrameClass::of(&message.kind) == FrameClass::Announce);
    announces.map(|message| varying_bytes_of(&message)).sum()
}

/// The unmeshed minute sends no membership, document or other frame. The bytes of the data frames
/// and of the keepalives are exact: 15 runs gave the same line. The bytes of the 5 `PeerInfo` frames
/// are the fixed part of each frame plus its own address and seal key text, which the host and the
/// key decide: `varying_bytes` is the sum over the 5 frames. A change to the wire form moves them.
fn assert_no_other_frame_and_exact_bytes(counter: &WireCounter, varying_bytes: usize) {
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
    let announce = 5 * ANNOUNCE_FIXED_BYTES + varying_bytes;
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
        let parsed = frames.iter().filter_map(|bytes| Message::parse(bytes).ok());
        let data = parsed.filter(|message| FrameClass::of(&message.kind) == FrameClass::Data);
        let data_bodies: Vec<usize> = data.map(|message| message.body.as_str().len()).collect();
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
        assert_no_other_frame_and_exact_bytes(&counter, announce_varying_bytes(&frames));
        assert_eq!(
            data_bodies,
            vec![512; 5],
            "a data frame of the workload does not carry a 512-byte body: {counter}"
        );
        endpoint.close().await;
    });
}

/// 5 `PeerInfo` frames. The first 4 carry an address with a port of 5 digits and a seal key of 44
/// characters (32 bytes of 0xff). The last carries a port of 4 digits and a seal key of 43 (a 1 in
/// the first byte), as when the host changes its address between two frames and another run draws
/// another key. The count follows each frame: the numbers of the first frame, taken for all 5, are 2
/// bytes too many.
#[test]
fn the_announce_bytes_follow_the_address_and_the_seal_key_that_each_frame_carries() {
    let _guard = ::habilis_network_test_tracing::init();
    let (mesh, identity, us) = (MeshId::from("test"), Identity::generate(), nick("us"));
    let address_on = |port: &str| {
        iroh::EndpointAddr::new(endpoint_id(1)).with_ip_addr(port.parse().expect("an address"))
    };
    let frame = |carried: &iroh::EndpointAddr, seal: &str| {
        let mut body = peer_addr_error::endpoint_addr_to_json(carried);
        body["proof"] = serde_json::Value::String("proof".to_owned());
        body["seal"] = serde_json::Value::String(seal.to_owned());
        let message =
            Message::new_peer_info(&mesh, &us, MessageBody::from(body.to_string().as_str()));
        let wire = message
            .sign(&identity)
            .serialize()
            .expect("a frame serializes");
        wire.into_bytes().to_vec()
    };
    let address_bytes = |carried: &iroh::EndpointAddr| {
        let json = peer_addr_error::endpoint_addr_to_json(carried).to_string();
        serde_json::to_string(&json)
            .expect("a string serializes")
            .len()
    };
    let (long, short) = (address_on("127.0.0.1:54321"), address_on("127.0.0.1:5432"));
    let mut small = [0u8; 32];
    small[0] = 1;
    let (seal_44, seal_43) = (
        bs58::encode([0xff_u8; 32]).into_string(),
        bs58::encode(small).into_string(),
    );
    assert_eq!(
        (seal_44.len(), seal_43.len()),
        (44, 43),
        "the 2 keys are the 2 lengths of the run"
    );
    let frames = vec![
        frame(&long, &seal_44),
        frame(&long, &seal_44),
        frame(&long, &seal_44),
        frame(&long, &seal_44),
        frame(&short, &seal_43),
    ];

    let counted = announce_varying_bytes(&frames);

    let first = address_bytes(&long) + 44;
    assert_eq!(
        counted,
        4 * first + address_bytes(&short) + 43,
        "each frame counts the address and the seal key that it carries"
    );
    assert_eq!(
        counted + 2,
        5 * first,
        "the numbers of the first frame, taken for all 5, are 2 bytes too many"
    );
}

/// A seal of another encoding is a change of the wire form: the count refuses it, and does not absorb
/// its length.
#[test]
#[should_panic(expected = "a PeerInfo seal is the Base58 of 32 bytes")]
fn a_seal_that_is_not_the_base58_of_32_bytes_is_refused() {
    let _guard = ::habilis_network_test_tracing::init();
    let (mesh, identity, us) = (MeshId::from("test"), Identity::generate(), nick("us"));
    let address = iroh::EndpointAddr::new(endpoint_id(1));
    let mut body = peer_addr_error::endpoint_addr_to_json(&address);
    body["seal"] = serde_json::Value::String("ab".repeat(32));
    let message = Message::new_peer_info(&mesh, &us, MessageBody::from(body.to_string().as_str()));

    let _ = varying_bytes_of(&message.sign(&identity));
}
