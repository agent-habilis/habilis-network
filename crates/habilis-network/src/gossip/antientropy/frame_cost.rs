//! The CPU cost of one received frame, per kind, through the real receive path, with no peer.
//!
//! A test and not a `benches/` target, because `ingest` and the state it takes are crate-private.
//! Run it in a release build, at a quiet moment:
//!
//! `cargo test --release -p habilis-network --lib frame_cost -- --ignored --nocapture`.
//!
//! Each frame is a distinct signed frame, so the dedup never drops it as a repeat. The signing is
//! done before the clock starts. Each row is the median of `RUNS` single-frame timings.

use std::collections::HashSet;
use std::hint::black_box;
use std::iter;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh_gossip::net::Gossip;
use iroh_gossip::proto;
use serde_json::json;
use tokio::runtime::Builder;

use super::{
    DigestBody, HeadsBody, WireWindow, digest_windows, handle_digest_at, handle_state_digest,
};
use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::message_log::MissingQuery;
use crate::daemon::state::{EventLoopState, RendezvousFlag, Standing};
use crate::gossip::app::{AppClass, InboundApp, NodeApp};
use crate::gossip::event::SilentSink;
use crate::gossip::json_body;
use crate::gossip::merge_ctx::peer_info_json;
use crate::protocol::identity::Identity;
use crate::protocol::messages::{self, Authored, Verified};
use crate::protocol::{AppTag, Channel, DedupKey, MeshId, Message, MessageBody, Nickname};
use crate::testing::{endpoint_id, fresh_state, nick};
use crate::transport::{self, MeshSender};
use crate::util::clock::Instant;
use crate::util::tuning;

const RUNS: usize = 1000;
const PEERS: usize = 45;
const DEAD: usize = 14;
const LACKS: usize = 10;

/// An app that counts the meta hook, as the app that `on_meta_applied` serves would see it.
#[derive(Default)]
struct Hooked {
    meta_applied: usize,
}

#[async_trait::async_trait]
impl NodeApp for Hooked {
    fn classify(&self, _message: &Authored) -> AppClass {
        AppClass::BEAT.union(AppClass::VALID)
    }

    async fn on_app_frame(
        &mut self,
        _frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _context: &HandlerCtx<'_>,
    ) -> bool {
        false
    }

    fn on_meta_applied(
        &mut self,
        _author: &Nickname,
        _state: &mut EventLoopState,
        _context: &HandlerCtx<'_>,
    ) {
        self.meta_applied += 1;
    }
}

struct Member {
    nick: Nickname,
    identity: Identity,
}

fn member(index: usize) -> Member {
    Member {
        nick: nick(&format!("peer-{index:02}")),
        identity: Identity::generate(),
    }
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn row(name: &str, samples: Vec<Duration>) -> Duration {
    let mid = median(samples);
    println!(
        "{name:<52} {:>9} ns {:>9.2} us",
        mid.as_nanos(),
        mid.as_secs_f64() * 1e6
    );
    mid
}

/// Time `work` once per input, and return the median.
fn time_each<T>(name: &str, inputs: Vec<T>, mut work: impl FnMut(T)) -> Duration {
    let samples = inputs
        .into_iter()
        .map(|input| {
            let start = Instant::now();
            work(input);
            start.elapsed()
        })
        .collect();
    row(name, samples)
}

/// A signed chat frame of `author`, at `timestamp`.
fn chat(author: &Member, mesh: &MeshId, body: &str, timestamp: i64) -> Verified {
    let mut message = Message::new_app(
        mesh,
        &author.nick,
        messages::AppFrameParams::new(
            AppTag::try_new("app_msg").expect("a valid app tag"),
            None,
            None,
            MessageBody::from(body),
        ),
    );
    message.timestamp = timestamp.into();
    message.sign(&author.identity)
}

/// The digest frame that `author` sends for the windows of `holder`, with `drop` ids left out of
/// the first window.
fn chat_digest_from(
    holder: &mut EventLoopState,
    author: &Member,
    mesh: &MeshId,
    drop: usize,
) -> Verified {
    holder.digest_cursor = 0;
    let mut windows = digest_windows(holder).expect("a non-empty log has windows");
    if drop > 0 {
        let mut ids = packed_ids(&windows[0]);
        ids.truncate(ids.len() - drop);
        windows[0].ids = bs58::encode(ids.concat()).into_string();
    }
    let body = json_body(&DigestBody { windows }).expect("a digest serializes");
    Message::new_digest(mesh, &author.nick, body).sign(&author.identity)
}

fn packed_ids(window: &WireWindow) -> Vec<Vec<u8>> {
    let raw = bs58::decode(&window.ids).into_vec().expect("valid base58");
    raw.chunks_exact(16).map(<[u8]>::to_vec).collect()
}

fn digest_ids(frame: &Verified) -> usize {
    let body: DigestBody = serde_json::from_str(frame.body.as_str()).expect("a digest body");
    body.windows
        .iter()
        .map(|window| window.decode_ids().map_or(0, |ids| ids.len()))
        .sum()
}

/// The heads frame of `channel` that `author` sends for `heads`.
fn heads_frame(author: &Member, mesh: &MeshId, heads: Vec<String>, channel: Channel) -> Verified {
    let body = json_body(&HeadsBody {
        heads,
        closing: false,
    })
    .expect("heads");
    Message::new_channel_digest(mesh, &author.nick, body, channel).sign(&author.identity)
}

/// The next meta change of `writer` to its own card, applied to `doc_holder` as it is built.
fn card_change(
    doc_holder: &mut EventLoopState,
    writer: &Member,
    mesh: &MeshId,
    card: &serde_json::Value,
) -> Verified {
    let merge = json!({ "peers": { writer.nick.as_str(): card } });
    let seed = *writer.identity.public().as_bytes();
    let change = doc_holder
        .doc(Channel::Meta)
        .build_change(&merge, &seed)
        .expect("a JSON object merges")
        .expect("a non-empty merge yields a change");
    let (wire, _plain) = doc_holder
        .doc(Channel::Meta)
        .compose_wire_body(&change, None)
        .expect("compose the wire body");
    let frame =
        Message::new_channel_event(mesh, &writer.nick, wire, Channel::Meta).sign(&writer.identity);
    doc_holder.doc_mut(Channel::Meta).ingest(&frame);
    frame
}

/// A state that holds a chat log of `logged` frames and a meta doc of `PEERS` cards, `DEAD` of
/// them of peers that left. Returns the state, the heads that lack the last `LACKS` cards, and
/// the frames of the doc.
fn holder(
    members: &[Member],
    mesh: &MeshId,
    logged: usize,
) -> (EventLoopState, Vec<String>, Vec<Verified>) {
    let mut state = fresh_state();
    state.standing.insert(Standing::Meshed);
    state.rendezvous_flags.insert(RendezvousFlag::Linked);
    let start = 1_790_000_000;
    for index in 0..logged {
        let author = &members[index % members.len()];
        state.message_log.push(chat(
            author,
            mesh,
            &format!("message {index}"),
            start + i64::try_from(index).expect("a small index"),
        ));
    }
    let mut cards = Vec::new();
    let mut lacking = Vec::new();
    for (index, writer) in members.iter().enumerate() {
        if index == members.len() - LACKS {
            lacking = state.doc(Channel::Meta).heads().collect();
        }
        let status = if index < DEAD { "left" } else { "idle" };
        let card =
            json!({ "status": status, "model": "m", "harness": "h", "host": "host", "cwd": "~/x" });
        cards.push(card_change(&mut state, writer, mesh, &card));
    }
    (state, lacking, cards)
}

/// The whole receive path, as `ingest` runs it.
#[test]
#[ignore = "a benchmark: run it in a release build, see the module doc"]
fn frame_cost() {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(run());
}

#[expect(
    clippy::too_many_lines,
    reason = "one bench, one table, in the order it prints"
)]
async fn run() {
    let mesh = MeshId::from("test");
    let members: Vec<Member> = (0..PEERS).map(member).collect();
    let peer = &members[PEERS - 1];

    let endpoint = iroh::Endpoint::builder(presets::Minimal)
        .bind()
        .await
        .expect("bind a local endpoint");
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let topic = gossip
        .subscribe(proto::TopicId::from_bytes([3u8; 32]), vec![])
        .await
        .expect("subscribe to a peerless topic");
    let (gossip_sender, _receiver) = topic.split();
    let sender = MeshSender::new(gossip_sender);
    let identity = Identity::generate();
    let me = nick("reader");
    let sink = SilentSink;
    let context = HandlerCtx {
        sender: &sender,
        endpoint: &endpoint,
        mesh: &mesh,
        author: &me,
        identity: &identity,
        our_pubkey: identity.author_key(),
        max_peers: 64,
        rendezvous_id: endpoint_id(9),
        external_msg_tx: None,
        sink: &sink,
    };
    let mut app = Hooked::default();
    let wire = |frame: &Verified| frame.serialize().expect("serialize").into_bytes();

    println!("UNICAST_DIGESTS = {}", tuning::UNICAST_DIGESTS);
    println!(
        "{RUNS} runs per row, median; {PEERS} peers in the roster and the meta doc, {DEAD} of them dead\n"
    );

    // The reader: a roster of every member, a log of 300 chats (2 full windows), the meta doc.
    let (mut reader, lacking_heads, cards) = holder(&members, &mesh, 300);
    for other in &members {
        reader.peers.insert(other.nick.clone());
    }
    // One frame of the peer before the clock: its first frame greets a new peer, and that is not
    // the idle cost.
    let warm = Message::new_alive(&mesh, &peer.nick).sign(&peer.identity);
    super::super::recv::ingest(wire(&warm), &mut reader, &mut app, &context).await;

    println!("== whole receive path (ingest), from a known peer of a {PEERS}-peer roster");
    let mut ingest_rows = Vec::new();

    macro_rules! ingest_row {
        ($name:expr, $frames:expr) => {{
            let frames: Vec<bytes::Bytes> = $frames;
            let mut samples = Vec::with_capacity(frames.len());
            for frame in frames {
                let start = Instant::now();
                super::super::recv::ingest(frame, &mut reader, &mut app, &context).await;
                samples.push(start.elapsed());
            }
            ingest_rows.push(($name, row($name, samples)));
        }};
    }

    let digests_full: Vec<Verified> = (0..RUNS)
        .map(|_| chat_digest_from(&mut reader, peer, &mesh, 0))
        .collect();
    let ids_full = digest_ids(&digests_full[0]);
    let digests_full_bytes = digests_full.iter().map(wire).collect();
    let resent_before = reader.idle.resent;
    ingest_row!("chat digest, 2 windows, lacks nothing", digests_full_bytes);
    let resent_140 = reader.idle.resent - resent_before;

    let (mut small, _, _) = holder(&members, &mesh, 40);
    let digests_small: Vec<Verified> = (0..RUNS)
        .map(|_| chat_digest_from(&mut small, peer, &mesh, 0))
        .collect();
    let ids_small = digest_ids(&digests_small[0]);
    ingest_row!(
        "chat digest, 40 ids (vs a 300-frame log)",
        digests_small.iter().map(wire).collect()
    );

    let meta_heads: Vec<String> = reader.doc(Channel::Meta).heads().collect();
    let state_heads: Vec<String> = reader.doc(Channel::State).heads().collect();
    ingest_row!(
        "state digest, lacks nothing",
        (0..RUNS)
            .map(|_| wire(&heads_frame(
                peer,
                &mesh,
                state_heads.clone(),
                Channel::State
            )))
            .collect()
    );
    ingest_row!(
        "meta digest, lacks nothing",
        (0..RUNS)
            .map(|_| wire(&heads_frame(peer, &mesh, meta_heads.clone(), Channel::Meta)))
            .collect()
    );
    ingest_row!(
        "alive",
        (0..RUNS)
            .map(|_| wire(&Message::new_alive(&mesh, &peer.nick).sign(&peer.identity)))
            .collect()
    );
    ingest_row!(
        "presence joined",
        (0..RUNS)
            .map(|_| wire(&Message::new_joined(&mesh, &peer.nick).sign(&peer.identity)))
            .collect()
    );
    let peer_endpoint = iroh::SecretKey::generate();
    let address = iroh::EndpointAddr::new(peer_endpoint.public());
    let proof =
        transport::proven_endpoints::sign(&peer_endpoint, &mesh, &peer.identity.author_key());
    let info_body = json_body(&peer_info_json(&address, proof, false)).expect("a PeerInfo body");
    let infos: Vec<bytes::Bytes> = (0..=RUNS)
        .map(|_| {
            wire(&Message::new_peer_info(&mesh, &peer.nick, info_body.clone()).sign(&peer.identity))
        })
        .collect();
    // The first PeerInfo of an endpoint adds its address; the idle mesh sends the same one again.
    super::super::recv::ingest(infos[0].clone(), &mut reader, &mut app, &context).await;
    ingest_row!("PeerInfo (address already known)", infos[1..].to_vec());

    // The writer holds the same doc as the reader: the same card frames.
    let mut writer = fresh_state();
    for card in &cards {
        writer.doc_mut(Channel::Meta).ingest(card);
    }
    let changes: Vec<bytes::Bytes> = (0..RUNS)
        .map(|step| {
            wire(&card_change(
                &mut writer,
                peer,
                &mesh,
                &json!({ "status": "idle", "step": step }),
            ))
        })
        .collect();
    let hooks_before = app.meta_applied;
    ingest_row!("meta change, 1 change on the 45-card doc", changes);
    let hooks = app.meta_applied - hooks_before;

    println!(
        "\nchecks: digest ids {ids_full} and {ids_small}; resends from the 2-window digests {resent_140}; \
         on_meta_applied {hooks} of {RUNS}"
    );

    // The answer path, with this node one of the answerers (an empty roster) and a new asker per
    // frame, so that no per-author serve budget holds an answer back.
    println!("\n== answer path (the handler alone, this node answers every digest)");
    let (mut answerer, _, _) = holder(&members, &mesh, 300);
    let (outbox, mut resends) = transport::ResendOutbox::new(RUNS * 64);
    answerer.resend_outbox = outbox;
    let askers: Vec<Member> = (0..RUNS).map(|index| member(100 + index)).collect();
    let mut at = Instant::now();
    for (label, drop) in [
        ("chat digest answer, asker lacks nothing", 0),
        ("chat digest answer, asker lacks 10", LACKS),
    ] {
        let asks: Vec<Verified> = askers
            .iter()
            .map(|asker| chat_digest_from(&mut answerer, asker, &mesh, drop))
            .collect();
        let sent_before = answerer.idle.resent;
        time_each(label, asks, |frame| {
            at += Duration::from_secs(3600);
            handle_digest_at(&frame, &mut answerer, &me, at);
        });
        println!("    resends queued: {}", answerer.idle.resent - sent_before);
        while resends.try_recv().is_ok() {}
    }
    // An idle mesh logs only the joined frames: about one id per member.
    let (mut idle_answerer, _, _) = holder(&members, &mesh, 12);
    let (idle_outbox, mut idle_resends) = transport::ResendOutbox::new(RUNS * 64);
    idle_answerer.resend_outbox = idle_outbox;
    let idle_asks: Vec<Verified> = askers
        .iter()
        .map(|asker| chat_digest_from(&mut idle_answerer, asker, &mesh, 0))
        .collect();
    time_each(
        "chat digest answer, 12-id log, asker lacks nothing",
        idle_asks,
        |frame| {
            at += Duration::from_secs(3600);
            handle_digest_at(&frame, &mut idle_answerer, &me, at);
        },
    );
    while idle_resends.try_recv().is_ok() {}
    let full_heads: Vec<String> = answerer.doc(Channel::Meta).heads().collect();
    for (label, heads) in [
        ("meta digest answer, asker lacks nothing", full_heads),
        ("meta digest answer, asker lacks 10", lacking_heads),
    ] {
        let heads_asks: Vec<Verified> = askers
            .iter()
            .map(|asker| heads_frame(asker, &mesh, heads.clone(), Channel::Meta))
            .collect();
        let mut samples = Vec::with_capacity(RUNS);
        for frame in heads_asks {
            let start = Instant::now();
            black_box(handle_state_digest(Channel::Meta, &frame, &mut answerer, &context).await);
            samples.push(start.elapsed());
        }
        row(label, samples);
    }

    // What a member pays to send its own frames on a tick.
    println!("\n== send side (build + sign one frame)");
    let me_member = member(99);
    time_each("chat digest, 2 windows (140 ids)", vec![(); RUNS], |()| {
        black_box(chat_digest_from(&mut reader, &me_member, &mesh, 0));
    });
    time_each("chat digest, 12-id log", vec![(); RUNS], |()| {
        black_box(chat_digest_from(&mut idle_answerer, &me_member, &mesh, 0));
    });
    let origin = super::DigestOrigin {
        mesh: &mesh,
        author: &me_member.nick,
    };
    time_each("meta heads digest", vec![(); RUNS], |()| {
        black_box(super::state_digest(&reader, origin, Channel::Meta));
    });
    time_each("alive", vec![(); RUNS], |()| {
        black_box(Message::new_alive(&mesh, &me_member.nick).sign(&me_member.identity));
    });
    time_each("serialize one signed frame (alive)", vec![(); RUNS], |()| {
        black_box(warm.serialize().expect("serialize"));
    });

    // The parts of one 2-window chat digest.
    println!("\n== parts of one 2-window chat digest frame");
    let bytes: Vec<bytes::Bytes> = digests_full.iter().map(wire).collect();
    let parsed: Vec<Message> = bytes
        .iter()
        .map(|frame| Message::parse_wire(frame).expect("parses").0)
        .collect();
    time_each("parse (json + hex)", bytes.clone(), |frame| {
        black_box(Message::parse_wire(&frame).expect("parses"));
    });
    time_each("canonical bytes", parsed.clone(), |message| {
        black_box(message.canonical_bytes());
    });
    let canonical: Vec<(Message, Vec<u8>)> = parsed
        .iter()
        .map(|message| (message.clone(), message.canonical_bytes()))
        .collect();
    time_each("ed25519 verify", canonical, |(message, signed)| {
        assert!(message.verify_signature_with(&signed));
    });
    time_each(
        "dedup key + is_seen + mark_seen",
        digests_full.clone(),
        |frame| {
            let key: DedupKey = frame.dedup_key();
            black_box(reader.is_seen(&key));
            black_box(reader.mark_seen(&frame));
        },
    );
    time_each("body json (DigestBody)", digests_full.clone(), |frame| {
        black_box(serde_json::from_str::<DigestBody>(frame.body.as_str()).expect("a body"));
    });
    let bodies: Vec<DigestBody> = digests_full
        .iter()
        .map(|frame| serde_json::from_str(frame.body.as_str()).expect("a body"))
        .collect();
    time_each(
        "base58 decode of the ids and keys",
        bodies.iter().collect(),
        |body: &DigestBody| {
            for window in &body.windows {
                black_box(window.decode_ids());
                black_box(window.range());
            }
        },
    );
    let mut haves = Vec::new();
    for body in &bodies {
        let mut have = HashSet::new();
        for window in &body.windows {
            have.extend(window.decode_ids().expect("ids"));
        }
        haves.push((body, have));
    }
    time_each(
        "digest diff (missing_in_window), lacks nothing",
        haves.iter().collect(),
        |(body, have)| {
            for window in &body.windows {
                black_box(reader.message_log.missing_in_window(MissingQuery {
                    range: window.range().expect("a range"),
                    have,
                    max: 64,
                    requester: &peer.nick,
                }));
            }
        },
    );
    time_each(
        "answer rank (answers_digest, 45 members)",
        digests_full.clone(),
        |frame| {
            let roster = reader.peers.iter().chain(iter::once(&me));
            black_box(super::answers_digest(
                &me,
                &frame.author,
                frame.id.as_str(),
                roster,
            ));
        },
    );

    println!("\n== summary for the model (ns)");
    for (name, cost) in ingest_rows {
        println!("{name}\t{}", cost.as_nanos());
    }
    endpoint.close().await;
}
