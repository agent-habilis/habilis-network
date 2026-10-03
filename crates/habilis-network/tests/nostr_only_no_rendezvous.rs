//! A mesh whose only lookup is Nostr has no rendezvous: no relay rung to home
//! a beacon on, no loopback ladder, no mDNS or DHT to resolve the bare id.
//! Its members meet over Nostr instead, so the rendezvous machinery must stay
//! quiet — no beacon bound on loopback, no heal tick re-grafting an id nothing
//! can reach.
//!
//! Run with `cargo test -p habilis-network --test nostr_only_no_rendezvous`.

#![cfg(feature = "host")]

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::mesh::NostrChoice;
use habilis_network::protocol::{LookupOpts, MeshConfig, Message, Nickname, TransportPolicy};
use habilis_network::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_config, setup_mesh};

struct Quiet;

#[habilis_network::async_trait]
impl NodeApp for Quiet {
    fn classify(&self, _message: &Message) -> AppClass {
        AppClass {
            loggable: false,
            beat: true,
            valid: true,
            chained: false,
            sealed: false,
        }
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

#[habilis_network::async_trait]
impl NodeDriver for Quiet {
    type Session = ();
    type Http = ();
    type Ipc = serde_json::Value;
}

struct NoSink;

impl NodeSink for NoSink {
    fn emit(&self, _event: NodeEvent) {}
}

/// Every log line the engine writes, for the assertions below.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("no poison").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("no poison")).into_owned()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nostr_only_mesh_binds_no_beacon_and_heals_no_rendezvous() {
    let logs = Captured::default();
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_env_filter("habilis_network=debug")
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .init();

    let topic = format!("nostr-only-{}", rand::random::<u64>());
    let mesh = derive_topic_mesh_config(
        &topic,
        MeshConfig {
            lookups: LookupOpts {
                nostr: NostrChoice::Pinned,
                ..LookupOpts::loopback()
            },
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        },
    )
    .expect("derive a nostr-only mesh");
    let config = setup_mesh(
        SetupKind::Topic {
            mesh,
            topic_string: topic.clone(),
        },
        SetupParams {
            author: Nickname::new("alice").expect("valid nickname"),
            max_peers: 16,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink: Arc::new(NoSink),
            multihop: false,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup a nostr-only mesh");
    let node = Node::spawn(config, Quiet, None, false);

    // Longer than one heal interval (15 s), so a heal tick would have run.
    tokio::time::sleep(Duration::from_secs(20)).await;
    node.leave().await.expect("leave");

    let text = logs.text();
    for forbidden in [
        "beacon assumed",
        "beacon role active",
        "heal tick: re-graft the rendezvous",
        "reclaim tick: re-graft the rendezvous",
    ] {
        assert!(
            !text.contains(forbidden),
            "a nostr-only mesh has no rendezvous, but the log says {forbidden:?}:\n{text}"
        );
    }
}
