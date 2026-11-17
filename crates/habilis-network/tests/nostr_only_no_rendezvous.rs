//! A mesh whose only lookup is Nostr has no rendezvous: no relay rung to home
//! a beacon on, no loopback ladder, no mDNS or DHT to resolve the bare id.
//! Its members meet over Nostr instead, so the rendezvous machinery must stay
//! quiet — no beacon bound on loopback, no heal tick re-grafting an id nothing
//! can reach.
//!
//! Run with `cargo test -p habilis-network --test nostr_only_no_rendezvous`.

#![cfg(feature = "host")]

use std::sync::Arc;
use std::time::Duration;
use tokio::time;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent, NodeSink,
};
use habilis_network::protocol::meshes::{Mesh, NostrChoice};
use habilis_network::protocol::messages::Authored;
use habilis_network::protocol::{LookupOpts, MeshConfig, Nickname, TransportPolicy};
use habilis_network::runtime::{
    EventLoopConfig, Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_config,
    setup_mesh,
};
use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use url::Url;

struct Quiet;

#[habilis_network::async_trait]
impl NodeApp for Quiet {
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

#[test]
fn a_nostr_only_mesh_binds_no_beacon_and_heals_no_rendezvous() {
    let guard = habilis_network_test_tracing::init_capturing("habilis_network=debug");
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        // A relay of this machine: a test must not need the internet.
        let relay = TestRelay::spawn().await.expect("test relay");
        let nonce: u64 = rand::random();
        let topic = format!("nostr-only-{nonce}");
        let urls: Vec<Url> = vec![relay.url()];
        let lookups = LookupOpts::loopback().nostr(NostrChoice::Custom(urls));
        let mesh_config = MeshConfig::new(lookups, None, None, TransportPolicy::default());
        let mesh: Mesh =
            derive_topic_mesh_config(&topic, mesh_config).expect("derive a nostr-only mesh");
        let author = Nickname::try_new("alice").expect("valid nickname");
        // the node keeps the sink for the life of the mesh
        let sink = Arc::new(NoSink);
        let params = SetupParams::new(author, sink).max_peers(16);
        let kind = SetupKind::Topic {
            mesh,
            topic_string: topic.clone(),
        };
        let config: EventLoopConfig = setup_mesh(kind, params)
            .await
            .expect("setup a nostr-only mesh");
        let node = Node::spawn(config, Quiet, None, SignalHandling::Leave);

        // Longer than one heal interval (15 s), so a heal tick would have run.
        time::sleep(Duration::from_secs(20)).await;
        node.leave().await.expect("leave");

        let text = habilis_network_test_tracing::captured_logs();
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
    });
}
