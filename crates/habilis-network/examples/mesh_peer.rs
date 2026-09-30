//! A minimal mesh peer, for interop testing against a browser peer.
//!
//! ```text
//! cargo run -p habilis-network --example mesh_peer              # create, print the id
//! cargo run -p habilis-network --example mesh_peer -- <id>    # join that mesh
//! MESH_TRANSPORT=webrtc cargo run -p habilis-network --example mesh_peer  # create a WebRTC-only mesh
//! MESH_RELAY_TRANSPORT=on cargo run -p habilis-network --example mesh_peer   # create: relay may carry payload (the `relay_transport` create option)
//! ```
//!
//! `MESH_TRANSPORT=webrtc` leaves `udp` out of the mesh's transport list, so
//! any data path that is not the `WebRTC` one is a failure rather than a silent
//! fallback. The relay stays — it is the rendezvous, and the JSEP exchange
//! rides it. A joiner takes the list from the id and ignores the variable.
//!
//! Prints one line per second: the gossip roster count and the number of live
//! `WebRTC` sessions. Those two numbers are the whole point — they are what a
//! browser peer must be able to move.
//!
//! This is also the smallest possible answer to "what does embedding the engine
//! take": a driver with two required methods and three associated types.
//! Everything else on `NodeDriver` has a default.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, SilentSink,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{
    DirectorySelection, JoinTarget, LookupOpts, MeshConfig, MeshName, Message, TransportPolicy,
};
use habilis_network::runtime::{CreateParams, JoinParams, Node, Resolved, SetupParams, setup_mesh};

/// The do-nothing application. A peer that only carries presence still forms a
/// mesh — payload handling is a separate concern from membership.
struct Probe;

#[habilis_network::async_trait]
impl NodeApp for Probe {
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
impl NodeDriver for Probe {
    type Session = ();
    type Http = ();
    type Ipc = serde_json::Value;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "habilis_network=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Env var rather than a flag: this example takes exactly one positional
    // argument and adding a parser for one knob is not worth it. The real CLI
    // surface is `--transport`, on `agent-share`.
    let udp = match std::env::var("MESH_TRANSPORT").as_deref() {
        Ok("webrtc") => false,
        Ok(other) if !other.is_empty() => {
            anyhow::bail!("unknown MESH_TRANSPORT {other:?}; expected `webrtc`")
        }
        _ => true,
    };

    // A topic mesh, for pairing with a browser peer: the harness page joins
    // by topic, so the two sides meet on one string. `MESH_RELAY_URLS`
    // (comma-separated) swaps the default ladder — with a topic it is part
    // of the derived id, so both sides must pass the same list.
    let relay_urls = std::env::var("MESH_RELAY_URLS")
        .ok()
        .filter(|urls| !urls.is_empty());
    if let Ok(topic) = std::env::var("MESH_TOPIC") {
        let ladder = match &relay_urls {
            Some(urls) => habilis_network::protocol::RelayChoice::Custom(
                urls.split(',')
                    .map(|url| url.trim().parse())
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => habilis_network::protocol::RelayChoice::Pinned,
        };
        let mesh = habilis_network::runtime::derive_topic_mesh_config(
            &topic,
            MeshConfig {
                lookups: LookupOpts {
                    mdns: true,
                    dht: true,
                    relay_lookup: ladder,
                    pkarr: habilis_network::protocol::PkarrChoice::Disabled,
                },
                password: None,
                issuer_pubkey: None,
                transport: TransportPolicy {
                    relay_transport: std::env::var_os("MESH_RELAY_TRANSPORT")
                        .is_some_and(|value| value == "on"),
                    udp,
                    ..TransportPolicy::default()
                },
            },
        )?;
        return run_peer(
            habilis_network::runtime::SetupKind::Topic {
                mesh,
                topic_string: topic,
            },
            habilis_network::protocol::Nickname::random(),
        )
        .await;
    }

    let arg = std::env::args().nth(1);
    let Resolved { kind, author, .. } = match arg {
        Some(id) => JoinParams {
            target: id.parse::<JoinTarget>()?,
            nickname: None,
            password: None,
        }
        .resolve()?,
        None => CreateParams {
            name: MeshName::random(),
            nickname: None,
            // Public preset: mDNS + DHT + the pinned relay ladder. The relay
            // rung is the part that matters here — it is the only leg a browser
            // peer has, and the rendezvous homes on it.
            config: MeshConfig {
                lookups: LookupOpts::public_preset(),
                password: None,
                issuer_pubkey: None,
                // Baked into the id, so a joiner inherits it: only the
                // creator reads the env var.
                transport: TransportPolicy {
                    relay_transport: std::env::var_os("MESH_RELAY_TRANSPORT")
                        .is_some_and(|value| value == "on"),
                    udp,
                    ..TransportPolicy::default()
                },
            },
            advertise: DirectorySelection::Unset,
            password: None,
            invite_only: false,
        }
        .resolve()?,
    };

    run_peer(kind, author).await
}

/// Stand the peer up and print its per-second status until ctrl-c.
async fn run_peer(
    kind: habilis_network::runtime::SetupKind,
    author: habilis_network::protocol::Nickname,
) -> anyhow::Result<()> {
    // The live peer count, mirrored out of the loop on every roster change and
    // on the periodic refresh. Lock-free, so reading it per second costs
    // nothing and needs no request/response hop into the loop.
    let live = Arc::new(AtomicUsize::new(0));
    let config = setup_mesh(
        kind,
        SetupParams {
            author: author.clone(),
            max_peers: 16,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            // No files and no control socket: this is an embedded peer, not a
            // daemon something else drives.
            runtime_base: None,
            state_file: None,
            sink: Arc::new(SilentSink),
            multihop: false,
            per_peer_gate: None,
            cohost: None,
            live_count: Some(Arc::clone(&live)),
        },
    )
    .await?;

    println!("mesh    {}", config.mesh_id().as_str());
    println!("nick    {author}");

    // `handle_signals: false` — registering tokio's signal handlers suppresses
    // the OS default-terminate for the whole process, permanently. This example
    // wants ctrl-c to keep working.
    let node: Node<Probe> = Node::spawn(config, Probe, None, false);

    let ticker = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            println!("peers   {}", live.load(Ordering::Relaxed));
        }
    };
    tokio::select! {
        () = ticker => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    node.leave().await?;
    Ok(())
}
