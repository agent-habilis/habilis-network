//! A gossip link on a pair that never sent unicast loses its direct IP path, and
//! the pair recovers.
//!
//! Direct connections are on demand: a pair is offered a `WebRTC` session only
//! after a send, and its path is watched only while a pooled connection exists. A
//! pair that only gossips has neither. This test pins what remains for it: the
//! relay policy closes a gossip link that stays on the relay, and the pair must
//! then find another direct path (a `WebRTC` session) and form its link again.
//!
//! Two members on a local relay, the default transport list (`udp,webrtc,multihop`,
//! the relay for lookup only). Nothing is sent between them before the block: the
//! only traffic is the engine's own gossip.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::Lookup;
use tokio::sync::mpsc::UnboundedReceiver;

/// Past the point where the relay policy closes a gossip link that stayed on the
/// relay: the probe deadline of 15 s, and a margin. A broadcast sent before it can
/// still arrive over the relay, which proves nothing about recovery.
const SETTLE: Duration = Duration::from_secs(45);

/// Long enough, after that, for an ICE round and for the link to form again.
const RECOVERY_DEADLINE: Duration = Duration::from_mins(2);

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
    seen: Vec<Inbound>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            _events: events,
            seen: Vec::new(),
        }
    }

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
            relay_urls: vec![relay.to_string()],
            ..membership::Opts::default()
        })
        .await
    }

    async fn join(nick: &str, creator: &Self) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            mesh: Some(creator.membership.node.mesh_id().to_string()),
            ..membership::Opts::default()
        })
        .await
    }

    async fn roster_len(&self) -> usize {
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(&json)
            .ok()
            .and_then(|roster| roster["peers"].as_array().map(Vec::len))
            .unwrap_or(0)
    }

    fn ports(&self) -> Vec<u16> {
        self.membership.node.bound_ports().to_vec()
    }

    async fn block_ip_to(&self, ports: Vec<u16>) {
        self.membership
            .request(|reply| Request::BlockIpTo {
                remote_ports: ports,
                reply,
            })
            .await
            .expect("the loop answers");
    }

    async fn broadcast(&self, text: &str) {
        let body = membership::msg_body(text).expect("fits one frame");
        self.membership
            .request(|reply| Request::Send {
                to: None,
                body,
                reply,
            })
            .await
            .expect("the loop answers")
            .expect("sent");
    }

    fn saw(&mut self, text: &str) -> bool {
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen.push(msg);
        }
        self.seen.iter().any(|msg| msg.text == text)
    }
}

/// With `RUST_LOG` set, a failing run prints the engine's log.
fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gossip_pair_that_never_sent_unicast_recovers_when_ip_is_lost() {
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let alice = Member::create("alice", &relay).await;
    let mut bob = Member::join("bob", &alice).await;

    let linking = Instant::now();
    while alice.roster_len().await != 1 || bob.roster_len().await != 1 {
        assert!(
            linking.elapsed() < Duration::from_mins(1),
            "the pair never linked"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Both ends lose IP to each other. Nothing has been sent between them.
    alice.block_ip_to(bob.ports()).await;
    bob.block_ip_to(alice.ports()).await;

    // Let the relay policy act first, and note what the rosters read meanwhile.
    let mut lowest = usize::MAX;
    let settling = Instant::now();
    while settling.elapsed() < SETTLE {
        lowest = lowest
            .min(alice.roster_len().await)
            .min(bob.roster_len().await);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("lowest roster during the settle: {lowest}");

    // The link may have closed and formed again; what must hold is that a
    // broadcast arrives. A fresh text each time, so a late one is not mistaken
    // for it.
    let started = Instant::now();
    let mut attempt = 0_u32;
    let arrived = loop {
        attempt += 1;
        let text = format!("after the loss, try {attempt}");
        alice.broadcast(&text).await;
        let tried = Instant::now();
        let mut seen = false;
        while tried.elapsed() < Duration::from_secs(5) {
            if bob.saw(&text) {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if seen {
            break true;
        }
        if started.elapsed() >= RECOVERY_DEADLINE {
            break false;
        }
    };

    assert!(
        arrived,
        "no broadcast reached bob within {RECOVERY_DEADLINE:?} of the IP loss; \
         the roster of alice is {} and bob's is {}",
        alice.roster_len().await,
        bob.roster_len().await
    );

    for member in [alice, bob] {
        let _ = member.membership.node.leave().await;
    }
}
