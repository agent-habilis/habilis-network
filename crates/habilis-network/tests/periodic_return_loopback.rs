//! A node that let go of the rendezvous on purpose comes back to it once in a while, though it
//! holds links enough, so that islands of a split mesh meet again there. The period is a tuning
//! override, and the override is process-wide: this case has a binary of its own.
//!
//! Real members on UDP over a local relay. The case is `#[ignore]` and `cargo task matrix` runs
//! it: it stands up four members and takes over a minute.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership};
use habilis_network::protocol::{Lookup, Transport};
use habilis_network::runtime::tuning::{Tuning, init};
use tokio::sync::mpsc::UnboundedReceiver;

/// The creator, who hosts the rendezvous, and three joiners. Each joiner ends with three links,
/// which is the release count.
const GROUP: usize = 4;

/// The period of a return. A node adds up to half of it from its id.
const PERIOD: Duration = Duration::from_secs(20);

fn logs() -> String {
    habilis_network_test_tracing::captured_logs()
}

fn count(needle: &str) -> usize {
    logs().matches(needle).count()
}

/// The lines that say how the rendezvous was held, let go of and re-grafted: the
/// last 120, because the lines that explain a failure come after the group forms.
fn rendezvous_trace() -> String {
    logs()
        .lines()
        .filter(|line| {
            [
                "released the rendezvous",
                "gossip neighbor",
                "relay-only path refused",
                "re-graft the rendezvous",
                "rendezvous released",
                "beacon role active",
                "closing it",
            ]
            .iter()
            .any(|needle| line.contains(needle))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .take(120)
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

/// The whole log, written to the file that `HABILIS_TEST_LOG_DUMP` names, if set.
fn dump_logs() {
    if let Ok(path) = std::env::var("HABILIS_TEST_LOG_DUMP") {
        let _ = std::fs::write(path, logs());
    }
}

async fn eventually(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    done()
}

struct Member {
    membership: Membership,
    /// Held so that the sink of the member never meets a closed channel.
    _events: UnboundedReceiver<String>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            _events: events,
        }
    }

    async fn create(nick: &str, relay: &RelayUrl) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
            transport: vec![Transport::Udp],
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
}

/// Every joiner lets go of the rendezvous once the group is formed, and each of them wants it
/// again a period later. The second release is the proof that the visit came, and that it ended
/// after its dwell time: a node cannot release twice without a link in between.
#[test]
#[ignore = "run by cargo task matrix"]
fn a_member_that_let_go_of_the_rendezvous_comes_back_and_lets_go_again() {
    let guard = habilis_network_test_tracing::init_capturing(
        "habilis_network=info,habilis_network::transport=debug,habilis_network::gossip=info,\
         habilis_ladder=trace",
    );
    habilis_network_test_tracing::clear_captured_logs();
    habilis_network_test_tracing::run_multi_thread(guard, 4, async {
        init(Tuning {
            rendezvous_periodic_return: PERIOD,
            ..Tuning::DEFAULTS
        });

        let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
            .await
            .expect("local relay");

        let creator = Member::create("member-0", &relay).await;
        assert!(
            eventually(Duration::from_mins(1), || logs()
                .contains("beacon role active"))
            .await,
            "the creator never claimed the beacon"
        );
        let mut members = vec![creator];
        for index in 1..GROUP {
            let member = Member::join(&format!("member-{index}"), &members[0]).await;
            members.push(member);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let joiners = GROUP - 1;
        let formed = eventually(Duration::from_mins(1), || {
            count("released the rendezvous") >= joiners
        })
        .await;
        let first = count("released the rendezvous");
        let started = Instant::now();

        // The worst case is 30 s (the period with its full share), 15 s (the heal tick that grafts),
        // 30 s (the dwell of the visit) and 15 s (the heal tick that releases), plus the link time.
        let again = eventually(Duration::from_mins(2), || {
            count("released the rendezvous") >= 2 * joiners
        })
        .await;
        let waited = started.elapsed();

        let trace = rendezvous_trace();
        dump_logs();
        for member in members {
            let _ = member.membership.node.leave().await;
        }
        assert!(
            formed,
            "not every joiner let go of the rendezvous: {first} of {joiners}\n{trace}"
        );
        assert!(
            again,
            "a joiner never came back to the rendezvous and let go again: {} releases after {waited:?}, \
         {first} after the group formed\n{trace}",
            count("released the rendezvous"),
        );
    });
}
