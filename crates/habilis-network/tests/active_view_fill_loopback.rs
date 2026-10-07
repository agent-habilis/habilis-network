//! The gossip active view is a target, not only a cap (G).
//!
//! A mesh of at most G + 1 members forms a full gossip mesh: every member holds a
//! link to every other. A bigger mesh forms a dense overlay in which every member
//! holds G links, and the views stay stable once they are full.
//!
//! The transport list has `relay`, so the relay may carry payload. That is the
//! case where no probe holds a graft and a `PeerInfo` is not repeated, so the
//! alive tick is what fills a view that missed a graft (`probe::fill_active_view`).
//! The count of links is read from the roster: a peer is `direct` only while the
//! member holds a live gossip link to it.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::{Duration, Instant};

use habilis_network::iroh::RelayUrl;
use habilis_network::membership::{self, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use habilis_network::util::tuning::STARVED_SECS;
use tokio::sync::mpsc::UnboundedReceiver;

/// Long enough for a mesh of ten to form and for the alive ticks to fill what the
/// first grafts missed.
const FILL_DEADLINE: Duration = Duration::from_mins(3);

/// How long the views must stay full in the stability test.
const STABLE_FOR: Duration = Duration::from_mins(5);

/// The active view cap of the stability test, smaller than the mesh.
const VIEW_CAP: usize = 4;

/// How long the churn test counts link changes, after the formation.
const CHURN_WINDOW: Duration = Duration::from_mins(5);

/// What a settled view may change: the alive tick fills one gap and the relink
/// cooldown paces the rest.
const MAX_LINK_UPS_PER_MEMBER_PER_MINUTE: f64 = 2.0;

/// The share of G that a member holds on average. Without a floor, a view that nothing
/// fills passes the test above.
const MIN_MEAN_LINKS_OF_G: f64 = 0.9;

struct Member {
    membership: Membership,
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

    async fn create(nick: &str, relay: &RelayUrl, max_peers: usize) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            lookup: vec![Lookup::Relay],
            transport: vec![
                Transport::Udp,
                Transport::WebRtc,
                Transport::Multihop,
                Transport::Relay,
            ],
            relay_urls: vec![relay.to_string()],
            max_peers,
            ..membership::Opts::default()
        })
        .await
    }

    async fn join(nick: &str, creator: &Self, max_peers: usize) -> Self {
        Self::open(&membership::Opts {
            nick: Some(nick.to_owned()),
            mesh: Some(creator.membership.node.mesh_id().to_string()),
            max_peers,
            ..membership::Opts::default()
        })
        .await
    }

    /// The nicknames of the peers this member holds a live gossip link to.
    async fn linked_set(&self) -> std::collections::BTreeSet<String> {
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        let roster: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        roster["peers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|peer| peer["reach"].as_str() == Some("direct"))
            .filter_map(|peer| peer["nickname"].as_str().map(str::to_owned))
            .collect()
    }

    /// How many peers the roster holds, and how many of them are linked now.
    async fn counts(&self) -> (usize, usize) {
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        let roster: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        let peers = roster["peers"].as_array().cloned().unwrap_or_default();
        let linked = peers
            .iter()
            .filter(|peer| peer["reach"].as_str() == Some("direct"))
            .count();
        (peers.len(), linked)
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

/// `count` members on a local relay, each with the active view cap `max_peers`.
async fn mesh(count: usize, max_peers: usize) -> (Vec<Member>, tokio::task::JoinHandle<()>) {
    let (relay, server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let keep = tokio::spawn(async move {
        let _server = server;
        std::future::pending::<()>().await;
    });
    let first = Member::create("m0", &relay, max_peers).await;
    let mut members = Vec::with_capacity(count);
    for index in 1..count {
        members.push(Member::join(&format!("m{index}"), &first, max_peers).await);
    }
    members.insert(0, first);
    (members, keep)
}

/// Wait until every member holds `want` links, or return the last counts read.
async fn until_every_view_holds(
    members: &[Member],
    want: usize,
    deadline: Duration,
) -> Result<(), Vec<(usize, usize)>> {
    let started = Instant::now();
    loop {
        let mut counts = Vec::with_capacity(members.len());
        for member in members {
            counts.push(member.counts().await);
        }
        if counts.iter().all(|(_, linked)| *linked == want) {
            return Ok(());
        }
        eprintln!(
            "{:>4} s: links per member {:?}",
            started.elapsed().as_secs(),
            counts.iter().map(|(_, linked)| *linked).collect::<Vec<_>>()
        );
        if started.elapsed() >= deadline {
            return Err(counts);
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mesh_of_ten_links_every_member_to_every_other() {
    init_logging();
    let (members, keep) = mesh(10, 32).await;

    let result = until_every_view_holds(&members, 9, FILL_DEADLINE).await;
    assert!(
        result.is_ok(),
        "every member must hold 9 links; (roster, linked) per member: {:?}",
        result.unwrap_err()
    );

    for member in members {
        let _ = member.membership.node.leave().await;
    }
    keep.abort();
}

/// Twelve members with G = 4. A graft is a join, and a full view cannot refuse a
/// join, so every graft evicts a neighbor and the views must not be pushed around by
/// grafts nobody needs. After the views settle, the links may change at most twice per
/// member per minute. The links are sampled every five seconds, so a flap shorter than
/// that is not counted: the figure is a floor of the real churn.
///
/// A frozen overlay has no churn either, so the views must also stay filled: the mean
/// number of links per member is at least 90 percent of G, and every member holds at
/// least G - 1 links in at least half of the samples. A member that every other member
/// refuses gets a link only from the fallback of a starved node (`STARVED_SECS`), so the
/// window starts after two of them.
/// Takes eighteen minutes, so it only runs when asked for: `-- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "eighteen minutes: the views are sampled"]
async fn a_mesh_of_twelve_with_g_four_has_a_bounded_churn_after_formation() {
    init_logging();
    let (members, keep) = mesh(12, VIEW_CAP).await;

    let started = Instant::now();
    let settle = FILL_DEADLINE + Duration::from_secs(2 * STARVED_SECS);
    let mut link_ups = 0_u32;
    let mut link_total = 0_u32;
    let mut link_samples = 0_u32;
    let mut near_target = vec![0_u32; members.len()];
    let mut previous: Vec<std::collections::BTreeSet<String>> = Vec::new();
    while started.elapsed() < settle + CHURN_WINDOW {
        let mut now = Vec::with_capacity(members.len());
        for (index, member) in members.iter().enumerate() {
            let links = member.linked_set().await;
            if let Some(before) = previous.get(index) {
                link_ups += u32::try_from(links.difference(before).count()).unwrap_or(u32::MAX);
            }
            if started.elapsed() >= settle {
                link_total += u32::try_from(links.len()).unwrap_or(u32::MAX);
                link_samples += 1;
                near_target[index] += u32::from(links.len() + 1 >= VIEW_CAP);
            }
            now.push(links);
        }
        // Only the window after the settling counts.
        if started.elapsed() >= settle {
            previous = now;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let minutes = CHURN_WINDOW.as_secs_f64() / 60.0;
    let per_member_per_minute =
        f64::from(link_ups) / f64::from(u32::try_from(members.len()).unwrap_or(1)) / minutes;
    let samples_per_member = link_samples / u32::try_from(members.len()).unwrap_or(1);
    let mean_links = f64::from(link_total) / f64::from(link_samples.max(1));
    let view_cap = f64::from(u32::try_from(VIEW_CAP).unwrap_or(0));
    eprintln!(
        "link ups in {minutes} min: {link_ups}, {per_member_per_minute:.1} per member per min; \
         mean links per member {mean_links:.2} of {VIEW_CAP}"
    );
    eprintln!("samples at G - 1 or more, per member: {near_target:?} of {samples_per_member}");
    assert!(
        near_target
            .iter()
            .all(|count| count * 2 >= samples_per_member),
        "a member held fewer than G - 1 links in more than half of the samples: \
         {near_target:?} of {samples_per_member}"
    );
    assert!(
        mean_links >= MIN_MEAN_LINKS_OF_G * view_cap,
        "a frozen overlay: {mean_links:.2} links per member on average, at least \
         {MIN_MEAN_LINKS_OF_G} of {VIEW_CAP} wanted"
    );
    assert!(
        per_member_per_minute <= MAX_LINK_UPS_PER_MEMBER_PER_MINUTE,
        "{per_member_per_minute:.1} link ups per member per minute after the formation, \
         at most {MAX_LINK_UPS_PER_MEMBER_PER_MINUTE} allowed"
    );

    for member in members {
        let _ = member.membership.node.leave().await;
    }
    keep.abort();
}

/// Eight members with G = 4. The overlay is a hot potato: a graft at a full peer
/// evicts one of its links, so the views move. What is claimed is what can hold:
/// every member reaches G at least once, and the fraction of samples at G and the
/// rate of link changes are printed as numbers, with a floor on the first only.
/// Takes five minutes, so it only runs when asked for: `-- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "five minutes: the views are sampled"]
async fn a_mesh_larger_than_g_plus_one_reaches_g_everywhere_and_the_churn_is_reported() {
    init_logging();
    let (members, keep) = mesh(8, VIEW_CAP).await;

    let mut reached = vec![false; members.len()];
    let mut at_cap = 0_u32;
    let mut samples = 0_u32;
    let mut changes = 0_u32;
    let mut previous: Vec<std::collections::BTreeSet<String>> = Vec::new();
    let started = Instant::now();
    let window = FILL_DEADLINE + STABLE_FOR;
    while started.elapsed() < window {
        let mut now = Vec::with_capacity(members.len());
        for (index, member) in members.iter().enumerate() {
            let links = member.linked_set().await;
            reached[index] |= links.len() == VIEW_CAP;
            // Only after the fill deadline do samples count toward the fraction.
            if started.elapsed() >= FILL_DEADLINE {
                samples += 1;
                at_cap += u32::from(links.len() == VIEW_CAP);
                if let Some(before) = previous.get(index) {
                    changes += u32::try_from(links.symmetric_difference(before).count())
                        .unwrap_or(u32::MAX);
                }
            }
            now.push(links);
        }
        if started.elapsed() >= FILL_DEADLINE {
            previous = now;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let minutes = STABLE_FOR.as_secs_f64() / 60.0;
    eprintln!(
        "reached G at least once: {reached:?}; samples at G: {at_cap} of {samples}; \
         link changes: {changes} in {minutes} min, {:.1} per member per min",
        f64::from(changes) / f64::from(u32::try_from(members.len()).unwrap_or(1)) / minutes
    );
    assert!(
        reached.iter().all(|reached| *reached),
        "every member must hold {VIEW_CAP} links at least once: {reached:?}"
    );
    assert!(
        at_cap * 2 >= samples,
        "fewer than half of the samples had a view at G: {at_cap} of {samples}"
    );

    for member in members {
        let _ = member.membership.node.leave().await;
    }
    keep.abort();
}
