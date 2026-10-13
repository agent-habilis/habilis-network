//! A node that holds enough links to other members lets go of the rendezvous,
//! and the mesh keeps working without it: a late joiner still finds the mesh,
//! the beacon is still replaced when its holder goes, and a link that falls
//! back to the relay is closed, then comes back with the heal.
//!
//! Real members on UDP over a local relay. The cells share one process-wide
//! log buffer, so they run one at a time.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use habilis_network::iroh::{EndpointId, RelayUrl};
use habilis_network::membership::{self, Inbound, Membership, Request};
use habilis_network::protocol::{Lookup, Transport};
use tokio::sync::mpsc::UnboundedReceiver;

/// Members of the first group: the creator, who hosts the rendezvous, and five
/// joiners. Each joiner ends with five links, above the release count of three.
const GROUP: usize = 6;

fn serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn log_buffer() -> &'static Mutex<String> {
    static BUFFER: OnceLock<Mutex<String>> = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(String::new()))
}

struct BufferWriter;

impl std::io::Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        log_buffer()
            .lock()
            .expect("no poison")
            .push_str(&String::from_utf8_lossy(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            "habilis_network=info,habilis_network::transport=debug,habilis_network::gossip=info,\
             habilis_ladder=trace",
        )
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| BufferWriter)
        .with_ansi(false)
        .try_init();
    log_buffer().lock().expect("no poison").clear();
}

fn logs() -> String {
    log_buffer().lock().expect("no poison").clone()
}

fn count(needle: &str) -> usize {
    logs().matches(needle).count()
}

/// The log from line `since` on. A check about a step of the test reads only what the step wrote:
/// the whole buffer holds lines from the start of the test, and from members the step did not touch.
/// A line count, not a byte offset: a count cannot fall inside a character.
fn logs_since(since: usize) -> String {
    logs().lines().skip(since).collect::<Vec<_>>().join("\n")
}

/// Whether, since `since`, the ladder of `local` considered a path of the member that bound
/// `remote_ports` (an IP path with one of these ports is in the list the ladder saw) and chose
/// something that is not an IP path: nothing, or a relay path. The port names the remote, as it does
/// in the block itself; the line carries no span of the remote, because the test's log filter drops the
/// spans of iroh.
fn left_ip(since: usize, local: &EndpointId, remote_ports: &[u16]) -> bool {
    let local = local.fmt_short().to_string();
    logs_since(since).lines().any(|line| {
        line.contains("habilis_ladder: path selection")
            && line.contains(&format!("local={local} "))
            && sees_port(line, remote_ports)
            && !line.contains("chosen=Some(Ip(")
    })
}

/// Whether the ladder line lists an IP path with one of `ports`.
fn sees_port(line: &str, ports: &[u16]) -> bool {
    ports
        .iter()
        .any(|port| line.contains(&format!(":{port}) rtt=")))
}

/// The last ladder lines of `local` that list a path with one of `remote_ports`, since `since`, for
/// the text of a failure: they say whether the cut left no candidate or the IP path was still chosen.
fn ladder_lines(since: usize, local: &EndpointId, remote_ports: &[u16]) -> String {
    let local = local.fmt_short().to_string();
    let lines: Vec<String> = logs_since(since)
        .lines()
        .filter(|line| {
            line.contains("habilis_ladder: path selection")
                && line.contains(&format!("local={local} "))
                && sees_port(line, remote_ports)
        })
        .map(str::to_owned)
        .collect();
    lines[lines.len().saturating_sub(3)..].join("\n")
}

/// Whether, since `since`, the link between `one` and `two` was closed for staying on the relay path
/// past its deadline, and reported down by one of the two. Both ids name the pair: a close of a link
/// of any other member, the rendezvous host included, does not count.
fn pair_link_closed(since: usize, one: &EndpointId, two: &EndpointId) -> bool {
    let log = logs_since(since);
    let closed = log.lines().any(|line| {
        line.contains("gossip link on the relay path past the deadline: closing it")
            && (line.contains(&format!("remote={one} "))
                || line.contains(&format!("remote={two} ")))
    });
    let down = log.lines().any(|line| {
        line.contains("gossip neighbor down")
            && ((line.contains(&format!("local={} ", one.fmt_short()))
                && line.contains(&format!("endpoint_id={two} ")))
                || (line.contains(&format!("local={} ", two.fmt_short()))
                    && line.contains(&format!("endpoint_id={one} "))))
    });
    closed && down
}

/// How many times a member reported its link to the rendezvous down. It counts
/// events, not members: the line does not name the member, and a member that
/// comes back and leaves again counts twice. The creator hosts the rendezvous
/// and has no such link, so it never counts.
fn rendezvous_links_down() -> usize {
    logs()
        .lines()
        .filter(|line| line.contains("gossip neighbor down") && line.contains("is_rendezvous=true"))
        .count()
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
    events: UnboundedReceiver<String>,
    seen_msgs: Vec<Inbound>,
}

impl Member {
    async fn open(opts: &membership::Opts) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink).await.expect("open a member");
        Self {
            membership,
            events,
            seen_msgs: Vec::new(),
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

    fn pump(&mut self) {
        while self.events.try_recv().is_ok() {}
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(msg);
        }
    }

    fn saw_msg(&mut self, text: &str) -> bool {
        self.pump();
        self.seen_msgs.iter().any(|msg| msg.text == text)
    }

    /// Whether this member holds a live link to the member `nick`.
    async fn linked_to(&self, nick: &str) -> bool {
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(&json)
            .ok()
            .and_then(|roster| {
                roster["peers"].as_array().map(|peers| {
                    peers
                        .iter()
                        .any(|peer| peer["nickname"] == nick && peer["reach"] == "direct")
                })
            })
            .unwrap_or(false)
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

    async fn send(&self, text: &str) {
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

    /// The ports this member's endpoint is bound on.
    fn ports(&self) -> Vec<u16> {
        self.membership.node.bound_ports().to_vec()
    }

    /// Take UDP away from this member alone, to the nodes bound on `ports`.
    async fn block_ip_to(&self, ports: Vec<u16>) {
        self.membership
            .request(|reply| Request::BlockIpTo {
                remote_ports: ports,
                reply,
            })
            .await
            .expect("the loop answers");
    }

    async fn block_udp(&self, blocked: bool) {
        self.membership
            .request(|reply| Request::BlockUdp { blocked, reply })
            .await
            .expect("the loop answers");
    }
}

async fn all_rosters_hold(members: &[&Member], peers: usize, deadline: Duration) -> bool {
    rosters_until(members, peers, deadline)
        .await
        .iter()
        .all(|len| *len == peers)
}

/// The roster size of every member, once all hold `peers` or the deadline ends.
async fn rosters_until(members: &[&Member], peers: usize, deadline: Duration) -> Vec<usize> {
    let started = Instant::now();
    loop {
        let mut rosters = Vec::new();
        for member in members {
            rosters.push(member.roster_len().await);
        }
        if rosters.iter().all(|len| *len == peers) || started.elapsed() >= deadline {
            return rosters;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A creator who hosts the rendezvous and five joiners, all linked, and every
/// joiner done with the rendezvous.
async fn group_that_let_go(relay: &RelayUrl) -> Vec<Member> {
    let creator = Member::create("member-0", relay).await;
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
    assert!(
        all_rosters_hold(&refs(&members), GROUP - 1, Duration::from_mins(1)).await,
        "the group never formed\n{}",
        rendezvous_trace()
    );
    assert!(
        eventually(Duration::from_mins(1), || count("released the rendezvous")
            >= GROUP - 1)
        .await,
        "not every joiner let go of the rendezvous: {} of {}\n{}",
        count("released the rendezvous"),
        GROUP - 1,
        rendezvous_trace()
    );
    // The release is a choice, and the link must end with it: the beacon keeps
    // no claim on a joiner, and the joiner reports the rendezvous link down.
    assert!(
        eventually(Duration::from_mins(1), || rendezvous_links_down()
            >= GROUP - 1)
        .await,
        "not every joiner reported the rendezvous link down: {} of {}\n{}",
        rendezvous_links_down(),
        GROUP - 1,
        rendezvous_trace()
    );
    members
}

async fn leave_all(members: Vec<Member>) {
    for member in members {
        let _ = member.membership.node.leave().await;
    }
}

/// Every joiner has let go, so the beacon's gossip view holds only the
/// creator's own link. A joiner that arrives now must still find the mesh
/// through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_joiner_finds_a_mesh_where_every_member_let_go_of_the_rendezvous() {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let mut members = group_that_let_go(&relay).await;

    let late = Member::join("late-joiner", &members[0]).await;
    members.push(late);
    let found = all_rosters_hold(&refs(&members), GROUP, Duration::from_mins(1)).await;

    let trace = rendezvous_trace();
    leave_all(members).await;
    assert!(found, "the late joiner never found the mesh\n{trace}");
}

/// Nobody but the creator holds a link to the rendezvous now, so nobody sees
/// it go. The mesh must still get a new beacon, from the heal tick of a member
/// that may host it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_beacon_holder_leaving_is_replaced_though_every_other_member_let_go_of_it() {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let mut members = group_that_let_go(&relay).await;
    let before = count("beacon role active");

    let holder = members.remove(0);
    let _ = holder.membership.node.leave().await;
    let replaced = eventually(Duration::from_secs(45), || {
        count("beacon role active") > before
    })
    .await;

    let trace = rendezvous_trace();
    leave_all(members).await;
    assert!(replaced, "no member took the beacon over\n{trace}");
}

/// The accept gate checks the path once. A link that is later left on the
/// relay, with the relay lookup only, is closed after a minute, and
/// the heal brings it back once the direct path returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_left_on_the_relay_is_closed_and_the_heal_brings_it_back() {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let creator = Member::create("alice", &relay).await;
    assert!(
        eventually(Duration::from_mins(1), || logs()
            .contains("beacon role active"))
        .await,
        "alice never claimed the beacon"
    );
    let mut bob = Member::join("bob", &creator).await;
    let alice = creator;
    assert!(
        all_rosters_hold(&[&alice, &bob], 1, Duration::from_secs(30)).await,
        "the pair never linked"
    );
    alice.send("before the block").await;
    assert!(
        eventually(Duration::from_secs(20), || bob.saw_msg("before the block")).await,
        "no payload before the block"
    );

    alice.block_udp(true).await;
    // The relay policy waits a minute, longer than one race round, then closes.
    let closed = eventually(Duration::from_mins(2), || {
        logs().contains("gossip link on the relay path past the deadline: closing it")
    })
    .await;

    alice.block_udp(false).await;
    // The first send may find no link yet: send again on every look.
    let mut healed = false;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(90) {
        alice.send("after the heal").await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        if bob.saw_msg("after the heal") {
            healed = true;
            break;
        }
    }

    let trace = rendezvous_trace();
    let _ = alice.membership.node.leave().await;
    let _ = bob.membership.node.leave().await;
    assert!(closed, "the relay-only link was never closed\n{trace}");
    assert!(healed, "the link never came back after the block\n{trace}");
}

fn refs(members: &[Member]) -> Vec<&Member> {
    members.iter().collect()
}

/// The cut between two chosen nodes (`Request::BlockIpTo`): they lose UDP to
/// each other and to no one else. Their link falls back to the relay, which
/// carries no payload on this mesh, so it is closed after 15 seconds; the heal
/// brings it back once the cut is lifted. The process-wide block of the test
/// above takes UDP from every node, so it cannot show that the other links of
/// the two nodes are left alone.
///
/// The fall back needs the relay in the book of the pair: with none, the ladder
/// has no candidate once IP is blocked, it chooses nothing, and iroh keeps the
/// old IP path. The test first waits for the ladder of both members to choose no IP
/// path, which shows that the block took, and then for the close of their link.
/// It reads the log only from the cut on and only for the two members: the close
/// of the link of any other member, the rendezvous host included, is not the
/// cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_between_two_members_closes_their_link_and_leaves_the_others() {
    let _serial = serial().lock().await;
    init_logging();
    let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("local relay");
    let mut members = vec![Member::create("member-0", &relay).await];
    assert!(
        eventually(Duration::from_mins(1), || logs()
            .contains("beacon role active"))
        .await,
        "the creator never claimed the beacon"
    );
    for index in 1..4 {
        let member = Member::join(&format!("member-{index}"), &members[0]).await;
        members.push(member);
    }
    assert!(
        all_rosters_hold(&refs(&members), 3, Duration::from_mins(1)).await,
        "the group never formed\n{}",
        rendezvous_trace()
    );

    // The roster fills through any link, so it does not show that these two hold
    // a link to each other. A cut that lands before they do has nothing to close.
    let linking_since = Instant::now();
    while !(members[1].linked_to("member-2").await && members[2].linked_to("member-1").await) {
        assert!(
            linking_since.elapsed() < Duration::from_mins(1),
            "member-1 and member-2 never linked to each other before the cut\n{}",
            rendezvous_trace()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Cut member-1 from member-2, and nobody else. Every check about the cut reads the log from here.
    let (one_id, two_id) = (
        members[1].membership.node.endpoint_id(),
        members[2].membership.node.endpoint_id(),
    );
    let (one, two) = (members[1].ports(), members[2].ports());
    let cut_at = logs().lines().count();
    members[1].block_ip_to(two.clone()).await;
    members[2].block_ip_to(one.clone()).await;
    // The cut took when the ladder of each member, with the other's IP path in view, chooses no IP
    // path. That is the block working; it does not say that the link moved. The close below does.
    let cut_took = eventually(Duration::from_secs(30), || {
        left_ip(cut_at, &one_id, &two) && left_ip(cut_at, &two_id, &one)
    })
    .await;
    let closed = cut_took
        && eventually(Duration::from_mins(2), || {
            pair_link_closed(cut_at, &one_id, &two_id)
        })
        .await;
    // The others still talk: member-0 reaches member-3 while the cut stands.
    members[0].send("through the cut").await;
    let others = eventually(Duration::from_secs(30), || {
        members[3].saw_msg("through the cut")
    })
    .await;

    members[1].block_ip_to(Vec::new()).await;
    members[2].block_ip_to(Vec::new()).await;
    members[1].send("after the cut").await;
    let mut healed = false;
    let started = Instant::now();
    while started.elapsed() < Duration::from_mins(2) {
        members[1].send("after the cut").await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        if members[2].saw_msg("after the cut") {
            healed = true;
            break;
        }
    }

    let trace = rendezvous_trace();
    let ladder = format!(
        "member-1 about member-2:\n{}\nmember-2 about member-1:\n{}",
        ladder_lines(cut_at, &one_id, &two),
        ladder_lines(cut_at, &two_id, &one)
    );
    dump_logs();
    leave_all(members).await;
    assert!(
        cut_took,
        "the cut never took: the ladder of the pair still chose an IP path\n{ladder}\n{trace}"
    );
    assert!(closed, "the cut link was never closed\n{trace}");
    assert!(others, "the cut reached nodes it did not name\n{trace}");
    assert!(healed, "the link never came back after the cut\n{trace}");
}
