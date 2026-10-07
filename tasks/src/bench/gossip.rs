//! The gossip backup-path measurement: what an open but unselected gossip path
//! costs the mesh while the pair stands on IP.
//!
//! One pair of real endpoints, A and B, with an IP path and a gossip path to each
//! other, and N-2 members that only read the flood. The flood is in memory, so the
//! numbers are the frames the transport puts on the topic and the datagrams iroh
//! sends on the gossip path, not network time.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use habilis_network_iroh_gossip_transport::iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use habilis_network_iroh_gossip_transport::iroh_gossip::proto::TopicId;
use habilis_network_iroh_gossip_transport::memory::MemoryHub;
use habilis_network_iroh_gossip_transport::{
    GOSSIP_TRANSPORT_ID, GossipHandle, ReceiveLoop, Stats, gossip_addr, spawn_receive_loop,
};
use habilis_network_iroh_multihop_transport::underlay_path_selector;
use habilis_network_iroh_webrtc_transport::bench::{BENCH_ALPN, Bench, rtt_samples};
use habilis_network_iroh_webrtc_transport::iroh::address_lookup::memory::MemoryLookup;
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Connection, presets};
use habilis_network_iroh_webrtc_transport::iroh::protocol::{AcceptError, ProtocolHandler, Router};
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
};
use serde_json::{Value, json};

use super::Args;
use super::native::{RTT_ROUNDS, RTT_WARMUP, rounds_on, selected_path};
use super::run::{Measured, Outcome, Rtt, Sample, TRANSFER_TIMEOUT};

/// Group sizes of a real run, and the time one group idles. A test uses one small
/// group and a short idle: the idle is the wait, not the work.
fn group_sizes() -> &'static [usize] {
    if cfg!(test) { &[4] } else { &[8, 32] }
}

fn idle() -> Duration {
    if cfg!(test) {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(30)
    }
}

/// Time for the connection and its paths to settle before the idle window starts.
fn settle() -> Duration {
    if cfg!(test) {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(3)
    }
}

/// One pair with the gossip path open under IP, against the same pair with no
/// gossip address, for each group size.
pub(crate) async fn ladder_gossip_backup(args: &Args) -> Outcome {
    let run = async {
        let mut groups = Vec::new();
        let mut first_samples = None;
        for &members in group_sizes() {
            let (with_path, samples) = Box::pin(run_group(members, true, args)).await?;
            let (control, _) = Box::pin(run_group(members, false, args)).await?;
            first_samples.get_or_insert(samples);
            groups.push(json!({
                "members": members,
                "with_gossip_path": with_path,
                "ip_only_control": control,
            }));
        }
        let samples = first_samples.ok_or("no group ran")?;
        let mut measured = Measured::from_samples(0.0, samples)?;
        measured.extra = Some(json!({ "groups": groups }));
        Ok(measured)
    };
    run.await.into()
}

/// The bulk server, keeping a handle to the connection it serves so that the
/// measurement can read the server's side of the inner QUIC statistics.
#[derive(Debug, Clone)]
struct Tap {
    inner: Bench,
    served: Arc<Mutex<Option<Connection>>>,
}

impl ProtocolHandler for Tap {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        *self
            .served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(connection.clone());
        self.inner.accept(connection).await
    }
}

impl Tap {
    /// Packets that the server's side of the connection counts as lost.
    fn lost_packets(&self) -> u64 {
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, |connection| connection.stats().lost_packets)
    }
}

/// The ladder's gossip cell: a QUIC connection from A to C, which have no IP path
/// to each other, carried by the real gossip flood through B. Throughput and round
/// trips on the selected path, and what the flood costs each member.
pub(crate) async fn ladder_gossip(args: &Args) -> Outcome {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        return Outcome::Skipped(
            "the IPv6 loopback cannot be bound: A and C need it to have no IP path to each other"
                .to_owned(),
        );
    }
    Box::pin(three_member_flood(args)).await.into()
}

/// A, B and C on one gossip topic over IP, where A has `IPv6` loopback only and C
/// `IPv4` only, so they cannot send each other an IP packet. A dials C with the gossip
/// address alone: every packet of the connection is a frame that B reads and passes on.
/// The three members, their endpoints, the topic and the receive loops.
struct Flood {
    handles: Vec<GossipHandle>,
    endpoints: Vec<Endpoint>,
    /// C's bulk server, keeping its connection for the server-side statistics.
    tap: Tap,
    /// Kept alive for the whole run.
    routers: Vec<Router>,
    readers: Vec<ReceiveLoop>,
}

/// Bind the three endpoints, join the topic and attach every handle to it.
async fn start_flood() -> Result<Flood, String> {
    let topic = TopicId::from_bytes([42u8; 32]);
    let keys: Vec<SecretKey> = (0..3).map(|_| SecretKey::generate()).collect();
    let handles: Vec<GossipHandle> = keys
        .iter()
        .map(|key| GossipHandle::new(key.public()))
        .collect();
    let lookups = [
        MemoryLookup::new(),
        MemoryLookup::new(),
        MemoryLookup::new(),
    ];
    let mut endpoints = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let binds: &[&str] = match index {
            0 => &["[::1]:0"],
            1 => &["127.0.0.1:0", "[::1]:0"],
            _ => &["127.0.0.1:0"],
        };
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .add_custom_transport(handles[index].custom_transport())
            .path_selector(underlay_path_selector(key.public()))
            .address_lookup(lookups[index].clone());
        for bind in binds {
            builder = builder
                .bind_addr(
                    bind.parse::<SocketAddr>()
                        .expect("a literal loopback address"),
                )
                .map_err(|error| format!("bind address refused: {error:#}"))?;
        }
        endpoints.push(
            builder
                .bind()
                .await
                .map_err(|error| format!("bind failed: {error:#}"))?,
        );
    }
    // The gossip links: A and C each know B, and B knows both.
    lookups[0].add_endpoint_info(endpoints[1].addr());
    lookups[2].add_endpoint_info(endpoints[1].addr());
    lookups[1].add_endpoint_info(endpoints[0].addr());
    lookups[1].add_endpoint_info(endpoints[2].addr());

    let tap = Tap {
        inner: Bench,
        served: Arc::default(),
    };
    let mut gossips = Vec::new();
    let mut routers = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let mut router = Router::builder(endpoint.clone()).accept(GOSSIP_ALPN, gossip.clone());
        if index == 2 {
            router = router.accept(BENCH_ALPN, tap.clone());
        }
        routers.push(router.spawn());
        gossips.push(gossip);
    }
    // B joins first: A and C bootstrap on it, and wait for it to be there.
    let mut readers = Vec::new();
    for index in [1usize, 0, 2] {
        let joined = if index == 1 {
            gossips[1].subscribe(topic, vec![]).await
        } else {
            tokio::time::timeout(
                Duration::from_secs(20),
                gossips[index].subscribe_and_join(topic, vec![endpoints[1].id()]),
            )
            .await
            .map_err(|_| "joining the topic timed out".to_owned())?
        };
        let (sender, receiver) = joined
            .map_err(|error| format!("joining the topic failed: {error:#}"))?
            .split();
        handles[index].attach_gossip(sender);
        readers.push(spawn_receive_loop(receiver, handles[index].clone()));
    }
    Ok(Flood {
        handles,
        endpoints,
        tap,
        routers,
        readers,
    })
}

async fn three_member_flood(args: &Args) -> Result<Measured, String> {
    let Flood {
        handles,
        endpoints,
        tap,
        routers: _routers,
        readers,
    } = start_flood().await?;
    let to_carol = EndpointAddr::from_parts(
        endpoints[2].id(),
        [TransportAddr::Custom(gossip_addr(endpoints[2].id()))],
    );
    let connection = tokio::time::timeout(
        Duration::from_secs(30),
        endpoints[0].connect(to_carol, BENCH_ALPN),
    )
    .await
    .map_err(|_| "connecting over gossip timed out".to_owned())?
    .map_err(|error| format!("connect over gossip failed: {error:#}"))?;

    let all =
        |list: &[GossipHandle]| -> Vec<Stats> { list.iter().map(GossipHandle::stats).collect() };
    let before = all(&handles);
    let client_lost_before = connection.stats().lost_packets;
    let server_lost_before = tap.lost_packets();
    let samples = rounds_on(&connection, args, selected_path).await?;
    let round_trips = tokio::time::timeout(
        TRANSFER_TIMEOUT,
        rtt_samples(&connection, RTT_WARMUP, RTT_ROUNDS),
    )
    .await
    .map_err(|_| format!("the round trips stalled past {TRANSFER_TIMEOUT:?}"))?
    .map_err(|error| format!("round trips failed: {error:#}"))?;
    let after = all(&handles);
    let lost_packets_a = connection
        .stats()
        .lost_packets
        .saturating_sub(client_lost_before);
    let lost_packets_c = tap.lost_packets().saturating_sub(server_lost_before);
    connection.close(0u32.into(), b"done");
    for reader in readers {
        reader.abort();
    }

    let originated = sum_frames_out(&after) - sum_frames_out(&before);
    let received: u64 = after
        .iter()
        .zip(&before)
        .map(|(now, then)| now.frames_in - then.frames_in)
        .sum();
    let member = |index: usize| {
        let (then, now) = (before[index], after[index]);
        json!({
            "frames_out": now.frames_out - then.frames_out,
            "bytes_out": now.bytes_out - then.bytes_out,
            "frames_in": now.frames_in - then.frames_in,
            "bytes_in": now.bytes_in - then.bytes_in,
            "queued": now.queued - then.queued,
            "not_for_us": now.not_for_us - then.not_for_us,
            // Where a frame can be lost: this member's sink queue refusing it, the
            // inbound queue to iroh, an oversized packet, and the topic's own queue.
            "dropped_sink_refused": now.dropped_sink_refused - then.dropped_sink_refused,
            "queue_full": now.queue_full - then.queue_full,
            "dropped_oversized_in": now.dropped_oversized_in - then.dropped_oversized_in,
            "topic_lagged": now.topic_lagged - then.topic_lagged,
        })
    };
    let mut measured = Measured::from_samples(0.0, samples)?;
    measured.rtt = Rtt::from_samples(&round_trips);
    measured.extra = Some(json!({
        "members": { "a": member(0), "b": member(1), "c": member(2) },
        "frames_originated": originated,
        "frames_received": received,
        "flood_amplification": float(received) / float(originated.max(1)),
        "lost_packets_a": lost_packets_a,
        "lost_packets_c": lost_packets_c,
    }));
    Ok(measured)
}

/// An endpoint with IP on loopback and gossip beside it, ranked IP first.
async fn endpoint(key: &SecretKey, handle: &GossipHandle) -> Result<Endpoint, String> {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("a literal loopback address");
    Endpoint::builder(presets::Minimal)
        .secret_key(key.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr(loopback)
        .map_err(|error| format!("bind address refused: {error:#}"))?
        .add_custom_transport(handle.custom_transport())
        .path_selector(underlay_path_selector(key.public()))
        .bind()
        .await
        .map_err(|error| format!("bind failed: {error:#}"))
}

/// What the gossip path of `connection` has carried, if it is open.
fn gossip_path(connection: &Connection) -> Option<(u64, u64, u64)> {
    connection
        .paths()
        .iter()
        .find(|path| {
            matches!(path.remote_addr(), TransportAddr::Custom(addr) if addr.id() == GOSSIP_TRANSPORT_ID)
        })
        .map(|path| {
            let stats = path.stats();
            (
                stats.udp_tx.datagrams,
                stats.udp_rx.datagrams,
                stats.lost_packets,
            )
        })
}

/// A count as a float. Counts of frames and bytes in a minute are far below 2^52.
#[expect(
    clippy::cast_precision_loss,
    reason = "a count in one run is below 2^52"
)]
fn float(count: u64) -> f64 {
    count as f64
}

/// Per-second rates of one member over `secs`.
fn rates(before: Stats, after: Stats, secs: f64) -> Value {
    let rate = |now: u64, then: u64| float(now.saturating_sub(then)) / secs;
    json!({
        "frames_out_per_s": rate(after.frames_out, before.frames_out),
        "frames_in_per_s": rate(after.frames_in, before.frames_in),
        "bytes_in_per_s": rate(after.bytes_in, before.bytes_in),
    })
}

/// The mean of the bystanders' rates, which only read the flood.
fn bystander_mean(before: &[Stats], after: &[Stats], secs: f64) -> Value {
    let count = float(u64::try_from(before.len().max(1)).unwrap_or(1));
    let mean = |field: fn(&Stats) -> u64| {
        before
            .iter()
            .zip(after)
            .map(|(then, now)| float(field(now).saturating_sub(field(then))))
            .sum::<f64>()
            / count
            / secs
    };
    json!({
        "frames_out_per_s": mean(|stats| stats.frames_out),
        "frames_in_per_s": mean(|stats| stats.frames_in),
        "bytes_in_per_s": mean(|stats| stats.bytes_in),
    })
}

fn sum_frames_out(stats: &[Stats]) -> u64 {
    stats.iter().map(|member| member.frames_out).sum()
}

/// One run: `members` handles on one flood, the first two with real endpoints and
/// an IP path between them, and the gossip address given or not.
async fn run_group(
    members: usize,
    with_gossip_path: bool,
    args: &Args,
) -> Result<(Value, Vec<Sample>), String> {
    let hub = MemoryHub::new();
    let keys: Vec<SecretKey> = (0..members).map(|_| SecretKey::generate()).collect();
    let handles: Vec<GossipHandle> = keys
        .iter()
        .map(|key| GossipHandle::new(key.public()))
        .collect();
    for handle in &handles {
        hub.join(handle);
    }
    let alice = endpoint(&keys[0], &handles[0]).await?;
    let bob = endpoint(&keys[1], &handles[1]).await?;
    let tap = Tap {
        inner: Bench,
        served: Arc::default(),
    };
    let _router = Router::builder(bob.clone())
        .accept(BENCH_ALPN, tap.clone())
        .spawn();
    let socket = bob
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or("bob bound no IPv4 socket")?;
    let mut addrs = vec![TransportAddr::Ip(socket)];
    if with_gossip_path {
        addrs.push(TransportAddr::Custom(gossip_addr(bob.id())));
    }
    let connection = alice
        .connect(EndpointAddr::from_parts(bob.id(), addrs), BENCH_ALPN)
        .await
        .map_err(|error| format!("connect failed: {error:#}"))?;
    tokio::time::sleep(settle()).await;

    let all =
        |list: &[GossipHandle]| -> Vec<Stats> { list.iter().map(GossipHandle::stats).collect() };
    let (idle_before, path_before) = (all(&handles), gossip_path(&connection));
    tokio::time::sleep(idle()).await;
    let (idle_after, path_after) = (all(&handles), gossip_path(&connection));
    let secs = idle().as_secs_f64();
    let selected_idle = selected_path(&connection);

    let client_lost_before = connection.stats().lost_packets;
    let server_lost_before = tap.lost_packets();
    let samples = rounds_on(&connection, args, selected_path).await?;
    let bulk_after = all(&handles);
    let client_lost = connection
        .stats()
        .lost_packets
        .saturating_sub(client_lost_before);
    let server_lost = tap.lost_packets().saturating_sub(server_lost_before);
    let bulk_bytes: usize = samples.iter().skip(1).map(|sample| sample.bytes).sum();

    let report = json!({
        "selected_path": selected_idle,
        "gossip_path_open": path_after.is_some(),
        "idle_secs": secs,
        "gossip_path_idle": path_before.zip(path_after).map(|(then, now)| json!({
            "tx_datagrams": now.0.saturating_sub(then.0),
            "rx_datagrams": now.1.saturating_sub(then.1),
            "lost_packets": now.2.saturating_sub(then.2),
        })),
        "flood_frames_idle": sum_frames_out(&idle_after) - sum_frames_out(&idle_before),
        "idle": {
            "a": rates(idle_before[0], idle_after[0], secs),
            "b": rates(idle_before[1], idle_after[1], secs),
            "bystander_mean": bystander_mean(&idle_before[2..], &idle_after[2..], secs),
        },
        "bulk": {
            "bytes_timed_rounds": bulk_bytes,
            "flood_frames": sum_frames_out(&bulk_after) - sum_frames_out(&idle_after),
            "lost_packets_a": client_lost,
            "lost_packets_b": server_lost,
            "selected_path_after": selected_path(&connection),
        },
    });
    connection.close(0u32.into(), b"done");
    Ok((report, samples))
}

#[cfg(test)]
mod tests {
    use super::{Args, Outcome, ladder_gossip, ladder_gossip_backup};
    use crate::bench::Direction;

    fn small_args() -> Args {
        Args {
            only: None,
            bytes: 64 * 1024,
            rounds: 2,
            direction: Direction::Down,
            list: false,
            json: None,
        }
    }

    /// The cell keeps IP selected, reports the flood of both runs, and the run with
    /// no gossip address puts nothing on the topic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_backup_path_cell_reports_the_flood_under_ip_and_a_control_with_none() {
        let Outcome::Ok(measured) = ladder_gossip_backup(&small_args()).await else {
            panic!("the backup-path cell did not measure");
        };

        assert_eq!(measured.path, "ip", "IP is the selected path");
        let extra = measured.extra.expect("the flood numbers");
        let group = &extra["groups"][0];
        assert_eq!(group["members"], 4);
        let with_path = &group["with_gossip_path"];
        let control = &group["ip_only_control"];
        assert_eq!(with_path["selected_path"], "ip");
        assert_eq!(control["selected_path"], "ip");
        assert_eq!(control["gossip_path_open"], false);
        assert_eq!(control["flood_frames_idle"], 0);
        assert!(with_path["flood_frames_idle"].is_u64(), "{with_path}");
        assert!(with_path["idle"]["bystander_mean"]["frames_in_per_s"].is_f64());
        // Both ends of the inner connection report their lost packets in the bulk.
        assert!(with_path["bulk"]["lost_packets_a"].is_u64(), "{with_path}");
        assert!(with_path["bulk"]["lost_packets_b"].is_u64(), "{with_path}");
    }

    /// The gossip cell: a transfer and the round trips over the real flood, on the
    /// gossip path, and the cost of the flood at the member between the two ends.
    /// Skipped, with a log line, where the `IPv6` loopback cannot bind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_gossip_cell_measures_a_quic_transfer_over_the_real_flood() {
        let measured = match ladder_gossip(&small_args()).await {
            Outcome::Ok(measured) => measured,
            Outcome::Skipped(reason) => {
                eprintln!("SKIPPED: {reason}");
                return;
            }
            Outcome::Failed(reason) => panic!("the gossip cell failed: {reason}"),
        };

        assert_eq!(measured.path, "gossip", "the selected path");
        assert!(measured.rtt.is_some(), "round trips over gossip");
        let extra = measured.extra.expect("the flood numbers");
        assert!(
            extra["members"]["b"]["frames_in"].as_u64().unwrap_or(0) > 0,
            "the member between the ends read the flood: {extra}"
        );
        assert!(extra["flood_amplification"].is_f64(), "{extra}");
        // Where a frame can be lost: the sink queue, and the topic's own queue.
        for member in ["a", "b", "c"] {
            let counts = &extra["members"][member];
            assert!(
                counts["dropped_sink_refused"].is_u64(),
                "{member}: {counts}"
            );
            assert!(counts["topic_lagged"].is_u64(), "{member}: {counts}");
        }
        assert!(extra["lost_packets_a"].is_u64() && extra["lost_packets_c"].is_u64());
    }
}
