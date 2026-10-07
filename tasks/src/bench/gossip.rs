//! The gossip backup-path measurement: what an open but unselected gossip path
//! costs the mesh while the pair stands on IP.
//!
//! One pair of real endpoints, A and B, with an IP path and a gossip path to each
//! other, and N-2 members that only read the flood. The flood is in memory, so the
//! numbers are the frames the transport puts on the topic and the datagrams iroh
//! sends on the gossip path, not network time.

use std::net::SocketAddr;
use std::time::Duration;

use habilis_network_iroh_gossip_transport::memory::MemoryHub;
use habilis_network_iroh_gossip_transport::{
    GOSSIP_TRANSPORT_ID, GossipHandle, Stats, gossip_addr,
};
use habilis_network_iroh_multihop_transport::underlay_path_selector;
use habilis_network_iroh_webrtc_transport::bench::{BENCH_ALPN, Bench};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Connection, presets};
use habilis_network_iroh_webrtc_transport::iroh::protocol::Router;
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
};
use serde_json::{Value, json};

use super::Args;
use super::native::{rounds_on, selected_path};
use super::run::{Measured, Outcome, Sample};

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
    let _router = Router::builder(bob.clone())
        .accept(BENCH_ALPN, Bench)
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

    let lost_before = connection.stats().lost_packets;
    let samples = rounds_on(&connection, args, selected_path).await?;
    let bulk_after = all(&handles);
    let lost_after = connection.stats().lost_packets;
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
            "connection_lost_packets": lost_after.saturating_sub(lost_before),
            "selected_path_after": selected_path(&connection),
        },
    });
    connection.close(0u32.into(), b"done");
    Ok((report, samples))
}

#[cfg(test)]
mod tests {
    use super::{Args, Outcome, ladder_gossip_backup};
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
    }
}
