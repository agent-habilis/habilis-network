//! Load driver for the memory and mesh measurements. One process is one node.
//!
//! The creator (no argument) also hosts a local plain-HTTP relay, so no run
//! touches a public relay, the DHT or mDNS. A joiner takes the mesh id as its
//! only argument. `scripts/perf/` starts the nodes and reads the output.
//!
//! Env, all optional:
//!
//! - `MESH_TRANSPORT=udp|webrtc` (default `udp`): the one transport of the mesh,
//!   with multihop added to `udp` unless `MESH_MULTIHOP=off`.
//! - `MESH_TRANSPORTS=udp,webrtc,multihop,relay`: the whole list, in place of the
//!   two variables above. Only the creator reads it: a joiner inherits the list.
//! - `MESH_TRAFFIC=off`: no directed messages, gossip only. With traffic on, every
//!   node sends one directed message per second to every roster peer, which is one
//!   unicast connection per peer, the worst case.
//! - `MESH_MAX_PEERS` (G) and `MESH_MAX_SESSIONS` (D): the caps. `0`, or unset,
//!   takes the engine default.
//! - `MESH_TRAFFIC_UNTIL_SECS=180`: the directed messages stop after that many seconds.
//!   With `MESH_BLOCK_UDP_AFTER_SECS` and `MESH_TRANSPORTS=udp,webrtc,multihop` this is
//!   the run of the idle detach: sessions to members that are not neighbors must go.
//! - `MESH_TRAFFIC_BURSTY=1`: instead of a message per second to every peer, every 60 to 240 s
//!   (random) one message to each of 3 to 5 random peers.
//! - `MESH_BLOCK_UDP_AFTER_SECS=60`: after that many seconds the node takes IP away
//!   from every connection of the process, once. This is the second phase of the
//!   underlay measurement: the app endpoint and the underlay fall back to `WebRTC`.
//! - `MESH_UNDERLAY_LEG=off`: the multihop underlay holds no `WebRTC` leg. This is
//!   the control cell of the same measurement.
//!
//! Prints one line per second:
//! `t <s> phase <1|2> peers <roster> links <gossip neighbors> sessions <app WebRTC
//! sessions> underlay <underlay WebRTC sessions> rss_mb <current resident memory>
//! idle_sessions <app WebRTC sessions to members that are not neighbors> qclose <closes of
//! plain QUIC connections> qredial <of them followed by a connection to the same peer within
//! 300 s> sclose <closes of WebRTC sessions> sredial <of them followed by one within 300 s>`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use habilis_network::embed::SilentSink;
use habilis_network::membership::{
    INBOUND_CAP, MembershipApp, Opts, Request, msg_body, resolve_kind,
};
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{Lookup, Nickname, Transport};
use habilis_network::runtime::{Node, SetupParams, setup_mesh};
use habilis_network::util::resident_memory::current_resident_memory_mb;
use tokio::sync::{mpsc, oneshot};

/// A number from the environment, `0` when it is unset or not a number.
fn env_number(name: &str) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// The transport list of the mesh the creator mints.
fn transports() -> anyhow::Result<Vec<Transport>> {
    if let Ok(list) = std::env::var("MESH_TRANSPORTS") {
        return list
            .split(',')
            .filter(|name| !name.is_empty())
            .map(|name| {
                serde_json::from_str::<Transport>(&format!("\"{}\"", name.trim()))
                    .map_err(|_| anyhow::anyhow!("unknown transport {name:?} in MESH_TRANSPORTS"))
            })
            .collect();
    }
    let multihop = std::env::var("MESH_MULTIHOP").as_deref() != Ok("off");
    match std::env::var("MESH_TRANSPORT").as_deref() {
        Ok("webrtc") => Ok(vec![Transport::WebRtc]),
        Ok("udp" | "") | Err(_) if multihop => Ok(vec![Transport::Udp, Transport::Multihop]),
        Ok("udp" | "") | Err(_) => Ok(vec![Transport::Udp]),
        Ok(other) => anyhow::bail!("unknown MESH_TRANSPORT {other:?}"),
    }
}

/// The answer of a request that is a count, `0` when the node is gone.
async fn count(
    sender: &mpsc::Sender<Request>,
    request: impl FnOnce(oneshot::Sender<usize>) -> Request,
) -> usize {
    let (reply, answer) = oneshot::channel();
    if sender.send(request(reply)).await.is_ok() {
        answer.await.unwrap_or(0)
    } else {
        0
    }
}

/// The nicknames of the roster, and how many of them are gossip neighbors.
async fn roster(sender: &mpsc::Sender<Request>) -> Option<(Vec<String>, usize)> {
    let (reply, answer) = oneshot::channel();
    sender.send(Request::Peers { reply }).await.ok()?;
    let roster: serde_json::Value = serde_json::from_str(&answer.await.ok()?).unwrap_or_default();
    let peers = roster["peers"].as_array().cloned().unwrap_or_default();
    let links = peers
        .iter()
        .filter(|peer| peer["reach"].as_str() == Some("direct"))
        .count();
    let nicks = peers
        .iter()
        .filter_map(|peer| peer["nickname"].as_str().map(str::to_owned))
        .collect();
    Some((nicks, links))
}

/// One directed message to each of `nicks`.
async fn send_to<'a>(
    sender: &mpsc::Sender<Request>,
    nicks: impl IntoIterator<Item = &'a String>,
) -> anyhow::Result<()> {
    for nick in nicks {
        let (reply, _) = oneshot::channel();
        let _ = sender
            .send(Request::Send {
                to: Nickname::new(nick.clone()).ok(),
                body: msg_body("load")?,
                reply,
            })
            .await;
    }
    Ok(())
}

/// The traffic of this second. Steady: one message to every roster peer. Bursty: every 60 to
/// 240 s, at random, one message to each of 3 to 5 random peers, so a connection is idle for
/// a while, and then needed again.
async fn talk(
    sender: &mpsc::Sender<Request>,
    nicks: &[String],
    bursty: bool,
    elapsed: u64,
    next_burst: &mut u64,
) -> anyhow::Result<()> {
    use rand::seq::SliceRandom;
    if !bursty {
        return send_to(sender, nicks).await;
    }
    if elapsed >= *next_burst {
        let mut rng = rand::rng();
        let wanted = rand::Rng::random_range(&mut rng, 3..=5);
        let mut targets: Vec<&String> = nicks.iter().collect();
        targets.shuffle(&mut rng);
        targets.truncate(wanted);
        send_to(sender, targets).await?;
        *next_burst = elapsed + rand::Rng::random_range(&mut rng, 60..=240);
    }
    Ok(())
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

    let traffic = std::env::var("MESH_TRAFFIC").as_deref() != Ok("off");
    let block_udp_after = Some(env_number("MESH_BLOCK_UDP_AFTER_SECS")).filter(|secs| *secs > 0);
    let traffic_until = Some(env_number("MESH_TRAFFIC_UNTIL_SECS")).filter(|secs| *secs > 0);
    let bursty = std::env::var("MESH_TRAFFIC_BURSTY").as_deref() == Ok("1");
    if std::env::var("MESH_UNDERLAY_LEG").as_deref() == Ok("off") {
        habilis_network::net::set_underlay_leg_off(true);
    }

    let mut relay_server = None;
    let opts = if let Some(id) = std::env::args().nth(1) {
        Opts {
            mesh: Some(id),
            ..Opts::default()
        }
    } else {
        let (url, server) = habilis_network::net::test_relay::spawn_plain().await?;
        relay_server = Some(server);
        Opts {
            lookup: vec![Lookup::Relay],
            transport: transports()?,
            relay_urls: vec![url.to_string()],
            ..Opts::default()
        }
    };
    let (kind, author) = resolve_kind(&opts, None)?;

    let (inbound_tx, mut inbound) = mpsc::channel(INBOUND_CAP);
    let config = setup_mesh(
        kind,
        SetupParams {
            author: author.clone(),
            max_peers: usize::try_from(env_number("MESH_MAX_PEERS")).unwrap_or(0),
            max_sessions: usize::try_from(env_number("MESH_MAX_SESSIONS")).unwrap_or(0),
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink: Arc::new(SilentSink),
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await?;

    println!("mesh    {}", config.mesh_id().as_str());
    println!("nick    {author}");

    let webrtc = config.webrtc_handle();
    let node = Node::spawn(config, MembershipApp::new(inbound_tx), None, false);
    tokio::spawn(async move { while inbound.recv().await.is_some() {} });
    let sender = node.sender();

    let started = Instant::now();
    let mut blocked = false;
    let mut next_burst = rand::Rng::random_range(&mut rand::rng(), 60..=240);
    let ticker = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let elapsed = started.elapsed().as_secs();
            if let Some(after) = block_udp_after
                && !blocked
                && elapsed >= after
            {
                blocked = true;
                let (reply, _) = oneshot::channel();
                let _ = sender
                    .send(Request::BlockUdp {
                        blocked: true,
                        reply,
                    })
                    .await;
            }
            let Some((nicks, links)) = roster(&sender).await else {
                break;
            };
            if traffic && traffic_until.is_none_or(|until| elapsed < until) {
                talk(&sender, &nicks, bursty, elapsed, &mut next_burst).await?;
            }
            let underlay = count(&sender, |reply| Request::UnderlaySessions { reply }).await;
            let idle_sessions =
                count(&sender, |reply| Request::SessionsToNonNeighbors { reply }).await;
            let (reply, answer) = oneshot::channel();
            let redials = if sender.send(Request::RedialCounts { reply }).await.is_ok() {
                answer.await.unwrap_or([0; 4])
            } else {
                [0; 4]
            };
            println!(
                "t {elapsed} phase {} peers {} links {links} sessions {} underlay {underlay} rss_mb {} idle_sessions {idle_sessions} qclose {} qredial {} sclose {} sredial {}",
                if blocked { 2 } else { 1 },
                nicks.len(),
                webrtc.session_count(),
                current_resident_memory_mb().unwrap_or(0),
                redials[0],
                redials[1],
                redials[2],
                redials[3],
            );
        }
        anyhow::Ok(())
    };
    tokio::select! {
        _ = ticker => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    node.leave().await?;
    drop(relay_server);
    Ok(())
}
