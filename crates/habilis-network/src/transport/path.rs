//! Whether a connection's data is on a direct path right now, and whether the
//! mesh's transport policy lets payload ride it.
//!
//! iroh keeps every path it has to a peer open and picks one to carry data;
//! the relay path is never closed, only demoted. So "is this peer relayed" is
//! a question about the *selected* path, not about which paths exist —
//! `gossip::conn_path` answers the latter, for diagnostics.

use std::time::Duration;

use futures_util::StreamExt as _;
use iroh::endpoint::Connection;

use super::LOG_TARGET;

/// How long a hold waits for iroh to select a non-relay path. Hole punching
/// starts as soon as the connection has both sides' candidates, and a first
/// round lands within seconds; a punch that has not landed by now is
/// retried later rather than waited on.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(15);

/// Close code an inbound gossip connection gets when the relay is lookup
/// only and no direct path was selected within the deadline. Distinct from
/// the blob lane's code so a log reader can tell the two refusals apart.
pub(crate) const GOSSIP_RELAY_REFUSED_CODE: u32 = super::webrtc::close_code::GOSSIP_RELAY_REFUSED;

/// Close code of a gossip connection whose selected path is the gossip rung. Such a
/// connection would carry, inside gossip frames, the gossip that the frames need.
pub(crate) const GOSSIP_RECURSION_REFUSED_CODE: u32 =
    super::webrtc::close_code::GOSSIP_ON_GOSSIP_PATH;

static GOSSIP_RECURSION_CLOSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many gossip connections the recursion rule closed since the process started: a total,
/// not a delta. A count that grows without bound is a pair that dials again after each close.
pub(crate) fn gossip_recursion_closes() -> u64 {
    GOSSIP_RECURSION_CLOSES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Close `conn` with [`GOSSIP_RECURSION_REFUSED_CODE`] once its selected path is the gossip
/// rung, now or after a path change. Unconditional: it reads no mesh policy.
pub(crate) fn watch_gossip_recursion(conn: &Connection) {
    habilis_network_iroh_gossip_transport::watch_recursion(
        conn,
        GOSSIP_RECURSION_REFUSED_CODE,
        || {
            GOSSIP_RECURSION_CLOSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(target: LOG_TARGET, "gossip connection closed: its path is the gossip rung");
        },
    );
}

/// Whether iroh's selected path to the remote is not the relay: a direct UDP
/// path, or a custom transport (`WebRTC`, multihop), which is peer to peer as
/// far as the relay is concerned. `false` while no path is selected yet.
pub(crate) fn selected_is_direct(conn: &Connection) -> bool {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .is_some_and(|path| !path.is_relay())
}

/// Whether iroh's selected path to the remote is a direct UDP path: the race
/// against `WebRTC` is won. `false` while no path is selected yet.
pub(crate) fn selected_is_ip(conn: &Connection) -> bool {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .is_some_and(|path| path.is_ip())
}

/// The rung of iroh's selected path on `conn`, for a test that shows a node
/// stepping down the ladder: `ip`, `webrtc`, `multihop` or `relay`. `None`
/// while no path is selected yet.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(crate) fn selected_rung(conn: &Connection) -> Option<&'static str> {
    use super::probe::{PathKind, selected_kind};

    match selected_kind(conn) {
        PathKind::Ip => Some("ip"),
        PathKind::WebRtc => Some("webrtc"),
        PathKind::Multihop => Some("multihop"),
        PathKind::Relay => Some("relay"),
        PathKind::None => None,
    }
}

/// Whether payload may go out on `conn` under the mesh's transport policy.
/// With the relay allowed as a transport, anything goes — decided before the
/// path snapshot, which locks and clones. With the relay lookup only, the
/// selected path must be a proven non-relay one: "not selected yet" is
/// refused, not trusted.
pub(crate) fn payload_allowed_on(conn: &Connection, relay_transport: bool) -> bool {
    relay_transport || selected_is_direct(conn)
}

/// The refusal every payload lane reports when the relay is lookup only and
/// the only path is the relay. One string, so a log reader can grep for it.
pub(crate) const RELAY_REFUSED: &str =
    "relay-only path refused: the relay is lookup only on this mesh";

/// Wait until `conn`'s selected path is not the relay, or `deadline` passes.
/// Every path event is a reason to re-read the path list: the event's own
/// address may be stale by the time it is handled.
pub async fn wait_direct(conn: &Connection, deadline: Duration) -> bool {
    wait_selected(conn, deadline, selected_is_direct).await
}

/// [`wait_direct`] for a UDP path alone: whether UDP won the race against a
/// `WebRTC` session within `deadline`.
pub(crate) async fn wait_ip(conn: &Connection, deadline: Duration) -> bool {
    wait_selected(conn, deadline, selected_is_ip).await
}

/// How a wait for a selected path ended.
#[derive(Debug, PartialEq, Eq)]
enum PathWait {
    Selected,
    /// The connection closed first: the other end gave up, which is not a refusal.
    Closed,
    TimedOut,
}

async fn wait_selected(
    conn: &Connection,
    deadline: Duration,
    selected: fn(&Connection) -> bool,
) -> bool {
    wait_selected_outcome(conn, deadline, selected).await == PathWait::Selected
}

async fn wait_selected_outcome(
    conn: &Connection,
    deadline: Duration,
    selected: fn(&Connection) -> bool,
) -> PathWait {
    let mut events = conn.path_events();
    let proven = async {
        loop {
            if selected(conn) {
                return PathWait::Selected;
            }
            if events.next().await.is_none() {
                return PathWait::Closed;
            }
        }
    };
    n0_future::time::timeout(deadline, proven)
        .await
        .unwrap_or(PathWait::TimedOut)
}

/// The hold every inbound lane applies before reading a byte: with the relay
/// allowed as a transport, pass at once; otherwise wait up to `deadline` for
/// iroh to select a non-relay path, and on timeout close `conn` with
/// `close_code` so the other end reads the cause. Returns whether payload
/// may flow on `conn`.
pub async fn refuse_unless_direct(
    conn: &Connection,
    relay_transport: bool,
    deadline: Duration,
    close_code: u32,
) -> bool {
    let outcome = if relay_transport {
        PathWait::Selected
    } else {
        wait_selected_outcome(conn, deadline, selected_is_direct).await
    };
    match outcome {
        PathWait::Selected => {
            tracing::debug!(target: LOG_TARGET, remote = %conn.remote_id(), "payload path admitted");
            return true;
        }
        PathWait::Closed => {
            tracing::debug!(target: LOG_TARGET, remote = %conn.remote_id(), "dialer closed before a path was selected");
            return false;
        }
        PathWait::TimedOut => {}
    }
    // The paths iroh held at refusal time, because "which paths existed and
    // which was selected" is the whole diagnosis when a link that should
    // have gone direct did not.
    let paths: Vec<String> = conn
        .paths()
        .iter()
        .map(|path| {
            format!(
                "{:?}{}{}",
                path.remote_addr(),
                if path.is_selected() { " selected" } else { "" },
                if path.is_relay() { " relay" } else { "" },
            )
        })
        .collect();
    tracing::info!(target: LOG_TARGET, remote = %conn.remote_id(), paths = ?paths, "{RELAY_REFUSED}");
    conn.close(close_code.into(), b"relay path refused");
    false
}

/// [`refuse_unless_direct`] as a guard: waits up to `deadline` for the punch
/// a fresh connection is still making, and on refusal returns the error after
/// closing `conn` with `close_code`.
///
/// # Errors
/// The relay is lookup only and no direct path was selected on `conn` within
/// `deadline`.
#[cfg(feature = "blob")]
pub(crate) async fn refuse_relayed(
    conn: &Connection,
    relay_transport: bool,
    deadline: Duration,
    close_code: u32,
) -> anyhow::Result<()> {
    if refuse_unless_direct(conn, relay_transport, deadline, close_code).await {
        return Ok(());
    }
    anyhow::bail!("{RELAY_REFUSED}")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::{Endpoint, RelayMode, endpoint::presets};

    use super::{Connection, PathWait, wait_selected_outcome};

    const ALPN: &[u8] = b"test/path-wait";

    async fn loopback_endpoint() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("loopback"),
            )
            .expect("valid bind addr")
            .bind()
            .await
            .expect("bind a loopback endpoint")
    }

    /// A connection between two loopback endpoints: the dialer's end and the accepted end. The
    /// endpoints come back too: a dropped endpoint closes its connections.
    async fn connected() -> (Endpoint, Endpoint, Connection, Connection) {
        let server = loopback_endpoint().await;
        let client = loopback_endpoint().await;
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .accept()
                    .await
                    .expect("an incoming connection")
                    .await
                    .expect("the connection is accepted")
            })
        };
        let dialed = client
            .connect(server.addr(), ALPN)
            .await
            .expect("the dial succeeds");
        (
            client,
            server,
            dialed,
            accepting.await.expect("the accept task ends"),
        )
    }

    #[tokio::test]
    async fn a_dialer_that_closes_while_the_wait_runs_is_not_a_timeout() {
        let (_client, _server, dialed, accepted) = connected().await;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            dialed.close(0u32.into(), b"gave up");
        });

        let outcome = wait_selected_outcome(&accepted, Duration::from_secs(5), |_| false).await;

        assert_eq!(outcome, PathWait::Closed);
    }

    #[tokio::test]
    async fn a_wait_with_no_path_and_no_close_times_out() {
        let (_client, _server, _dialed, accepted) = connected().await;

        let outcome = wait_selected_outcome(&accepted, Duration::from_millis(300), |_| false).await;

        assert_eq!(outcome, PathWait::TimedOut);
    }

    #[tokio::test]
    async fn a_selected_path_ends_the_wait_at_once() {
        let (_client, _server, _dialed, accepted) = connected().await;

        let outcome = wait_selected_outcome(&accepted, Duration::from_secs(5), |_| true).await;

        assert_eq!(outcome, PathWait::Selected);
    }
}
