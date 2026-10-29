//! Whether a connection's data is on a direct path right now, and whether the
//! mesh's transport policy lets payload ride it.
//!
//! iroh keeps every path it has to a peer open and picks one to carry data;
//! the relay path is never closed, only demoted. So "is this peer relayed" is
//! a question about the *selected* path, not about which paths exist —
//! `net::conn_path` answers the latter, for diagnostics.

use std::time::Duration;

use iroh::endpoint::{Connection, Path};

use super::LOG_TARGET;

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use iroh::endpoint;
use n0_future::time as n0future_time;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use std::sync;
use std::sync::atomic;
use std::sync::atomic::Ordering;
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

static GOSSIP_RECURSION_CLOSES: atomic::AtomicU64 = atomic::AtomicU64::new(0);

/// How many gossip connections the recursion rule closed since the process started: a total,
/// not a delta. A count that grows without bound is a pair that dials again after each close.
pub(crate) fn gossip_recursion_closes() -> u64 {
    GOSSIP_RECURSION_CLOSES.load(Ordering::Relaxed)
}

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
static GOSSIP_CONNS: sync::Mutex<Vec<endpoint::WeakConnectionHandle>> =
    sync::Mutex::new(Vec::new());

/// Tests only: remember a gossip connection, so that [`close_gossip_links_to`] can close it. The
/// list is shared by every member of the process. A connection has two ends and a close on one ends
/// both, so a test names the remote of the end it closes.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(crate) fn track_gossip_conn(connection: &Connection) {
    let mut conns = GOSSIP_CONNS.lock().expect("gossip conns poisoned");
    conns.retain(|weak| weak.upgrade().is_some());
    conns.push(connection.weak_handle());
}

/// Tests only: close every live gossip connection whose remote is `remote`, as a lost link does.
/// Returns how many it closed.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(crate) fn close_gossip_links_to(remote: iroh::EndpointId) -> usize {
    const TEST_CLOSE_CODE: u32 = 0x7e57;
    let conns = GOSSIP_CONNS.lock().expect("gossip conns poisoned");
    conns
        .iter()
        .filter_map(endpoint::WeakConnectionHandle::upgrade)
        .filter(|connection| {
            connection.remote_id() == remote && connection.close_reason().is_none()
        })
        .map(|connection| connection.close(TEST_CLOSE_CODE.into(), b"closed by a test"))
        .count()
}

/// Close `conn` with [`GOSSIP_RECURSION_REFUSED_CODE`] once its selected path is the gossip
/// rung, now or after a path change. Unconditional: it reads no mesh policy.
pub(crate) fn watch_gossip_recursion(
    connection: &Connection,
    admission: super::admission::SignalAdmission,
) {
    let remote = connection.remote_id();
    habilis_network_iroh_gossip_transport::watch_recursion(
        connection,
        GOSSIP_RECURSION_REFUSED_CODE,
        move || {
            GOSSIP_RECURSION_CLOSES.fetch_add(1, Ordering::Relaxed);
            admission.note_closed_on_rung(remote);
            tracing::info!(target: LOG_TARGET, %remote, "gossip connection closed: its path is the gossip rung");
        },
    );
}

/// Whether iroh's selected path to the remote is not the relay: a direct UDP
/// path, or a custom transport (`WebRTC`, multihop), which is peer to peer as
/// far as the relay is concerned. `false` while no path is selected yet.
pub(crate) fn selected_is_direct(connection: &Connection) -> bool {
    let paths = connection.paths();
    let selected = paths.iter().find(Path::is_selected);
    selected.is_some_and(|path| !path.is_relay())
}

/// Whether iroh's selected path to the remote is a direct UDP path: the race
/// against `WebRTC` is won. `false` while no path is selected yet.
pub(crate) fn selected_is_ip(connection: &Connection) -> bool {
    let paths = connection.paths();
    let selected = paths.iter().find(Path::is_selected);
    selected.is_some_and(|path| path.is_ip())
}

/// The rung of iroh's selected path on `conn`, for a test that shows a node
/// stepping down the ladder: `ip`, `webrtc`, `multihop` or `relay`. `None`
/// while no path is selected yet.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(crate) fn selected_rung(connection: &Connection) -> Option<&'static str> {
    use super::probe::{PathKind, selected_kind};

    match selected_kind(connection) {
        PathKind::Ip => Some("ip"),
        PathKind::WebRtc => Some("webrtc"),
        PathKind::Multihop => Some("multihop"),
        PathKind::Gossip => Some("gossip"),
        PathKind::Relay => Some("relay"),
        PathKind::None => None,
    }
}

/// Whether payload may go out on `conn` under the mesh's transport policy.
/// With the relay allowed as a transport, anything goes — decided before the
/// path snapshot, which locks and clones. With the relay lookup only, the
/// selected path must be a proven non-relay one: "not selected yet" is
/// refused, not trusted.
pub(crate) fn payload_allowed_on(connection: &Connection, relay_transport: bool) -> bool {
    relay_transport || selected_is_direct(connection)
}

/// The refusal every payload lane reports when the relay is lookup only and
/// the only path is the relay. One string, so a log reader can grep for it.
pub(crate) const RELAY_REFUSED: &str =
    "relay-only path refused: the relay is lookup only on this mesh";

/// Wait until `conn`'s selected path is not the relay, or `deadline` passes.
/// Every path event is a reason to re-read the path list: the event's own
/// address may be stale by the time it is handled.
///
/// # Examples
///
/// It waits until the connection has a direct path, or the deadline passes. The doc test compiles it but does not run it.
///
/// ```no_run
/// use std::time::Duration;
///
/// use habilis_network::iroh::endpoint::Connection;
/// use habilis_network::net::direct::wait_direct;
///
/// # async fn demo(connection: &Connection) -> bool {
/// wait_direct(connection, Duration::from_secs(1)).await
/// # }
/// ```
pub async fn wait_direct(connection: &Connection, deadline: Duration) -> bool {
    wait_selected(connection, deadline, selected_is_direct).await
}

/// [`wait_direct`] for a UDP path alone: whether UDP won the race against a
/// `WebRTC` session within `deadline`.
pub(crate) async fn wait_ip(connection: &Connection, deadline: Duration) -> bool {
    wait_selected(connection, deadline, selected_is_ip).await
}

/// Whether a payload may flow on the relay path, or only on a direct one.
///
/// # Examples
///
/// A payload path says which transports may carry a payload to a peer. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::direct::PayloadPath;
///
/// # fn demo(path: PayloadPath) {
/// let _ = path;
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayloadPath {
    /// Only direct paths.
    DirectOnly,
    /// Direct paths, or the relay.
    RelayAllowed,
}

impl PayloadPath {
    /// The flag form that the wire and the handle config still carry.
    #[must_use]
    pub fn relay_allowed(self) -> bool {
        matches!(self, Self::RelayAllowed)
    }
}

impl From<bool> for PayloadPath {
    fn from(relay_allowed: bool) -> Self {
        if relay_allowed {
            Self::RelayAllowed
        } else {
            Self::DirectOnly
        }
    }
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
    connection: &Connection,
    deadline: Duration,
    selected: fn(&Connection) -> bool,
) -> bool {
    wait_selected_outcome(connection, deadline, selected).await == PathWait::Selected
}

async fn wait_selected_outcome(
    connection: &Connection,
    deadline: Duration,
    selected: fn(&Connection) -> bool,
) -> PathWait {
    use futures_util::StreamExt as _;
    let mut events = connection.path_events();
    let proven = async {
        loop {
            if selected(connection) {
                return PathWait::Selected;
            }
            if events.next().await.is_none() {
                return PathWait::Closed;
            }
        }
    };
    n0future_time::timeout(deadline, proven)
        .await
        .unwrap_or(PathWait::TimedOut)
}

/// The hold every inbound lane applies before reading a byte: with the relay
/// allowed as a transport, pass at once; otherwise wait up to `deadline` for
/// iroh to select a non-relay path, and on timeout close `conn` with
/// `close_code` so the other end reads the cause. Returns whether payload
/// may flow on `conn`.
///
/// # Examples
///
/// It refuses a relayed payload unless the connection finds a direct path before the deadline. The doc test compiles it but does not run it.
///
/// ```no_run
/// use std::time::Duration;
///
/// use habilis_network::iroh::endpoint::Connection;
/// use habilis_network::net::direct::{PayloadPath, refuse_unless_direct};
///
/// # async fn demo(connection: &Connection, relay: PayloadPath) {
/// let _ = refuse_unless_direct(connection, relay, Duration::from_secs(1), 0).await;
/// # }
/// ```
pub async fn refuse_unless_direct(
    connection: &Connection,
    relay: PayloadPath,
    deadline: Duration,
    close_code: u32,
) -> bool {
    let outcome = if relay.relay_allowed() {
        PathWait::Selected
    } else {
        wait_selected_outcome(connection, deadline, selected_is_direct).await
    };
    match outcome {
        PathWait::Selected => {
            tracing::debug!(target: LOG_TARGET, remote = %connection.remote_id(), "payload path admitted");
            return true;
        }
        PathWait::Closed => {
            tracing::debug!(target: LOG_TARGET, remote = %connection.remote_id(), "dialer closed before a path was selected");
            return false;
        }
        PathWait::TimedOut => {}
    }
    // The paths iroh held at refusal time, because "which paths existed and
    // which was selected" is the whole diagnosis when a link that should
    // have gone direct did not.
    let paths: Vec<String> = connection
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
    tracing::info!(target: LOG_TARGET, remote = %connection.remote_id(), paths = ?paths, "{RELAY_REFUSED}");
    connection.close(close_code.into(), b"relay path refused");
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
    connection: &Connection,
    relay: PayloadPath,
    deadline: Duration,
    close_code: u32,
) -> anyhow::Result<()> {
    if refuse_unless_direct(connection, relay, deadline, close_code).await {
        return Ok(());
    }
    anyhow::bail!("{RELAY_REFUSED}")
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode};

    use super::{Connection, PathWait, wait_selected_outcome};
    use tokio::time;

    const ALPN: &[u8] = b"test/path-wait";

    async fn loopback_endpoint() -> Endpoint {
        let alpns = vec![ALPN.to_vec()];
        let builder = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .alpns(alpns);
        let builder = builder
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("valid bind addr");
        builder.bind().await.expect("bind a loopback endpoint")
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

    #[test]
    fn a_dialer_that_closes_while_the_wait_runs_is_not_a_timeout() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (client, server, dialed, accepted) = connected().await;
            tokio::spawn(async move {
                time::sleep(Duration::from_millis(100)).await;
                dialed.close(0u32.into(), b"gave up");
            });

            let outcome = wait_selected_outcome(&accepted, Duration::from_secs(5), |_| false).await;

            assert_eq!(
                outcome,
                PathWait::Closed,
                "a dialler that closes during the wait is a closed wait, not a timeout"
            );
            client.close().await;
            server.close().await;
        });
    }

    #[test]
    fn a_wait_with_no_path_and_no_close_times_out() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (client, server, _dialed, accepted) = connected().await;

            let outcome =
                wait_selected_outcome(&accepted, Duration::from_millis(300), |_| false).await;

            assert_eq!(
                outcome,
                PathWait::TimedOut,
                "a wait with no path and no close times out"
            );
            client.close().await;
            server.close().await;
        });
    }

    #[test]
    fn a_selected_path_ends_the_wait_at_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (client, server, _dialed, accepted) = connected().await;

            let outcome = wait_selected_outcome(&accepted, Duration::from_secs(5), |_| true).await;

            assert_eq!(
                outcome,
                PathWait::Selected,
                "a selected path ends the wait at once"
            );
            client.close().await;
            server.close().await;
        });
    }
}
