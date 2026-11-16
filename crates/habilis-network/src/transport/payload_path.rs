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

/// Close code of a gossip connection whose selected path is Nostr.
pub(crate) const GOSSIP_NOSTR_REFUSED_CODE: u32 = super::webrtc::close_code::GOSSIP_ON_NOSTR_PATH;

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

/// Close `connection` with [`GOSSIP_NOSTR_REFUSED_CODE`] once its selected path is Nostr, now or
/// after a path change. Unconditional: it reads no mesh policy, and the mesh may allow the relay.
pub(crate) fn watch_gossip_on_nostr(
    connection: &Connection,
    admission: super::admission::SignalAdmission,
) {
    let remote = connection.remote_id();
    habilis_network_iroh_gossip_transport::watch_transport_path(
        connection,
        habilis_network_iroh_gossip_transport::NOSTR_TRANSPORT_ID,
        GOSSIP_NOSTR_REFUSED_CODE,
        move || {
            // The pair reads as Nostr for a while, so that a graft does not dial the link again
            // at once (see `request_graft`).
            admission.note_closed_on_rung(remote, super::probe::PathKind::Nostr);
            tracing::info!(target: LOG_TARGET, %remote, "gossip connection closed: its path is Nostr");
        },
    );
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
            admission.note_closed_on_rung(remote, super::probe::PathKind::Gossip);
            tracing::info!(target: LOG_TARGET, %remote, "gossip connection closed: its path is the gossip rung");
        },
    );
}

/// Whether a path address is peer to peer: a direct UDP address, or a custom transport
/// (`WebRTC`, multihop, gossip). The relay is not, and Nostr is not either: its relays are
/// infrastructure that sees every datagram, and it is the last fallback.
pub(crate) fn is_peer_to_peer(address: &iroh::TransportAddr) -> bool {
    !matches!(address, iroh::TransportAddr::Relay(_)) && !is_nostr(address)
}

/// Whether a path address is a Nostr address.
pub(crate) fn is_nostr(address: &iroh::TransportAddr) -> bool {
    matches!(address, iroh::TransportAddr::Custom(custom)
        if custom.id() == habilis_network_iroh_gossip_transport::NOSTR_TRANSPORT_ID)
}

/// Whether the selected path of `connection` is one that `path` lets a payload ride.
pub(crate) fn selected_is_payload_path(connection: &Connection, path: PayloadPath) -> bool {
    let paths = connection.paths();
    let selected = paths.iter().find(Path::is_selected);
    let address: Option<iroh::TransportAddr> =
        selected.map(|selected_path| selected_path.remote_addr().clone());
    path.carries(address.as_ref())
}

/// Whether iroh's selected path to the remote is peer to peer: a direct UDP
/// path, or a custom transport (`WebRTC`, multihop), but neither the relay nor Nostr
/// (see [`is_peer_to_peer`]). `false` while no path is selected yet.
pub(crate) fn selected_is_direct(connection: &Connection) -> bool {
    let paths = connection.paths();
    let selected = paths.iter().find(Path::is_selected);
    selected.is_some_and(|path| is_peer_to_peer(path.remote_addr()))
}

/// Whether iroh's selected path to the remote is a direct UDP path: the race
/// against `WebRTC` is won. `false` while no path is selected yet.
pub(crate) fn selected_is_ip(connection: &Connection) -> bool {
    let paths = connection.paths();
    let selected = paths.iter().find(Path::is_selected);
    selected.is_some_and(|path| path.is_ip())
}

/// The rung of iroh's selected path on `conn`, for a test that shows a node
/// stepping down the ladder: `ip`, `webrtc`, `multihop`, `gossip`, `relay` or `nostr`. `None`
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
        PathKind::Nostr => Some("nostr"),
        PathKind::None => None,
    }
}

/// Whether payload may go out on `conn` under the mesh's transport policy.
/// With both the relay and Nostr allowed as transports, anything goes — decided before the
/// path snapshot, which locks and clones. Otherwise the selected path must be one that the
/// policy lists (see [`PayloadPath::carries`]): a peer-to-peer path, the relay when it is
/// listed, Nostr when it is listed. "Not selected yet" is trusted only when the relay is
/// listed.
pub(crate) fn payload_allowed_on(connection: &Connection, path: PayloadPath) -> bool {
    path == PayloadPath::RelayOrNostr || selected_is_payload_path(connection, path)
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

/// [`wait_direct`] for the paths that `path` lets a payload ride: a direct path, or a Nostr path
/// when the policy lists Nostr.
pub(crate) async fn wait_payload_path(
    connection: &Connection,
    deadline: Duration,
    path: PayloadPath,
) -> bool {
    wait_selected_outcome(connection, deadline, |connection| {
        selected_is_payload_path(connection, path)
    })
    .await
        == PathWait::Selected
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
    /// Direct paths, or the Nostr relays of a custom list. The relay is lookup only.
    DirectOrNostr,
    /// Direct paths, the relay, or the Nostr relays of a custom list.
    RelayOrNostr,
}

impl PayloadPath {
    /// The flag form that the wire and the handle config still carry.
    #[must_use]
    pub fn relay_allowed(self) -> bool {
        matches!(self, Self::RelayAllowed | Self::RelayOrNostr)
    }

    /// Whether a payload may ride a Nostr path: the mesh lists the Nostr transport.
    #[must_use]
    pub fn nostr_allowed(self) -> bool {
        matches!(self, Self::DirectOrNostr | Self::RelayOrNostr)
    }

    /// The payload path of a mesh policy: whether it lists the relay, and whether it lists Nostr.
    #[must_use]
    pub fn from_policy(
        // `true` lets payloads use the relay
        relay_allowed: bool,
        // `true` lets payloads use the Nostr relays of a custom list
        nostr_allowed: bool,
    ) -> Self {
        match (relay_allowed, nostr_allowed) {
            (false, false) => Self::DirectOnly,
            (true, false) => Self::RelayAllowed,
            (false, true) => Self::DirectOrNostr,
            (true, true) => Self::RelayOrNostr,
        }
    }

    /// The same path with Nostr off: a gossip link never rides Nostr, whatever the mesh lists.
    #[must_use]
    pub fn without_nostr(self) -> Self {
        Self::from_policy(self.relay_allowed(), false)
    }

    /// Whether a payload may ride the selected path `selected` (`None` while iroh selected no
    /// path yet). A peer-to-peer path always carries it. The relay carries it when the mesh lists
    /// the relay, Nostr when the mesh lists Nostr. No path yet reads as the relay does: it is
    /// trusted only when the relay is listed.
    #[must_use]
    pub(crate) fn carries(self, selected: Option<&iroh::TransportAddr>) -> bool {
        match selected {
            None | Some(iroh::TransportAddr::Relay(_)) => self.relay_allowed(),
            Some(address) if is_nostr(address) => self.nostr_allowed(),
            Some(_) => true,
        }
    }

    /// Make the payload path from a flag.
    #[must_use]
    pub fn from_bool(
        // `true` lets payloads use the relay (`RelayAllowed`); `false` keeps them on direct paths (`DirectOnly`).
        relay_allowed: bool,
    ) -> Self {
        if relay_allowed {
            Self::RelayAllowed
        } else {
            Self::DirectOnly
        }
    }
}

impl From<bool> for PayloadPath {
    fn from(relay_allowed: bool) -> Self {
        Self::from_bool(relay_allowed)
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
    selected: impl Fn(&Connection) -> bool,
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
        wait_selected_outcome(connection, deadline, |connection| {
            selected_is_payload_path(connection, relay)
        })
        .await
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

    use super::{Connection, PathWait, PayloadPath, is_peer_to_peer, wait_selected_outcome};
    use habilis_network_iroh_gossip_transport as gossip_transport;
    use tokio::time;

    /// The mesh policy decides what rides a path: a peer-to-peer path always, the relay when the
    /// mesh lists it, Nostr when the mesh lists Nostr. A mesh without Nostr refuses it even if
    /// the relay is listed.
    #[test]
    fn the_policy_lists_which_selected_paths_carry_a_payload() {
        let _guard = ::habilis_network_test_tracing::init();
        let peer = iroh::SecretKey::from_bytes(&[6; 32]).public();
        let nostr = iroh::TransportAddr::Custom(gossip_transport::transport_addr(
            gossip_transport::NOSTR_TRANSPORT_ID,
            peer,
        ));
        let relay = iroh::TransportAddr::Relay("https://relay.invalid".parse().expect("relay url"));
        let udp = iroh::TransportAddr::Ip(([127, 0, 0, 1], 9).into());
        for (policy, on_nostr, on_relay, on_udp, unselected) in [
            (PayloadPath::DirectOnly, false, false, true, false),
            (PayloadPath::RelayAllowed, false, true, true, true),
            (PayloadPath::DirectOrNostr, true, false, true, false),
            (PayloadPath::RelayOrNostr, true, true, true, true),
        ] {
            assert_eq!(
                policy.carries(Some(&nostr)),
                on_nostr,
                "{policy:?} on Nostr"
            );
            assert_eq!(
                policy.carries(Some(&relay)),
                on_relay,
                "{policy:?} on the relay"
            );
            assert_eq!(policy.carries(Some(&udp)), on_udp, "{policy:?} on UDP");
            assert_eq!(
                policy.carries(None),
                unselected,
                "{policy:?} with no path yet"
            );
        }
        assert_eq!(
            PayloadPath::from_policy(true, true),
            PayloadPath::RelayOrNostr,
            "both"
        );
        assert_eq!(
            PayloadPath::RelayOrNostr.without_nostr(),
            PayloadPath::RelayAllowed,
            "a gossip link never rides Nostr"
        );
        assert_eq!(
            PayloadPath::DirectOrNostr.without_nostr(),
            PayloadPath::DirectOnly,
            "a gossip link never rides Nostr, with the relay off too"
        );
    }

    /// The gate on a live connection whose selected path is Nostr: a mesh that lists the Nostr
    /// transport lets payload ride it, and a mesh that does not refuses it.
    #[test]
    fn a_connection_on_the_nostr_path_carries_a_payload_only_when_the_mesh_lists_nostr() {
        use gossip_transport::hub::Hub;
        use iroh::endpoint::presets;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};
        use iroh::{EndpointAddr, SecretKey};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (alice_key, bob_key) = (
                    SecretKey::from_bytes(&[41; 32]),
                    SecretKey::from_bytes(&[42; 32]),
                );
                let hub = Hub::new();
                let handles = (
                    gossip_transport::GossipHandle::with_transport_id(
                        alice_key.public(),
                        gossip_transport::NOSTR_TRANSPORT_ID,
                    ),
                    gossip_transport::GossipHandle::with_transport_id(
                        bob_key.public(),
                        gossip_transport::NOSTR_TRANSPORT_ID,
                    ),
                );
                hub.join(&handles.0);
                hub.join(&handles.1);
                let bind = |key: SecretKey, handle: gossip_transport::GossipHandle| async move {
                    let builder = Endpoint::builder(presets::Minimal);
                    let builder = builder.secret_key(key);
                    let builder = builder.relay_mode(RelayMode::Disabled);
                    let builder = builder.add_custom_transport(handle.custom_transport());
                    let builder = builder.clear_ip_transports();
                    let builder = builder.clear_relay_transports();
                    builder.bind().await.expect("bind a Nostr-only endpoint")
                };
                let alice = bind(alice_key, handles.0).await;
                let bob = bind(bob_key, handles.1).await;
                let router = Router::builder(bob.clone()).accept(ALPN, Hold).spawn();
                let target = EndpointAddr::from_parts(
                    bob.id(),
                    [iroh::TransportAddr::Custom(
                        gossip_transport::transport_addr(
                            gossip_transport::NOSTR_TRANSPORT_ID,
                            bob.id(),
                        ),
                    )],
                );
                let connection = alice
                    .connect(target, ALPN)
                    .await
                    .expect("connect over Nostr");

                for (policy, expected) in [
                    (PayloadPath::DirectOnly, false),
                    (PayloadPath::RelayAllowed, false),
                    (PayloadPath::DirectOrNostr, true),
                    (PayloadPath::RelayOrNostr, true),
                ] {
                    assert_eq!(
                        super::payload_allowed_on(&connection, policy),
                        expected,
                        "{policy:?} on a Nostr path"
                    );
                }
                assert!(
                    super::wait_payload_path(
                        &connection,
                        Duration::from_secs(2),
                        PayloadPath::DirectOrNostr
                    )
                    .await,
                    "the wait ends on a Nostr path that the mesh lists"
                );
                assert!(
                    !super::wait_payload_path(
                        &connection,
                        Duration::from_millis(300),
                        PayloadPath::DirectOnly
                    )
                    .await,
                    "the wait times out on a Nostr path that the mesh does not list"
                );
                connection.close(0u32.into(), b"done");
                router.shutdown().await.expect("shutdown");
                alice.close().await;
            },
        );
    }

    /// The relay and Nostr are infrastructure, not peers: a path on either is not direct, so the
    /// gate of a mesh whose relay is lookup only refuses payload on it.
    #[test]
    fn a_nostr_path_is_not_peer_to_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let peer = iroh::SecretKey::from_bytes(&[5; 32]).public();
        let custom = |id| iroh::TransportAddr::Custom(gossip_transport::transport_addr(id, peer));
        assert!(
            !is_peer_to_peer(&custom(gossip_transport::NOSTR_TRANSPORT_ID)),
            "a Nostr path is not peer to peer"
        );
        assert!(
            is_peer_to_peer(&custom(gossip_transport::GOSSIP_TRANSPORT_ID)),
            "a gossip path is"
        );
        assert!(
            is_peer_to_peer(&iroh::TransportAddr::Ip(([127, 0, 0, 1], 9).into())),
            "a UDP path is"
        );
        assert!(
            !is_peer_to_peer(&iroh::TransportAddr::Relay(
                "https://relay.invalid".parse().expect("relay url")
            )),
            "the relay is not"
        );
    }

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
