//! A source-routed, multi-hop iroh **custom transport**.
//!
//! Registered on an iroh endpoint via the `unstable-custom-transports` seam,
//! this transport lets a peer reach a destination it cannot dial directly by
//! relaying the destination's QUIC packets through intermediate peers. iroh runs
//! its full QUIC state machine end-to-end, so the two endpoints share a real
//! [`iroh::endpoint::Connection`] (streams, congestion control, QUIC-TLS
//! end-to-end secrecy); the relays only forward opaque, already-encrypted
//! packets.
//!
//! # Shape
//!
//! - [`Topology`] is the routing brain: a metric-weighted link-state graph fed by
//!   peers' [`LinkVector`]s, producing node-disjoint source [`Route`]s.
//! - A computed [`Route`] is packed into a [`CustomAddr`](iroh_base::CustomAddr)
//!   and travels with the connection; the address lookup resolves a target
//!   endpoint id to one.
//! - [`MultihopHandle`] owns a dedicated **underlay** iroh endpoint that carries
//!   packets hop-by-hop, and wires the transport onto an application endpoint via
//!   its [`Preset`](iroh::endpoint::presets::Preset) impl.
//!
//! # Usage
//!
//! ```ignore
//! // A dedicated underlay endpoint the crate forwards over, on the key derived
//! // from the application key.
//! let underlay = Endpoint::builder(presets::N0)
//!     .secret_key(underlay_secret(&app_secret))
//!     .bind()
//!     .await?;
//! let handle = MultihopHandle::new(&app_secret, underlay, HandleConfig::default())?;
//! // Wire the transport, its address lookup, and the path selector.
//! let app = Endpoint::builder(presets::N0)
//!     .secret_key(app_secret)
//!     .preset(handle.clone())
//!     .bind()
//!     .await?;
//! // Feed live link-state so routes can be computed.
//! handle.feed_topology(link_vector);
//! ```

mod addr;
mod graph;
mod lookup;
mod metric;
mod preset;
mod selector;
#[cfg(test)]
mod test_support;
mod topology;
mod transport;
mod underlay;
mod wire;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use iroh::address_lookup::AddressLookup;
use iroh::endpoint::transports::{CustomTransport, PathSelector};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use n0_future::time::{Duration, Instant};

pub use addr::{Route, RouteHop};
pub use metric::LinkMetric;
pub use topology::{LinkVector, Topology, TopologyEdge, TopologyView};

use crate::addr::Route as RouteInner;
use crate::lookup::MultihopLookup;
use crate::selector::MultihopLadder;
use crate::transport::{MultihopTransport, Shared};
use crate::underlay::{ForwardAcceptor, Forwarder};

/// Transport-type id for the multihop transport, tagging every multihop
/// [`CustomAddr`](iroh_base::CustomAddr) (see iroh's `TRANSPORTS.md` registry).
pub const MULTIHOP_TRANSPORT_ID: u64 = 0x6d68; // "mh"

/// The key of the underlay endpoint that belongs to the peer holding `app`.
///
/// Derived with a fixed domain label, so the same peer always has the same
/// underlay id across restarts, and no two peers share one. The link-vector the
/// peer advertises names this id and is signed by `app`, which is what binds the
/// underlay to the peer for everyone else.
#[must_use]
pub fn underlay_secret(app: &SecretKey) -> SecretKey {
    SecretKey::from_bytes(&blake3::derive_key(UNDERLAY_KEY_DOMAIN, &app.to_bytes()))
}

const UNDERLAY_KEY_DOMAIN: &str = "habilis-network-iroh-multihop-transport underlay key v1";

/// Terminal-delivery queue depth into the local transport's `poll_recv`.
const INBOUND_CAP: usize = 256;

/// How a [`MultihopHandle`] behaves. The mesh policy and the caller decide it;
/// an endpoint that is injected into a mesh must be built with the values that
/// mesh's policy implies (see `check_injected_identity` in the engine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleConfig {
    /// Whether the relay may carry cells (the mesh's `relay_transport`). Off, the
    /// relay is for lookup alone: the forwarder drops a cell it would send, and
    /// one it receives, unless the connection's selected path is not the relay.
    pub relay_payload: bool,
    /// How long a link-vector stays without a newer one, how old a vector may be
    /// when it arrives, and how long a removed peer is remembered. See
    /// [`Topology::with_max_age`] for the trade.
    pub vector_max_age: Duration,
    /// How long a hop's underlay may stay on the relay, refused by the gate,
    /// before it stops being advertised as a link.
    pub relay_stuck_after: Duration,
}

impl Default for HandleConfig {
    fn default() -> Self {
        Self {
            relay_payload: false,
            vector_max_age: topology::DEFAULT_VECTOR_MAX_AGE,
            relay_stuck_after: Duration::from_secs(20),
        }
    }
}

/// A handle to a live multihop transport: its underlay endpoint, forwarder, and
/// routing table. Clone-cheap (`Arc` inside). Register it on an application
/// endpoint with [`Endpoint::builder(..).preset(handle)`](iroh::endpoint::presets::Preset),
/// then keep it to [`feed_topology`](Self::feed_topology) as link-state changes.
///
/// The key passed to [`new`](Self::new) **must** be the secret key of the
/// application endpoint this handle is presetted onto: its public key is stamped
/// as our hop identity in every cell we originate, and it signs the link-vectors
/// we advertise. The handle therefore **holds that key**, and so does every clone
/// of it. Its `Debug` output shows no key material.
#[derive(Clone, Debug)]
pub struct MultihopHandle {
    inner: Arc<HandleInner>,
}

#[derive(Debug)]
struct HandleInner {
    secret: SecretKey,
    config: HandleConfig,
    /// The `seq` of the last vector this handle made.
    last_seq: AtomicU64,
    forwarder: Arc<Forwarder>,
    topology: Arc<RwLock<Topology>>,
    self_id: EndpointId,
    underlay: Endpoint,
    transport: Arc<MultihopTransport>,
    // Kept alive so the underlay's `FORWARD_ALPN` accept loop keeps running.
    _router: iroh::protocol::Router,
}

impl MultihopHandle {
    /// Build a handle over `underlay`, an endpoint dedicated to hop-by-hop
    /// forwarding. Must be called from within a tokio runtime (it spawns the
    /// forwarder's accept loop). `secret` is the application endpoint's key.
    ///
    /// `config` sets the relay rule, the age of a link-vector and how long a hop
    /// may sit on the relay: see [`HandleConfig`].
    ///
    /// # Errors
    /// `underlay` is not bound to [`underlay_secret`]`(secret)`. The underlay has
    /// a key of its own, because a relay hands an id's packets to one endpoint
    /// only and the underlay cannot share the application endpoint's. That key is
    /// derived, so it is stable and tied to the peer rather than a second random
    /// identity.
    pub fn new(
        secret: &SecretKey,
        underlay: Endpoint,
        config: HandleConfig,
    ) -> anyhow::Result<Self> {
        let app_id = secret.public();
        anyhow::ensure!(
            underlay.id() == underlay_secret(secret).public(),
            "the underlay must be bound to `underlay_secret(secret)`, not another key"
        );
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(INBOUND_CAP);
        let forwarder = Arc::new(Forwarder::new(
            underlay.clone(),
            app_id,
            inbound_tx,
            config.relay_payload,
            config.relay_stuck_after,
        ));

        let self_hop = RouteHop {
            app_id,
            underlay: underlay.addr(),
        };
        let self_addr = RouteInner::singleton(self_hop.clone()).encode();
        let shared = Arc::new(Shared {
            self_hop,
            self_addr,
            forwarder: Arc::clone(&forwarder),
        });

        let transport = Arc::new(MultihopTransport::new(shared, inbound_rx));
        let router = iroh::protocol::Router::builder(underlay.clone())
            .accept(
                underlay::FORWARD_ALPN,
                ForwardAcceptor::new(Arc::clone(&forwarder)),
            )
            .spawn();

        Ok(Self {
            inner: Arc::new(HandleInner {
                secret: secret.clone(),
                config,
                last_seq: AtomicU64::new(0),
                forwarder: Arc::clone(&forwarder),
                topology: Arc::new(RwLock::new(Topology::with_max_age(config.vector_max_age))),
                self_id: app_id,
                underlay,
                transport,
                _router: router,
            }),
        })
    }

    /// Ingest a peer's link-vector into the routing table. Returns whether the
    /// table changed (i.e. the vector was newer than what we held).
    ///
    /// # Panics
    /// If the routing-table lock is poisoned by a panic in another thread.
    #[expect(
        clippy::must_use_candidate,
        reason = "the returned 'changed' flag is advisory; ignoring it is valid"
    )]
    pub fn feed_topology(&self, vector: LinkVector) -> bool {
        self.inner
            .topology
            .write()
            .expect("topology lock poisoned")
            .ingest(vector)
    }

    /// The custom address of the best route from this node to `dst`, if the
    /// topology has one: what the address lookup would answer now. A dial can
    /// carry it, to teach iroh the route when iroh runs no lookup, which it does
    /// not while a non-relay path is selected. The address is one fixed route:
    /// see the note on `MultihopLookup`.
    ///
    /// # Panics
    /// If the routing-table lock is poisoned by a panic in another thread.
    #[must_use]
    pub fn route_addr(&self, dst: EndpointId) -> Option<iroh_base::CustomAddr> {
        self.inner
            .topology
            .read()
            .expect("topology lock poisoned")
            .route_to(self.inner.self_id, dst, 1)
            .into_iter()
            .next()
            .map(|route| route.encode())
    }

    /// Drop an origin's advertised links (e.g. a peer that left the mesh).
    ///
    /// # Panics
    /// If the routing-table lock is poisoned by a panic in another thread.
    #[expect(
        clippy::must_use_candidate,
        reason = "the returned 'removed' flag is advisory; ignoring it is valid"
    )]
    pub fn remove_origin(&self, origin: EndpointId) -> bool {
        self.inner
            .topology
            .write()
            .expect("topology lock poisoned")
            .remove(origin)
    }

    /// The application endpoint id this handle stamps as the hop identity of
    /// every cell it originates.
    #[must_use]
    pub fn app_id(&self) -> EndpointId {
        self.inner.self_id
    }

    /// Whether this handle lets the relay carry cells. A mesh whose policy has no
    /// `relay` must not be given a handle that does.
    #[must_use]
    pub fn relay_payload(&self) -> bool {
        self.inner.config.relay_payload
    }

    /// The application ids of the hops whose underlay has stayed on the relay,
    /// refused by the gate, for longer than the configured deadline. They are not
    /// advertised as links.
    #[must_use]
    pub fn stuck_hops(&self) -> Vec<EndpointId> {
        self.inner.forwarder.stuck_hops()
    }

    /// The id of this node's underlay endpoint: the key derived by
    /// [`underlay_secret`], not the application endpoint's.
    #[must_use]
    pub fn underlay_id(&self) -> EndpointId {
        self.inner.underlay.id()
    }

    /// The ports this node's underlay endpoint is bound on, for a test that
    /// blocks IP between underlays. Not in a browser, which binds no socket.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn underlay_ports(&self) -> Vec<u16> {
        self.inner
            .underlay
            .bound_sockets()
            .iter()
            .map(std::net::SocketAddr::port)
            .collect()
    }

    /// How many cells this node passed on for other nodes. Cells it sends for
    /// itself, and cells that end here, are not counted.
    #[must_use]
    pub fn forwarded_cells(&self) -> u64 {
        self.inner.forwarder.forwarded_cells()
    }

    /// The application id of the peer whose multihop underlay endpoint is
    /// `underlay_id`, from the link-vectors we hold. `None` if no vector names it.
    ///
    /// # Panics
    /// If the routing-table lock is poisoned by a panic in another thread.
    #[must_use]
    pub fn app_id_of(&self, underlay_id: EndpointId) -> Option<EndpointId> {
        self.inner
            .topology
            .read()
            .expect("topology lock poisoned")
            .app_id_of(underlay_id)
    }

    /// This node's current underlay dial address, for advertising to peers so
    /// they can route through us.
    #[must_use]
    pub fn underlay_addr(&self) -> EndpointAddr {
        self.inner.underlay.addr()
    }

    /// Build this node's own link-vector for gossiping: our underlay address plus
    /// one `(neighbour, cost)` link per direct neighbour, less the hops whose
    /// underlay is stuck on the relay (a link that carries nothing is not a link).
    ///
    /// Its `seq` is the wall-clock time in milliseconds, kept strictly above the
    /// last one this handle made, so a restart with the same key never loses to
    /// the vectors it sent before.
    #[must_use]
    pub fn link_vector(&self, mut links: Vec<(EndpointId, u32)>) -> LinkVector {
        let stuck = self.stuck_hops();
        links.retain(|(neighbour, _)| !stuck.contains(neighbour));
        let now = topology::wall_clock_ms();
        let mut seq = now;
        // The closure can run again if another thread wins the exchange.
        let _ = self
            .inner
            .last_seq
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
                seq = now.max(last.saturating_add(1));
                Some(seq)
            });
        LinkVector::signed(&self.inner.secret, seq, self.underlay_addr(), links)
    }

    /// Drop every vector whose newest version arrived more than the configured
    /// max age ago, so a crashed peer leaves no edge in the routing graph. Returns
    /// how many.
    ///
    /// # Panics
    /// If the routing-table lock is poisoned by a panic in another thread.
    #[expect(
        clippy::must_use_candidate,
        reason = "the returned count is advisory; ignoring it is valid"
    )]
    pub fn expire_stale(&self) -> usize {
        self.inner
            .topology
            .write()
            .expect("topology lock poisoned")
            .expire_older_than(Instant::now())
    }

    /// A JSON-serializable snapshot of the routing graph from this node's point of
    /// view, for the `topology` IPC query.
    ///
    /// # Panics
    /// If the routing-table lock is poisoned by a panic in another thread.
    #[must_use]
    pub fn topology_view(&self) -> TopologyView {
        self.inner
            .topology
            .read()
            .expect("topology lock poisoned")
            .view(self.inner.self_id)
    }

    /// The custom transport factory, for `Builder::add_custom_transport`.
    #[must_use]
    pub fn custom_transport(&self) -> Arc<dyn CustomTransport> {
        Arc::clone(&self.inner.transport) as Arc<dyn CustomTransport>
    }

    /// The address lookup that resolves a target endpoint id to a routed multihop
    /// address, for `Builder::address_lookup`.
    #[must_use]
    pub fn address_lookup(&self) -> impl AddressLookup + use<> {
        MultihopLookup::new(self.inner.self_id, Arc::clone(&self.inner.topology))
    }

    /// The path selector: a direct path, then multihop, then the relay. For
    /// `Builder::path_selector`.
    #[must_use]
    pub fn path_selector(&self) -> Arc<dyn PathSelector> {
        Arc::new(MultihopLadder)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode, SecretKey};

    use super::{HandleConfig, MultihopHandle, underlay_secret};
    use crate::addr::{Route, RouteHop};
    use crate::test_support::relay_server;
    use crate::wire::Cell;

    #[test]
    fn the_underlay_key_is_derived_from_the_peer_key() {
        let peer = SecretKey::from_bytes(&[7; 32]);
        let other = SecretKey::from_bytes(&[8; 32]);
        assert_eq!(
            underlay_secret(&peer).public(),
            underlay_secret(&peer).public(),
            "stable across restarts"
        );
        assert_ne!(
            underlay_secret(&peer).public(),
            peer.public(),
            "not the application id: a relay would deliver to only one of them"
        );
        assert_ne!(
            underlay_secret(&peer).public(),
            underlay_secret(&other).public(),
            "one underlay per peer"
        );
    }

    /// RFC 4648 base32 without padding, upper case: one of the two encodings that
    /// iroh uses for keys.
    fn base32(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        let (mut acc, mut bits) = (0_u32, 0_u32);
        for byte in bytes {
            acc = (acc << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                let index = usize::try_from((acc >> (bits - 5)) & 31).expect("five bits");
                out.push(char::from(ALPHABET[index]));
                bits -= 5;
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            let index = usize::try_from((acc << (5 - bits)) & 31).expect("five bits");
            out.push(char::from(ALPHABET[index]));
        }
        out
    }

    /// Bitcoin-alphabet base58 of a key with no leading zero byte.
    fn base58(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut digits: Vec<u8> = Vec::new();
        for byte in bytes {
            let mut carry = u32::from(*byte);
            for digit in &mut digits {
                carry += u32::from(*digit) << 8;
                *digit = u8::try_from(carry % 58).expect("below 58");
                carry /= 58;
            }
            while carry > 0 {
                digits.push(u8::try_from(carry % 58).expect("below 58"));
                carry /= 58;
            }
        }
        digits
            .iter()
            .rev()
            .map(|digit| char::from(ALPHABET[usize::from(*digit)]))
            .collect()
    }

    /// The encoders below stand in for iroh's key encodings in the Debug test; a
    /// wrong one would make that test pass for nothing.
    #[test]
    fn the_test_encoders_match_known_vectors() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI", "RFC 4648 vector");
        assert_eq!(
            base58(b"hello world"),
            "StV1DL6CwTryKyV",
            "the usual base58 vector"
        );
    }

    #[tokio::test]
    async fn the_debug_output_of_a_handle_shows_no_key_material() {
        // Distinct bytes, so no pattern of one repeated byte stands for the key.
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index)
                .expect("below 32")
                .wrapping_mul(7)
                .wrapping_add(3);
        }
        let secret = SecretKey::from_bytes(&bytes);
        let underlay = Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(&secret))
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind an underlay");
        let handle = MultihopHandle::new(&secret, underlay, HandleConfig::default())
            .expect("underlay on the derived key");
        let shown = format!("{handle:?}");

        let lower_hex = hex(&bytes);
        let forms = [
            ("hex", lower_hex.clone()),
            ("hex upper", lower_hex.to_uppercase()),
            ("base32", base32(&bytes)),
            ("base32 lower", base32(&bytes).to_lowercase()),
            ("base58", base58(&bytes)),
            ("byte list", format!("{bytes:?}")),
        ];
        for (name, form) in forms {
            assert!(!shown.contains(&form), "the key as {name}: {shown}");
        }
        assert!(
            !shown.as_bytes().windows(32).any(|run| run == bytes),
            "the 32 raw bytes of the key: {shown}"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    /// A handle whose underlay can only reach other underlays through the relay.
    async fn relay_only_handle(secret: &SecretKey, url: &iroh::RelayUrl) -> MultihopHandle {
        let underlay = Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(secret))
            .relay_mode(RelayMode::custom([url.clone()]))
            .clear_ip_transports()
            .bind()
            .await
            .expect("bind a relay-only underlay");
        tokio::time::timeout(Duration::from_secs(10), underlay.online())
            .await
            .expect("the underlay reaches the relay");
        let config = HandleConfig {
            relay_stuck_after: Duration::from_millis(300),
            ..HandleConfig::default()
        };
        MultihopHandle::new(secret, underlay, config).expect("underlay on the derived key")
    }

    #[tokio::test]
    async fn two_nodes_whose_underlays_only_meet_on_the_relay_advertise_no_usable_route() {
        let (url, _server) = relay_server().await;
        let (alice, bob) = (
            SecretKey::from_bytes(&[41; 32]),
            SecretKey::from_bytes(&[42; 32]),
        );
        let (first, second) = (
            relay_only_handle(&alice, &url).await,
            relay_only_handle(&bob, &url).await,
        );
        let (first_id, second_id) = (alice.public(), bob.public());
        assert_eq!(
            first.link_vector(vec![(second_id, 10)]).links.len(),
            1,
            "a link before any cell"
        );

        // Traffic each way: the gate refuses it, since only the relay is open.
        let hop = |handle: &MultihopHandle, id| RouteHop {
            app_id: id,
            underlay: handle.underlay_addr(),
        };
        for (from, from_id, to, to_id) in [
            (&first, first_id, &second, second_id),
            (&second, second_id, &first, first_id),
        ] {
            let cell = Cell {
                path: Route::new(vec![hop(to, to_id)]).expect("legal route"),
                pos: 0,
                source: hop(from, from_id),
                packet: vec![1, 2, 3],
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            while from.stuck_hops().is_empty() && std::time::Instant::now() < deadline {
                from.inner.forwarder.enqueue(&hop(to, to_id), cell.clone());
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }

        let (from_a, from_b) = (
            first.link_vector(vec![(second_id, 10)]),
            second.link_vector(vec![(first_id, 10)]),
        );
        assert!(
            from_a.links.is_empty() && from_b.links.is_empty(),
            "no stuck hop is advertised"
        );
        assert!(first.feed_topology(from_a) && first.feed_topology(from_b));
        assert!(
            first.topology_view().edges.is_empty(),
            "so no route is computed"
        );
    }
}
