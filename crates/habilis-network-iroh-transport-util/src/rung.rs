#[cfg(feature = "test-hooks")]
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use iroh::endpoint::transports::{Addr, FourTuple, PathSelectionData, Transmit};

#[cfg(feature = "test-hooks")]
use std::sync;
#[cfg(feature = "test-hooks")]
use std::sync::atomic;
#[cfg(feature = "test-hooks")]
use std::sync::atomic::Ordering;
use std::{iter, net};
/// The RTT that another path of a rung must beat the current path by before the selection moves to it. It is
/// the value of `RTT_SWITCHING_MIN` in the default selector of iroh (`BiasedRttPathSelector`, in
/// `iroh/src/socket/biased_rtt_path_selector.rs`), which keeps that constant private.
const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// The path of `iter` that the selection takes: the current path stays while it is in `iter` and no other path is
/// faster than it by `RTT_SWITCHING_MIN`, and otherwise the lowest-RTT path.
///
/// A host with several interfaces (a LAN, a VM bridge, a VPN) has several IP paths to one peer, and their RTTs
/// differ by the noise of the measure. A selection that follows the lowest RTT moves at each event, and each move
/// makes iroh close the paths that are not selected, so the path in use is never the one that stays open.
///
/// A path whose stats are not readable yet — freshly added, not yet validated —
/// still counts as a candidate, so an unmeasured path is never skipped in
/// favour of the fallback it is meant to replace. That is the load-bearing
/// half: without it a new direct path loses to the relay forever, because it
/// never gets the traffic that would measure it. A current path with no stats stays: it is the path in use,
/// and it is measured next.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::best_of;
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo<'a>(paths: &'a [PathSelectionData<'a>]) -> Option<&'a PathSelectionData<'a>> {
/// best_of(None, paths.iter())
/// # }
/// ```
#[must_use]
pub fn best_of<'a, Paths>(
    current: Option<&FourTuple>,
    iter: Paths,
) -> Option<&'a PathSelectionData<'a>>
where
    Paths: Iterator<Item = &'a PathSelectionData<'a>> + Clone,
{
    let best = lowest_rtt(iter.clone())?;
    let mut rest = iter;
    let kept = current.and_then(|current| rest.find(|path| path.network_path() == current));
    match kept {
        Some(kept) if stays(kept, best) => Some(kept),
        Some(_) | None => Some(best),
    }
}

/// The lowest-RTT path in `iter`, or its first path when none has stats.
fn lowest_rtt<'a>(
    iter: impl Iterator<Item = &'a PathSelectionData<'a>>,
) -> Option<&'a PathSelectionData<'a>> {
    let mut best: Option<(&PathSelectionData<'_>, Duration)> = None;
    let mut fallback: Option<&PathSelectionData<'_>> = None;
    for path in iter {
        if fallback.is_none() {
            fallback = Some(path);
        }
        if let Some(stats) = path.stats() {
            let rtt = stats.rtt;
            if best.is_none_or(|(_, known)| rtt < known) {
                best = Some((path, rtt));
            }
        }
    }
    best.map(|(path, _)| path).or(fallback)
}

/// Whether the current path `kept` stays selected against `best`: it has no stats yet, or `best` is not faster than it by
/// `RTT_SWITCHING_MIN`.
fn stays(kept: &PathSelectionData<'_>, best: &PathSelectionData<'_>) -> bool {
    let (Some(kept_stats), Some(best_stats)) = (kept.stats(), best.stats()) else {
        return true;
    };
    kept_stats.rtt < best_stats.rtt + RTT_SWITCHING_MIN
}

/// One rung of the path ladder, best first: a direct IP path, then `WebRTC`, then
/// multihop, then gossip, then the relay. A node with every rung climbs to the
/// highest one it has, and falls one rung when that path goes away.
///
/// The order is the declaration order, and both selectors take it from here, so
/// that it does not depend on which transports an endpoint has installed.
///
/// # Examples
///
/// The ladder tries the direct IP rung first.
///
/// ```
/// use habilis_network_iroh_transport_util::Rung;
///
/// assert!(matches!(Rung::LADDER[0], Rung::Ip));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Rung {
    /// A direct IP path.
    Ip,
    /// A `WebRTC` data channel.
    WebRtc,
    /// A path that hops through other members.
    Multihop,
    /// QUIC packets carried as frames on the mesh gossip topic. It stands above
    /// the relay, which is infrastructure, and below every path between two
    /// members.
    Gossip,
    /// The relay, the last resort.
    Relay,
    /// A custom transport that the caller does not name, below every other rung.
    Other,
}

impl Rung {
    /// Every rung, best first.
    pub const LADDER: [Self; 6] = [
        Self::Ip,
        Self::WebRtc,
        Self::Multihop,
        Self::Gossip,
        Self::Relay,
        Self::Other,
    ];
}

/// The rung `path` stands on. `custom` names the rung of a custom transport by
/// its id. Each selector knows its own transport's id and not the other's, so it
/// names its own and gives the other one by elimination.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, custom_rung, rung_of};
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo(path: &PathSelectionData<'_>) -> Rung {
/// rung_of(path, custom_rung)
/// # }
/// ```
#[must_use]
pub fn rung_of(path: &PathSelectionData<'_>, custom: impl Fn(u64) -> Rung) -> Rung {
    match path.network_path().remote() {
        Addr::Ip(_) => Rung::Ip,
        Addr::Relay(..) => Rung::Relay,
        Addr::Custom(address) => custom(address.id()),
    }
}

/// Transport id of the `WebRTC` custom transport.
pub const WEBRTC_TRANSPORT_ID: u64 = 0x5752_5443;
/// Transport id of the multihop custom transport.
pub const MULTIHOP_TRANSPORT_ID: u64 = 0x6d68;
/// Transport id of the gossip custom transport.
pub const GOSSIP_TRANSPORT_ID: u64 = 0x6773;

/// The rung of a custom transport id: the one function every selector asks, so
/// that no selector ranks a transport it does not know below the relay or above
/// its place. An id that none of the three names is [`Rung::Other`].
///
/// The ids live here because this crate is below the transport crates, which
/// cannot name each other. Each transport crate keeps its own constant, and a
/// test in that crate checks that it equals the one here.
///
/// # Examples
///
/// A custom transport id maps to the rung of that transport.
///
/// ```
/// use habilis_network_iroh_transport_util::{Rung, WEBRTC_TRANSPORT_ID, custom_rung};
///
/// assert!(matches!(custom_rung(WEBRTC_TRANSPORT_ID), Rung::WebRtc));
/// ```
#[must_use]
pub fn custom_rung(id: u64) -> Rung {
    match id {
        WEBRTC_TRANSPORT_ID => Rung::WebRtc,
        MULTIHOP_TRANSPORT_ID => Rung::Multihop,
        GOSSIP_TRANSPORT_ID => Rung::Gossip,
        _ => Rung::Other,
    }
}

/// The rung a node stands on: the highest rung that is `allowed` and has an
/// `available` path, or `None`. Pure. The ladder lives here and nowhere else:
/// both selectors choose through it, and a test that asks where a node should
/// stand asks it too.
///
/// # Examples
///
/// The first rung on the ladder that is allowed and available is the expected one.
///
/// ```
/// use habilis_network_iroh_transport_util::{Rung, expected_rung};
///
/// let rung = expected_rung(|_| true, |rung| matches!(rung, Rung::Multihop | Rung::Relay));
/// assert!(rung.is_some_and(|rung| matches!(rung, Rung::Multihop)));
/// ```
#[must_use]
pub fn expected_rung(
    allowed: impl Fn(Rung) -> bool,
    available: impl Fn(Rung) -> bool,
) -> Option<Rung> {
    Rung::LADDER
        .into_iter()
        .find(|&rung| allowed(rung) && available(rung))
}

/// The best path of the rung that [`expected_rung`] picks among the rungs that
/// have a usable path: the lowest RTT inside the rung (see [`best_of`]).
/// `usable` lets a caller drop a path, as a test does to take one rung away
/// from one node. It adds no ladder of its own.
///
/// # Examples
///
/// It walks the rungs of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, climb, custom_rung};
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo<'a>(paths: &'a [PathSelectionData<'a>]) -> Option<&'a PathSelectionData<'a>> {
/// climb(None, paths, custom_rung, |rung, _path| matches!(rung, Rung::Ip))
/// # }
/// ```
#[must_use]
pub fn climb<'a>(
    current: Option<&FourTuple>,
    paths: &'a [PathSelectionData<'a>],
    custom: impl Fn(u64) -> Rung,
    usable: impl Fn(Rung, &PathSelectionData<'_>) -> bool,
) -> Option<&'a PathSelectionData<'a>> {
    let usable_on = |rung: Rung, path: &PathSelectionData<'_>| {
        rung_of(path, &custom) == rung && usable(rung, path)
    };
    let rung = expected_rung(
        |_| true,
        |rung| paths.iter().any(|path| usable_on(rung, path)),
    )?;
    best_of(current, paths.iter().filter(|path| usable_on(rung, path)))
}

/// The IP address a path leads to, or `None` for a relay or custom path.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::ip_remote;
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo(path: &PathSelectionData<'_>) -> Option<std::net::SocketAddr> {
/// ip_remote(path)
/// # }
/// ```
#[must_use]
pub fn ip_remote(path: &PathSelectionData<'_>) -> Option<net::SocketAddr> {
    match path.network_path().remote() {
        Addr::Ip(remote) => Some(remote),
        Addr::Relay(..) | Addr::Custom(_) => None,
    }
}

/// The endpoint id that an address leads to, when the address names one: a relay
/// address carries the endpoint it reaches, and a `WebRTC` custom address is that
/// endpoint's id. An IP address does not, and a custom address of another
/// transport carries no single remote (a multihop address is a route), so those
/// give `None`.
///
/// # Examples
///
/// It reads an address of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::remote_id_of;
/// use iroh::endpoint::transports::Addr;
///
/// # fn demo(address: &Addr) -> Option<iroh::EndpointId> {
/// remote_id_of(address)
/// # }
/// ```
#[must_use]
pub fn remote_id_of(address: &Addr) -> Option<iroh::EndpointId> {
    match address {
        Addr::Relay(_, id) => Some(*id),
        Addr::Custom(custom) if custom.id() == WEBRTC_TRANSPORT_ID => {
            let bytes: [u8; 32] = custom.data().try_into().ok()?;
            iroh::EndpointId::from_bytes(&bytes).ok()
        }
        Addr::Ip(_) | Addr::Custom(_) => None,
    }
}

/// [`remote_id_of`] for the address of a path.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::remote_id;
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo(path: &PathSelectionData<'_>) -> Option<iroh::EndpointId> {
/// remote_id(path)
/// # }
/// ```
#[must_use]
pub fn remote_id(path: &PathSelectionData<'_>) -> Option<iroh::EndpointId> {
    remote_id_of(&path.network_path().remote())
}

/// Whether a test took the path `path` away from the node `local`, on `rung`:
/// [`is_blocked_to`] for a selector, which has a path and not an address.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, blocked};
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo(local: iroh::EndpointId, path: &PathSelectionData<'_>) -> bool {
/// blocked(local, Rung::Ip, path)
/// # }
/// ```
#[must_use]
pub fn blocked(local: iroh::EndpointId, rung: Rung, path: &PathSelectionData<'_>) -> bool {
    is_blocked_to(local, rung, ip_remote(path), remote_id(path))
}

/// Without `test-hooks` nothing is ever blocked, so a selector reads the same
/// function in every build and needs no feature of its own.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, is_blocked};
///
/// # fn demo(local: iroh::EndpointId) -> bool {
/// is_blocked(local, Rung::Ip, None)
/// # }
/// ```
#[cfg(not(feature = "test-hooks"))]
#[must_use]
pub fn is_blocked(_local: iroh::EndpointId, _rung: Rung, _remote: Option<net::SocketAddr>) -> bool {
    false
}

/// [`is_blocked`], and the remote endpoint id of the path when it has one.
///
/// # Examples
///
/// It reads the block list of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, is_blocked_to};
///
/// # fn demo(local: iroh::EndpointId, remote: iroh::EndpointId) -> bool {
/// is_blocked_to(local, Rung::Ip, None, Some(remote))
/// # }
/// ```
#[cfg(not(feature = "test-hooks"))]
#[must_use]
pub fn is_blocked_to(
    _local: iroh::EndpointId,
    _rung: Rung,
    _remote: Option<net::SocketAddr>,
    _remote_id: Option<iroh::EndpointId>,
) -> bool {
    false
}

#[cfg(feature = "test-hooks")]
static IP_BLOCKED: atomic::AtomicBool = atomic::AtomicBool::new(false);

#[cfg(feature = "test-hooks")]
type PortBlocks = sync::Mutex<Option<HashMap<iroh::EndpointId, HashSet<u16>>>>;

#[cfg(feature = "test-hooks")]
static IP_BLOCKED_TO: PortBlocks = sync::Mutex::new(None);

#[cfg(feature = "test-hooks")]
static RUNGS_BLOCKED: sync::Mutex<Option<HashSet<(iroh::EndpointId, Rung)>>> =
    sync::Mutex::new(None);

#[cfg(feature = "test-hooks")]
static RUNGS_BLOCKED_TO: sync::Mutex<Option<HashSet<(iroh::EndpointId, Rung, iroh::EndpointId)>>> =
    sync::Mutex::new(None);

/// The pure table behind [`blocked`]: whether `rung` is taken from `local`, for a
/// path whose IP remote is `remote` (`None` for a path that has no IP address).
/// A block of one remote endpoint ([`block_rung_to`]) is not read here: use
/// [`is_blocked_to`] for a path that may have one.
///
/// # Panics
///
/// Panics if another thread panicked while it held a block table.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, is_blocked};
///
/// # fn demo(local: iroh::EndpointId) -> bool {
/// is_blocked(local, Rung::Ip, None)
/// # }
/// ```
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn is_blocked(local: iroh::EndpointId, rung: Rung, remote: Option<net::SocketAddr>) -> bool {
    is_blocked_to(local, rung, remote, None)
}

/// [`is_blocked`], and also the blocks of one remote endpoint
/// ([`block_rung_to`]): `remote_id` is the endpoint a `WebRTC` or a relay path
/// leads to (`None` for a path that has no single remote id).
///
/// # Panics
///
/// Panics if another thread panicked while it held a block table.
///
/// # Examples
///
/// It reads the block list of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, is_blocked_to};
///
/// # fn demo(local: iroh::EndpointId, remote: iroh::EndpointId) -> bool {
/// is_blocked_to(local, Rung::Ip, None, Some(remote))
/// # }
/// ```
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn is_blocked_to(
    local: iroh::EndpointId,
    rung: Rung,
    remote: Option<net::SocketAddr>,
    remote_id: Option<iroh::EndpointId>,
) -> bool {
    let rung_blocked: bool = {
        let guard = RUNGS_BLOCKED.lock().expect("rung blocks");
        guard
            .as_ref()
            .is_some_and(|blocks| blocks.contains(&(local, rung)))
    };
    if rung_blocked {
        return true;
    }
    let remote_blocked = remote_id.is_some_and(|remote_id| {
        let guard = RUNGS_BLOCKED_TO.lock().expect("rung blocks to a remote");
        guard
            .as_ref()
            .is_some_and(|blocks| blocks.contains(&(local, rung, remote_id)))
    });
    if remote_blocked {
        return true;
    }
    rung == Rung::Ip
        && (IP_BLOCKED.load(Ordering::SeqCst)
            || remote.is_some_and(|remote| {
                let guard = IP_BLOCKED_TO.lock().expect("ip blocks");
                let ports = guard.as_ref().and_then(|blocks| blocks.get(&local));
                ports.is_some_and(|set| set.contains(&remote.port()))
            }))
}

/// Tests only: while set, no IP path is selected, in every endpoint of the
/// process. iroh re-runs selection on its path-stat updates, so a live
/// connection leaves UDP within a few seconds and returns once it is cleared.
///
/// # Examples
///
/// It changes the block list of the test hooks for the whole process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::block_ip_paths;
///
/// # fn demo() {
/// block_ip_paths(false);
/// # }
/// ```
#[cfg(feature = "test-hooks")]
pub fn block_ip_paths(
    // true blocks every IP path, false clears the block
    blocked: bool,
) {
    IP_BLOCKED.store(blocked, Ordering::SeqCst);
}

/// Tests only: from now on the endpoint `local` selects no IP path whose remote
/// port is one of `remote_ports`. It replaces the node's earlier set, and an
/// empty set clears it. Another node of the process is not affected, which is
/// what lets a test cut one group of nodes from another while each group keeps
/// its own links. iroh tells a selector the remote *address* of a path, not the
/// remote endpoint, so the key is the port: every address one endpoint binds
/// shares it, and a test names the ports of the endpoints it means.
///
/// # Panics
///
/// Panics if another thread panicked while it held the block table.
///
/// # Examples
///
/// It changes the block list of the test hooks for the whole process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::block_ip_to;
///
/// # fn demo(local: iroh::EndpointId) {
/// block_ip_to(local, [7000]);
/// # }
/// ```
#[cfg(feature = "test-hooks")]
pub fn block_ip_to(local: iroh::EndpointId, remote_ports: impl IntoIterator<Item = u16>) {
    let ports: HashSet<u16> = remote_ports.into_iter().collect();
    let mut blocks = IP_BLOCKED_TO.lock().expect("ip blocks");
    let blocks = blocks.get_or_insert_with(HashMap::new);
    if ports.is_empty() {
        blocks.remove(&local);
    } else {
        blocks.insert(local, ports);
    }
}

/// Tests only: while `blocked`, the endpoint `local` selects no path of `rung`,
/// whoever the remote is. With [`block_ip_to`] it takes a node down the ladder
/// one rung at a time, so a test can show each step. A path of a custom
/// transport carries no remote id that a selector can read for multihop, so a
/// rung is blocked whole, and another node of the process is not affected.
///
/// # Panics
///
/// Panics if another thread panicked while it held the block table.
///
/// # Examples
///
/// It changes the block list of the test hooks for the whole process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, block_rung};
///
/// # fn demo(local: iroh::EndpointId) {
/// block_rung(local, Rung::Ip, false);
/// # }
/// ```
#[cfg(feature = "test-hooks")]
pub fn block_rung(
    local: iroh::EndpointId,
    rung: Rung,
    // true blocks the rung for local, false clears it
    blocked: bool,
) {
    let mut blocks = RUNGS_BLOCKED.lock().expect("rung blocks");
    let blocks = blocks.get_or_insert_with(HashSet::new);
    if blocked {
        blocks.insert((local, rung));
    } else {
        blocks.remove(&(local, rung));
    }
}

/// Tests only: while `blocked`, the endpoint `local` selects no path of `rung`
/// that leads to the endpoint `remote`, and keeps the same rung to every other
/// remote. It is [`block_rung`] for one remote, which a test needs to cut one pair
/// of a group of nodes. Only a `WebRTC` path and a relay path name their remote in
/// their address ([`remote_id_of`]), so only those two rungs are blocked this way:
/// the block of any other rung has no effect.
///
/// # Panics
///
/// Panics if another thread panicked while it held the block table.
///
/// # Examples
///
/// It changes the block list of the test hooks for the whole process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{Rung, block_rung_to};
///
/// # fn demo(local: iroh::EndpointId, remote: iroh::EndpointId) {
/// block_rung_to(local, Rung::Ip, remote, false);
/// # }
/// ```
#[cfg(feature = "test-hooks")]
pub fn block_rung_to(
    local: iroh::EndpointId,
    rung: Rung,
    remote: iroh::EndpointId,
    // true blocks the rung from local to remote, false clears it
    blocked: bool,
) {
    let mut blocks = RUNGS_BLOCKED_TO.lock().expect("rung blocks to a remote");
    let blocks = blocks.get_or_insert_with(HashSet::new);
    if blocked {
        blocks.insert((local, rung, remote));
    } else {
        blocks.remove(&(local, rung, remote));
    }
}

/// Undo a transmit's GSO batching: one QUIC datagram per element.
///
/// An empty payload still yields one empty datagram rather than none, so a
/// keep-alive is not silently dropped. The three call sites this replaces did
/// not agree on that: two computed `contents.len().max(1)` as the segment size,
/// which turns an empty transmit into zero datagrams, while the third special-
/// cased it. A real QUIC packet is never empty, so the divergence was
/// unreachable — but it is the kind that outlives the copy it came from.
///
/// # Examples
///
/// It reads the transmit of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::datagrams;
/// use iroh::endpoint::transports::Transmit;
///
/// # fn demo<'a>(transmit: &'a Transmit<'a>) -> usize {
/// datagrams(transmit).count()
/// # }
/// ```
pub fn datagrams<'a>(transmit: &'a Transmit<'a>) -> impl Iterator<Item = &'a [u8]> {
    split_segments(transmit.contents, transmit.segment_size)
}

/// [`datagrams`] over the two fields it reads. Separate because `Transmit` has
/// a private field, so it cannot be built outside iroh and the rule above
/// would otherwise have no test at all.
///
/// # Examples
///
/// A buffer splits into segments of the given size, and the last one may be shorter.
///
/// ```
/// use habilis_network_iroh_transport_util::split_segments;
///
/// let parts: Vec<&[u8]> = split_segments(b"abcdef", Some(2)).collect();
/// assert_eq!(parts, [b"ab".as_slice(), b"cd", b"ef"]);
/// ```
pub fn split_segments(contents: &[u8], segment_size: Option<usize>) -> impl Iterator<Item = &[u8]> {
    let segment = segment_size.unwrap_or(contents.len()).max(1);
    let mut keepalive = contents.is_empty();
    contents.chunks(segment).chain(iter::from_fn(move || {
        keepalive.then(|| {
            keepalive = false;
            &contents[0..0]
        })
    }))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use iroh::endpoint::PathStats;
    use iroh::endpoint::transports::{Addr, FourTuple, PathSelectionData};

    use super::{best_of, climb, custom_rung};

    /// An IP path to `port` on the host.
    fn ip(port: u16) -> FourTuple {
        let remote: SocketAddr = ([127, 0, 0, 1], port).into();
        FourTuple::from_remote(Addr::Ip(remote))
    }

    /// The candidate for `tuple` with this RTT; `None` is a path with no stats yet.
    fn candidate(tuple: &FourTuple, rtt_ms: Option<u64>) -> PathSelectionData<'_> {
        let stats = rtt_ms.map(|rtt| {
            // PathStats is non-exhaustive: build it from the default.
            let mut stats = PathStats::default();
            stats.rtt = Duration::from_millis(rtt);
            stats
        });
        PathSelectionData::for_test(tuple, stats)
    }

    /// The selected tuple of `paths`, given the current one.
    fn chosen<'a>(
        current: Option<&FourTuple>,
        paths: &'a [PathSelectionData<'a>],
    ) -> Option<&'a FourTuple> {
        best_of(current, paths.iter()).map(PathSelectionData::network_path)
    }

    /// The current path stays while no other path of its rung is faster by the threshold: 2 paths of one host
    /// differ by a millisecond of noise, and a flip closes the path that was just opened.
    #[test]
    fn the_current_path_stays_when_another_is_only_a_little_faster() {
        let _guard = ::habilis_network_test_tracing::init();
        let (slow, fast) = (ip(1), ip(2));
        let paths = [candidate(&slow, Some(10)), candidate(&fast, Some(9))];

        let kept = chosen(Some(&slow), &paths);

        assert_eq!(
            kept,
            Some(&slow),
            "1 ms of gain does not move the selection"
        );
    }

    /// A path that is faster by more than the threshold takes the selection.
    #[test]
    fn a_path_that_is_much_faster_takes_the_selection() {
        let _guard = ::habilis_network_test_tracing::init();
        let (slow, fast) = (ip(1), ip(2));
        let paths = [candidate(&slow, Some(30)), candidate(&fast, Some(10))];

        let taken = chosen(Some(&slow), &paths);

        assert_eq!(taken, Some(&fast), "20 ms of gain moves the selection");
    }

    /// With no current path in the list, the best path is taken, and the current path that is gone costs nothing.
    #[test]
    fn the_best_path_is_taken_when_the_current_path_is_gone() {
        let _guard = ::habilis_network_test_tracing::init();
        let (gone, near, far) = (ip(1), ip(2), ip(3));
        let paths = [candidate(&near, Some(5)), candidate(&far, Some(8))];

        let taken = chosen(Some(&gone), &paths);

        assert_eq!(
            taken,
            Some(&near),
            "the lowest RTT of the paths that remain"
        );
    }

    /// A current path with no stats yet stays: it is the path in use, and it gets measured next.
    #[test]
    fn a_current_path_with_no_stats_stays() {
        let _guard = ::habilis_network_test_tracing::init();
        let (fresh, measured) = (ip(1), ip(2));
        let paths = [candidate(&fresh, None), candidate(&measured, Some(1))];

        let kept = chosen(Some(&fresh), &paths);

        assert_eq!(kept, Some(&fresh), "an unmeasured current path is kept");
    }

    /// The bug: 3 IP paths to one host, whose RTTs move by 1 ms from one event to the next, over 50 events. The
    /// selection is made once and changes 0 times after that. (The old rule changed it at almost each event.)
    #[test]
    fn the_selection_does_not_flap_over_paths_of_one_host_with_noisy_rtts() {
        let _guard = ::habilis_network_test_tracing::init();
        let tuples = [ip(1), ip(2), ip(3)];
        let mut current: Option<FourTuple> = None;
        let mut changes = 0_u32;

        for event in 0..50_u64 {
            let paths: Vec<PathSelectionData<'_>> = tuples
                .iter()
                .zip(0_u64..)
                .map(|(tuple, index)| candidate(tuple, Some(10 + (event + index) % 3)))
                .collect();
            let next = chosen(current.as_ref(), &paths).cloned();
            if next != current && current.is_some() {
                changes += 1;
            }
            current = next;
        }

        assert_eq!(
            changes, 0,
            "the selection changed {changes} times after the first choice"
        );
    }

    /// The hysteresis is inside a rung. A connection that is on the relay (a lower rung) climbs at once to a
    /// path of a higher rung: the current path is not in that rung, so it holds nothing.
    #[test]
    fn a_current_path_on_a_lower_rung_does_not_hold_the_ladder_down() {
        let _guard = ::habilis_network_test_tracing::init();
        let url: iroh::RelayUrl = "https://relay.example/".parse().expect("a relay URL");
        let relay = FourTuple::from_remote(Addr::Relay(
            url,
            iroh::EndpointId::from_bytes(&[0u8; 32]).expect("an id"),
        ));
        let direct = ip(7);
        let paths = [candidate(&relay, Some(1)), candidate(&direct, Some(40))];

        let climbed = climb(Some(&relay), &paths, custom_rung, |_, _| true);

        assert_eq!(
            climbed.map(PathSelectionData::network_path),
            Some(&direct),
            "a direct path beats the relay whatever the RTT"
        );
    }
}
