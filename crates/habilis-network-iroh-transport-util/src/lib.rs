//! The two pieces both custom iroh transports need and neither can host.
//!
//! `habilis-network-iroh-webrtc-transport` and `habilis-network-iroh-multihop-transport` are
//! deliberately standalone: neither depends on the other, and neither depends
//! on `habilis-network-util` — so a shared helper has nowhere else to live.
//!
//! That is the whole justification for a crate this small. Unlike the two
//! crates recently folded back into `habilis-network-protocol`, this one is not
//! isolating a dependency it could have inherited; it exists because there is
//! no other sharing point between two otherwise-independent crates. It adds no
//! external dependency — `iroh` is already in both manifests.

use std::time::Duration;

use iroh::endpoint::transports::{Addr, PathSelectionData, Transmit};

/// The lowest-RTT path in `iter`.
///
/// A path whose stats are not readable yet — freshly added, not yet validated —
/// still counts as a candidate, so an unmeasured path is never skipped in
/// favour of the fallback it is meant to replace. That is the load-bearing
/// half: without it a new direct path loses to the relay forever, because it
/// never gets the traffic that would measure it.
#[must_use]
pub fn best_of<'a>(
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

/// One rung of the path ladder, best first: a direct IP path, then `WebRTC`, then
/// multihop, then the relay. A node with every rung climbs to the highest one it
/// has, and falls one rung when that path goes away.
///
/// The order is the declaration order, and both selectors take it from here, so
/// that it does not depend on which transports an endpoint has installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rung {
    Ip,
    WebRtc,
    Multihop,
    Relay,
    /// A custom transport that the caller does not name, below every other rung.
    Other,
}

impl Rung {
    /// Every rung, best first.
    pub const LADDER: [Self; 5] = [
        Self::Ip,
        Self::WebRtc,
        Self::Multihop,
        Self::Relay,
        Self::Other,
    ];
}

/// The rung `path` stands on. `custom` names the rung of a custom transport by
/// its id. Each selector knows its own transport's id and not the other's, so it
/// names its own and gives the other one by elimination.
#[must_use]
pub fn rung_of(path: &PathSelectionData<'_>, custom: impl Fn(u64) -> Rung) -> Rung {
    match path.network_path().remote() {
        Addr::Ip(_) => Rung::Ip,
        Addr::Relay(..) => Rung::Relay,
        Addr::Custom(addr) => custom(addr.id()),
    }
}

/// The rung a node stands on: the highest rung that is `allowed` and has an
/// `available` path, or `None`. Pure. The ladder lives here and nowhere else:
/// both selectors choose through it, and a test that asks where a node should
/// stand asks it too.
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
#[must_use]
pub fn climb<'a>(
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
    best_of(paths.iter().filter(|path| usable_on(rung, path)))
}

/// Whether a test took the path `path` away from the node `local`, on `rung`:
/// the one table that every selector of this workspace reads. Without
/// `test-hooks` it is always `false`.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn blocked(local: iroh::EndpointId, rung: Rung, path: &PathSelectionData<'_>) -> bool {
    let remote = match path.network_path().remote() {
        Addr::Ip(remote) => Some(remote),
        Addr::Relay(..) | Addr::Custom(_) => None,
    };
    is_blocked(local, rung, remote)
}

/// Whether a test took the path `path` away from the node `local`, on `rung`.
/// Without `test-hooks` it is always `false`.
#[cfg(not(feature = "test-hooks"))]
#[must_use]
pub fn blocked(_local: iroh::EndpointId, _rung: Rung, _path: &PathSelectionData<'_>) -> bool {
    false
}

#[cfg(feature = "test-hooks")]
static IP_BLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "test-hooks")]
type PortBlocks = std::sync::Mutex<
    Option<std::collections::HashMap<iroh::EndpointId, std::collections::HashSet<u16>>>,
>;

#[cfg(feature = "test-hooks")]
static IP_BLOCKED_TO: PortBlocks = std::sync::Mutex::new(None);

#[cfg(feature = "test-hooks")]
static RUNGS_BLOCKED: std::sync::Mutex<
    Option<std::collections::HashSet<(iroh::EndpointId, Rung)>>,
> = std::sync::Mutex::new(None);

/// The pure table behind [`blocked`]: whether `rung` is taken from `local`, for a
/// path whose IP remote is `remote` (`None` for a path that has no IP address).
///
/// # Panics
///
/// Panics if another thread panicked while it held a block table.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn is_blocked(
    local: iroh::EndpointId,
    rung: Rung,
    remote: Option<std::net::SocketAddr>,
) -> bool {
    let rung_blocked = RUNGS_BLOCKED
        .lock()
        .expect("rung blocks")
        .as_ref()
        .is_some_and(|blocks| blocks.contains(&(local, rung)));
    if rung_blocked {
        return true;
    }
    rung == Rung::Ip
        && (IP_BLOCKED.load(std::sync::atomic::Ordering::SeqCst)
            || remote.is_some_and(|remote| {
                IP_BLOCKED_TO
                    .lock()
                    .expect("ip blocks")
                    .as_ref()
                    .and_then(|blocks| blocks.get(&local))
                    .is_some_and(|ports| ports.contains(&remote.port()))
            }))
}

/// Tests only: while set, no IP path is selected, in every endpoint of the
/// process. iroh re-runs selection on its path-stat updates, so a live
/// connection leaves UDP within a few seconds and returns once it is cleared.
#[cfg(feature = "test-hooks")]
pub fn block_ip_paths(blocked: bool) {
    IP_BLOCKED.store(blocked, std::sync::atomic::Ordering::SeqCst);
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
#[cfg(feature = "test-hooks")]
pub fn block_ip_to(local: iroh::EndpointId, remote_ports: impl IntoIterator<Item = u16>) {
    let ports: std::collections::HashSet<u16> = remote_ports.into_iter().collect();
    let mut blocks = IP_BLOCKED_TO.lock().expect("ip blocks");
    let blocks = blocks.get_or_insert_with(std::collections::HashMap::new);
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
#[cfg(feature = "test-hooks")]
pub fn block_rung(local: iroh::EndpointId, rung: Rung, blocked: bool) {
    let mut blocks = RUNGS_BLOCKED.lock().expect("rung blocks");
    let blocks = blocks.get_or_insert_with(std::collections::HashSet::new);
    if blocked {
        blocks.insert((local, rung));
    } else {
        blocks.remove(&(local, rung));
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
pub fn datagrams<'a>(transmit: &'a Transmit<'a>) -> impl Iterator<Item = &'a [u8]> {
    split_segments(transmit.contents, transmit.segment_size)
}

/// [`datagrams`] over the two fields it reads. Separate because `Transmit` has
/// a private field, so it cannot be built outside iroh and the rule above
/// would otherwise have no test at all.
pub fn split_segments(contents: &[u8], segment_size: Option<usize>) -> impl Iterator<Item = &[u8]> {
    let segment = segment_size.unwrap_or(contents.len()).max(1);
    let mut keepalive = contents.is_empty();
    contents.chunks(segment).chain(std::iter::from_fn(move || {
        keepalive.then(|| {
            keepalive = false;
            &contents[0..0]
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_runs_from_ip_to_the_relay() {
        assert!(
            Rung::LADDER.is_sorted(),
            "the declaration order is the ladder"
        );
        assert!(Rung::Ip < Rung::WebRtc);
        assert!(Rung::WebRtc < Rung::Multihop, "multihop is below WebRTC");
        assert!(Rung::Multihop < Rung::Relay, "the relay is the last rung");
    }

    /// The pure ladder: over every set of allowed rungs and every set of
    /// available ones, the node stands on the best rung in both.
    #[test]
    fn the_expected_rung_is_the_best_rung_that_is_allowed_and_available() {
        let set = |mask: u8| move |rung: Rung| mask >> (rung as u8) & 1 == 1;
        for allowed in 0..32u8 {
            for available in 0..32u8 {
                let expected = Rung::LADDER
                    .into_iter()
                    .filter(|&rung| set(allowed)(rung) && set(available)(rung))
                    .min();
                assert_eq!(
                    expected_rung(set(allowed), set(available)),
                    expected,
                    "allowed {allowed:#07b}, available {available:#07b}"
                );
            }
        }
    }

    #[test]
    fn the_expected_rung_reads_as_the_ladder_does() {
        let all = |_: Rung| true;
        let only = |rungs: &'static [Rung]| move |rung: Rung| rungs.contains(&rung);
        assert_eq!(
            expected_rung(all, only(&[Rung::Relay, Rung::Ip])),
            Some(Rung::Ip)
        );
        assert_eq!(
            expected_rung(all, only(&[Rung::Relay, Rung::Multihop])),
            Some(Rung::Multihop)
        );
        // A rung that policy does not allow is passed over, however good.
        assert_eq!(
            expected_rung(
                only(&[Rung::Multihop, Rung::Relay]),
                only(&[Rung::Ip, Rung::WebRtc, Rung::Relay])
            ),
            Some(Rung::Relay)
        );
        assert_eq!(expected_rung(all, |_| false), None);
        assert_eq!(expected_rung(|_| false, all), None);
    }

    #[cfg(feature = "test-hooks")]
    fn node(seed: u8) -> iroh::EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// A block on IP ports of one node leaves the others alone, whatever rung or
    /// port they ask about.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn an_ip_port_block_takes_one_port_of_the_ip_rung_from_one_node() {
        let (blocked, other) = (node(11), node(12));
        let at = |port: u16| Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        block_ip_to(blocked, [4000, 4001]);
        assert!(is_blocked(blocked, Rung::Ip, at(4000)));
        assert!(is_blocked(blocked, Rung::Ip, at(4001)));
        assert!(!is_blocked(blocked, Rung::Ip, at(4002)), "another port");
        assert!(!is_blocked(other, Rung::Ip, at(4000)), "another node");
        assert!(!is_blocked(blocked, Rung::Relay, None), "another rung");
        block_ip_to(blocked, []);
        assert!(
            !is_blocked(blocked, Rung::Ip, at(4000)),
            "an empty set clears"
        );
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn a_rung_block_takes_one_whole_rung_from_one_node() {
        let (blocked, other) = (node(13), node(14));
        block_rung(blocked, Rung::Multihop, true);
        assert!(is_blocked(blocked, Rung::Multihop, None));
        assert!(!is_blocked(blocked, Rung::WebRtc, None), "another rung");
        assert!(!is_blocked(other, Rung::Multihop, None), "another node");
        block_rung(blocked, Rung::Multihop, false);
        assert!(!is_blocked(blocked, Rung::Multihop, None));
    }

    /// The property the three copies disagreed on.
    #[test]
    fn an_empty_transmit_still_yields_one_datagram() {
        let out: Vec<&[u8]> = split_segments(&[], None).collect();
        assert_eq!(out.len(), 1, "a keep-alive must not be dropped");
        assert!(out[0].is_empty());
    }

    #[test]
    fn a_batched_transmit_splits_on_the_segment_size() {
        let out: Vec<&[u8]> = split_segments(&[1, 2, 3, 4, 5], Some(2)).collect();
        assert_eq!(out, vec![&[1u8, 2][..], &[3, 4][..], &[5][..]]);
    }

    #[test]
    fn an_unbatched_transmit_is_one_datagram() {
        let out: Vec<&[u8]> = split_segments(&[1, 2, 3], None).collect();
        assert_eq!(out, vec![&[1u8, 2, 3][..]]);
    }

    /// A zero segment size must not divide by zero or spin.
    #[test]
    fn a_zero_segment_size_is_clamped() {
        let out: Vec<&[u8]> = split_segments(&[1, 2], Some(0)).collect();
        assert_eq!(out, vec![&[1u8][..], &[2][..]]);
    }
}
