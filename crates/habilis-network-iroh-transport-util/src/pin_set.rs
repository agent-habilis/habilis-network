//! The peers that a node reaches only through multihop.
//!
//! A node at its cap of direct connections reaches a new peer through a connected peer. That
//! connection is pinned: its paths are multihop paths and no other. iroh keeps one set of paths per
//! remote, so the rule lives in the path selector, which reads the pins of its own endpoint here.
//!
//! A selector does not know its remote: `PathSelectionContext` of iroh carries no endpoint id. A
//! multihop path names it, because its address is the application id of the remote
//! ([`multihop_remote_of`]), and so does a relay or a `WebRTC` path, so a selector finds the remote
//! of a set of paths from any of them. A set with an IP path alone names nobody.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use iroh::EndpointId;
use iroh::endpoint::transports::{Addr, FourTuple, PathSelectionData};

use crate::rung::{MULTIHOP_TRANSPORT_ID, Rung, climb, remote_id_of};

type Pins = Mutex<Option<HashMap<EndpointId, HashSet<EndpointId>>>>;

/// The pins of each local endpoint of the process. A process holds several nodes in a test, so the
/// table is keyed by the endpoint that a selector serves, as the tables of the test hooks are.
static PINS: Pins = Mutex::new(None);

/// Pin `remote` on `local`: while pinned, the selector of `local` selects only a multihop path to
/// `remote`.
///
/// # Panics
///
/// Panics if another thread panicked while it held the table.
///
/// # Examples
///
/// It changes the table of the whole process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::pin;
///
/// # fn demo(local: iroh::EndpointId, remote: iroh::EndpointId) {
/// pin(local, remote);
/// # }
/// ```
pub fn pin(local: EndpointId, remote: EndpointId) {
    let mut table = PINS.lock().expect("pin table");
    table
        .get_or_insert_with(HashMap::new)
        .entry(local)
        .or_default()
        .insert(remote);
}

/// Release the pin of `remote` on `local`.
///
/// # Panics
///
/// Panics if another thread panicked while it held the table.
///
/// # Examples
///
/// It changes the table of the whole process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::unpin;
///
/// # fn demo(local: iroh::EndpointId, remote: iroh::EndpointId) {
/// unpin(local, remote);
/// # }
/// ```
pub fn unpin(local: EndpointId, remote: EndpointId) {
    let mut table = PINS.lock().expect("pin table");
    if let Some(pins) = table.as_mut().and_then(|table| table.get_mut(&local)) {
        pins.remove(&remote);
    }
}

/// Whether `remote` is pinned on `local`.
///
/// # Panics
///
/// Panics if another thread panicked while it held the table.
///
/// # Examples
///
/// It reads the table of the whole process, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::is_pinned;
///
/// # fn demo(local: iroh::EndpointId, remote: iroh::EndpointId) -> bool {
/// is_pinned(local, remote)
/// # }
/// ```
#[must_use]
pub fn is_pinned(local: EndpointId, remote: EndpointId) -> bool {
    let table = PINS.lock().expect("pin table");
    let Some(pins) = table.as_ref().and_then(|table| table.get(&local)) else {
        return false;
    };
    pins.contains(&remote)
}

/// The endpoint at the end of a multihop address, or `None` for any other address.
///
/// The address of a multihop path holds the 32 bytes of the application id of the remote and nothing
/// more. The multihop crate writes this form, and a test of that crate keeps the two in step.
///
/// # Examples
///
/// An address of another transport names no remote this way.
///
/// ```
/// use habilis_network_iroh_transport_util::multihop_remote_of;
/// use iroh::endpoint::transports::Addr;
///
/// let ip = Addr::Ip(([127, 0, 0, 1], 9).into());
/// assert_eq!(multihop_remote_of(&ip), None, "an IP address has no route");
/// ```
#[must_use]
pub fn multihop_remote_of(address: &Addr) -> Option<EndpointId> {
    let Addr::Custom(custom) = address else {
        return None;
    };
    if custom.id() != MULTIHOP_TRANSPORT_ID {
        return None;
    }
    let bytes: [u8; 32] = custom.data().try_into().ok()?;
    EndpointId::from_bytes(&bytes).ok()
}

/// Whether the paths of one remote belong to a pinned peer of `local`: a path in the set names a
/// pinned remote. A multihop path ends at its remote, and a relay or a `WebRTC` path names it, so
/// the pin holds when the multihop path of the set is gone and a direct path is left.
///
/// # Panics
///
/// Panics if another thread panicked while it held the table.
///
/// # Examples
///
/// It reads the paths of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::pinned_in;
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo(local: iroh::EndpointId, paths: &[PathSelectionData<'_>]) -> bool {
/// pinned_in(local, paths)
/// # }
/// ```
#[must_use]
pub fn pinned_in(local: EndpointId, paths: &[PathSelectionData<'_>]) -> bool {
    paths.iter().any(|path| {
        let address = path.network_path().remote();
        let remote = multihop_remote_of(&address).or_else(|| remote_id_of(&address));
        remote.is_some_and(|remote| is_pinned(local, remote))
    })
}

/// [`climb`] for a selector of `local`: when the paths belong to a pinned peer, only a multihop path
/// is usable. `usable` is the rule of the selector for the rest, such as a path that a test took.
///
/// # Panics
///
/// Panics if another thread panicked while it held the pin table.
///
/// # Examples
///
/// It reads the path selection of a live connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::{climb_pinned, custom_rung};
/// use iroh::endpoint::transports::PathSelectionData;
///
/// # fn demo<'a>(local: iroh::EndpointId, paths: &'a [PathSelectionData<'a>]) -> Option<&'a PathSelectionData<'a>> {
/// climb_pinned(local, None, paths, custom_rung, |_rung, _path| true)
/// # }
/// ```
#[must_use]
pub fn climb_pinned<'a>(
    local: EndpointId,
    current: Option<&FourTuple>,
    paths: &'a [PathSelectionData<'a>],
    custom: impl Fn(u64) -> Rung,
    usable: impl Fn(Rung, &PathSelectionData<'_>) -> bool,
) -> Option<&'a PathSelectionData<'a>> {
    let pinned = pinned_in(local, paths);
    climb(current, paths, custom, |rung, path| {
        pin_allows(pinned, rung) && usable(rung, path)
    })
}

/// Whether a path of `rung` can carry a connection that is `pinned`: a pinned connection takes the
/// multihop rung only.
///
/// # Examples
///
/// A pinned connection refuses an IP path, and an unpinned one keeps every rung.
///
/// ```
/// use habilis_network_iroh_transport_util::{Rung, pin_allows};
///
/// assert!(!pin_allows(true, Rung::Ip), "a pinned connection refuses IP");
/// assert!(pin_allows(true, Rung::Multihop), "a pinned connection takes multihop");
/// assert!(pin_allows(false, Rung::Ip), "an unpinned connection keeps IP");
/// ```
#[must_use]
pub fn pin_allows(
    // Whether the connection is pinned to multihop.
    pinned: bool,
    rung: Rung,
) -> bool {
    !pinned || rung == Rung::Multihop
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use iroh::endpoint::transports::{Addr, FourTuple, PathSelectionData};
    use iroh_base::CustomAddr;

    use super::{climb_pinned, is_pinned, pin, pin_allows, unpin};
    use crate::{MULTIHOP_TRANSPORT_ID, Rung, WEBRTC_TRANSPORT_ID, custom_rung};

    fn node(seed: u8) -> iroh::EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// The address of the last of `hops`, in the form that the multihop crate writes: the 32 bytes of the
    /// application id of the destination, and nothing more. The earlier hops are not part of the address.
    fn route_to(hops: &[iroh::EndpointId]) -> Addr {
        let destination = hops.last().expect("a destination");
        Addr::Custom(CustomAddr::from_parts(
            MULTIHOP_TRANSPORT_ID,
            destination.as_bytes(),
        ))
    }

    fn rung_of_choice(tuples: &[FourTuple], local: iroh::EndpointId) -> Option<Rung> {
        let paths: Vec<PathSelectionData<'_>> = tuples
            .iter()
            .map(|tuple| PathSelectionData::for_test(tuple, None))
            .collect();
        let chosen = climb_pinned(local, None, &paths, custom_rung, |_rung, _path| true)?;
        Some(crate::rung_of(chosen, custom_rung))
    }

    #[test]
    fn a_pinned_peer_with_a_direct_path_stays_on_multihop() {
        let _guard = ::habilis_network_test_tracing::init();
        let (local, remote, relay_hop) = (node(51), node(52), node(53));
        let tuples = [
            FourTuple::from_remote(Addr::Ip(([192, 0, 2, 7], 4433).into())),
            FourTuple::from_remote(Addr::Custom(CustomAddr::from_parts(
                WEBRTC_TRANSPORT_ID,
                remote.as_bytes(),
            ))),
            FourTuple::from_remote(route_to(&[relay_hop, remote])),
        ];
        pin(local, remote);
        let unpinned = rung_of_choice(&tuples, node(54));
        let pinned = rung_of_choice(&tuples, local);
        unpin(local, remote);
        assert_eq!(
            unpinned,
            Some(Rung::Ip),
            "control: a node with no pin takes the direct IP path"
        );
        assert_eq!(
            pinned,
            Some(Rung::Multihop),
            "a pinned peer stays on multihop though an IP and a WebRTC path are usable"
        );
    }

    #[test]
    fn a_pinned_peer_stays_on_multihop_when_only_direct_paths_are_listed() {
        let _guard = ::habilis_network_test_tracing::init();
        let (local, remote) = (node(55), node(56));
        let tuples = [
            FourTuple::from_remote(Addr::Ip(([192, 0, 2, 8], 4433).into())),
            FourTuple::from_remote(Addr::Custom(CustomAddr::from_parts(
                WEBRTC_TRANSPORT_ID,
                remote.as_bytes(),
            ))),
        ];
        pin(local, remote);
        let chosen = rung_of_choice(&tuples, local);
        unpin(local, remote);
        assert_eq!(
            chosen, None,
            "a pinned peer with no multihop path takes no direct path"
        );
    }

    /// The limit of the pin in the selector. iroh gives a selector no remote id, and an IP address
    /// names none, so a set of paths that holds only IP paths is not recognized as pinned. A pinned
    /// dial takes the route alone as its address, so a set holds an IP path only when a lookup
    /// adds one. The relay and a `WebRTC` path name the remote, and any of them pins the set.
    #[test]
    fn a_set_of_ip_paths_alone_names_no_remote_and_is_not_pinned() {
        let _guard = ::habilis_network_test_tracing::init();
        let (local, remote) = (node(57), node(58));
        let tuples = [FourTuple::from_remote(Addr::Ip(
            ([192, 0, 2, 9], 4433).into(),
        ))];
        pin(local, remote);
        let chosen = rung_of_choice(&tuples, local);
        unpin(local, remote);
        assert_eq!(
            chosen,
            Some(Rung::Ip),
            "a set with an IP path alone names nobody: the pin cannot hold it"
        );
    }

    #[test]
    fn a_pin_holds_for_its_local_endpoint_and_remote_only() {
        let _guard = ::habilis_network_test_tracing::init();
        let (local, other, remote, bystander) = (node(41), node(42), node(43), node(44));
        pin(local, remote);
        assert!(is_pinned(local, remote), "the pinned remote");
        assert!(!is_pinned(local, bystander), "another remote");
        assert!(!is_pinned(other, remote), "another local endpoint");
        unpin(local, remote);
        assert!(!is_pinned(local, remote), "the pin is released");
    }

    #[test]
    fn a_pinned_connection_takes_the_multihop_rung_only() {
        let _guard = ::habilis_network_test_tracing::init();
        for rung in [
            Rung::Ip,
            Rung::WebRtc,
            Rung::Gossip,
            Rung::Relay,
            Rung::Other,
        ] {
            assert!(
                !pin_allows(true, rung),
                "a pinned connection refuses {rung:?}"
            );
        }
        assert!(
            pin_allows(true, Rung::Multihop),
            "multihop is the pinned rung"
        );
        for rung in Rung::LADDER {
            assert!(
                pin_allows(false, rung),
                "an unpinned connection keeps {rung:?}"
            );
        }
    }
}
