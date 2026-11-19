use std::net::{Ipv4Addr, SocketAddr};

use iroh::address_lookup::memory;
use iroh::{Endpoint, EndpointAddr, RelayUrl};

use crate::lookup::{add_peer_addr, relay_ladder, replace_peer_addr};
use crate::util::clock::Instant;

use super::{RendezvousParams, RungRead, RungWatch, rung_is_busy};

/// The rendezvous's **dialable** address: the id plus somewhere to reach it. It names every place
/// where the beacon can be. What a member registers for the id is a part of it, see
/// [`rendezvous_addr_offering`], and what a rival probe dials is all of it: the probe asks "is
/// anyone serving the identity anywhere on the ladder?", and a rung that is not offered to
/// the dials of the member can still hold the beacon.
///
/// - Private (a non-empty ladder): every loopback rung. A member does not register them all: the
///   mesh shares a host with other meshes, and the port of a rung that nobody has proven to be ours
///   can be the rung of another mesh, whose beacon answers a dial with its own identity.
/// - Public: every rung of the relay choice of the member, and `bootstrap_relay`. The beacon homes
///   on one rung of the ladder (`beacon_lookups`), and a dial reaches it by the relay it homes
///   on. The rung that a member reads as the first reachable one is the outcome of a walk with a
///   10 s probe per rung. A member on a loaded host loses that race on rung 0, and a peer on a quiet
///   host does not, so two members can read two rungs, and an address with one rung makes each
///   dial a rung where the other is not. An address with every rung reaches the beacon on
///   whichever rung it homes. A dial opens at most one relay connection per rung, and does not wait
///   for the slowest rung.
/// - `None`: relay disabled, no ladder, or a walk that found no reachable rung
///   (`bootstrap_relay` is `None`), so there is nothing to name and only mDNS/DHT can resolve the
///   id. The probe then reads the rendezvous as held when no lookup can resolve it, and never
///   as free blind.
///
/// Two causes of the split are open: the probe of 10 s per rung (a retry of rung 0 before the walk
/// skips it would keep a loaded host on rung 0), and the move of a peer endpoint back and forth
/// between rungs (about once a minute in the logs of a loaded host). This address does not depend on
/// either.
pub(crate) fn rendezvous_addr(params: &RendezvousParams) -> Option<EndpointAddr> {
    let mut address = EndpointAddr::new(params.id);
    if !params.bind_ports.is_empty() {
        for &port in &params.bind_ports {
            address = address.with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
        return Some(address);
    }
    // No rung from the walk: the beacon and the prober of this member have no relay
    // (`beacon_lookups`), so an address of relays is one that they cannot dial.
    let bootstrap = params.bootstrap_relay.clone()?;
    let mut rungs: Vec<RelayUrl> = relay_ladder(&params.lookups.relay_lookup).collect();
    rungs.push(bootstrap);
    for rung in rungs {
        address = address.with_relay_url(rung);
    }
    Some(address)
}

/// [`rendezvous_addr`] with only the loopback rungs of `offered`: the address that a member
/// registers for the rendezvous id ([`RungWatch::offered_rungs`]). A rung that was never read as
/// ours is not in it, because another mesh whose ladder shares the port can hold it, and the
/// dial of the id ends on the first answer of a listener of another identity. An address of
/// another kind (a relay rung) stays.
pub(crate) fn rendezvous_addr_offering(
    params: &RendezvousParams,
    offered: &[u16],
) -> Option<EndpointAddr> {
    rendezvous_addr(params).map(|address| keeping_rungs(address, |port| offered.contains(&port)))
}

/// The rendezvous id at one rung of the loopback ladder.
pub(crate) fn rendezvous_holder_addr(params: &RendezvousParams, port: u16) -> EndpointAddr {
    EndpointAddr::new(params.id).with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// `addr` without the IP addresses whose port `keep` refuses. An address of another kind stays.
pub(crate) fn keeping_rungs(address: EndpointAddr, keep: impl Fn(u16) -> bool) -> EndpointAddr {
    EndpointAddr::from_parts(
        address.id,
        address.addrs.into_iter().filter(|transport| {
            if let iroh::TransportAddr::Ip(socket) = transport {
                keep(socket.port())
            } else {
                true
            }
        }),
    )
}

/// The index in `ladder` of the rung that `endpoint` is bound on, `None` when it is bound on none of
/// them.
pub(crate) fn rung_of(endpoint: &Endpoint, ladder: &[u16]) -> Option<usize> {
    // A browser binds no socket, so it holds no rung of a loopback ladder.
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (endpoint, ladder);
        None
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let bound: Vec<u16> = endpoint
            .bound_sockets()
            .iter()
            .map(SocketAddr::port)
            .collect();
        ladder.iter().position(|port| bound.contains(port))
    }
}

/// Take the rungs that `forget` names out of the addresses of the rendezvous id: out of the book,
/// and out of what the endpoint knows. A dial of the id tries every address that the endpoint
/// knows for it, and a listener of another identity on one of them (any process on the host can
/// hold a rung) answers with its own identity, or with an alert for an ALPN that it does not
/// serve, and the dial fails as a whole, on every retry.
pub(crate) async fn forget_rungs(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    forget: impl Fn(u16) -> bool,
) {
    let forgotten: EndpointAddr = params
        .bind_ports
        .iter()
        .copied()
        .filter(|&port| forget(port))
        .fold(EndpointAddr::new(params.id), |address, port| {
            address.with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        });
    if forgotten.addrs.is_empty() {
        return;
    }
    if let Some(info) = peer_book.get_endpoint_info(params.id) {
        replace_peer_addr(
            peer_book,
            keeping_rungs(info.into_endpoint_addr(), |port| !forget(port)),
        );
    }
    peer.remove_endpoint_addr(forgotten).await;
}

/// The rung `port` serves our beacon: the endpoint reaches the rendezvous id there and nowhere else
/// on the ladder, and the book names that rung. The endpoint is told too, because it does not read
/// the book again for an id that it knows.
pub(crate) async fn settle_on_rung(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    port: u16,
) {
    forget_rungs(params, peer, peer_book, |rung| rung != port).await;
    let holder = rendezvous_holder_addr(params, port);
    add_peer_addr(peer_book, holder.clone());
    if let Err(error) = peer.add_endpoint_addr(holder).await {
        tracing::debug!(target: "habilis_network::beacon", %error, port, "the endpoint did not take the rung of the holder");
    }
}

/// Read the ladder without claiming a rung: a member that knows a holder skips the walk, and the
/// rung of the holder that it read last may be dead or foreign when the holder moved (it shed or
/// yielded, and another member claimed a rung). The busy rungs are asked, the reports land on the
/// loop, which calls this again, and the rung that reads as ours is settled on.
pub(crate) async fn refresh_holder_rung(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    rungs: &mut RungWatch,
) {
    let now = Instant::now();
    for &port in &params.bind_ports {
        match rungs.reading(port, now) {
            RungRead::Ours => {
                rungs.clear_foreign(port);
                settle_on_rung(params, peer, peer_book, port).await;
                return;
            }
            RungRead::Unknown if rung_is_busy(port) => {
                rungs.ask(params, peer.id(), port, false);
            }
            RungRead::Unknown
            | RungRead::Foreign
            | RungRead::Silent
            | RungRead::SilentLongEnough => {}
        }
    }
}

/// The entry of the rendezvous id in the book of the member endpoint after a claim: the direct
/// addresses of the new holder, and what the mesh registered for the id by itself, a relay rung or
/// the loopback ladder ([`rendezvous_addr`]). The addresses of a former holder are not in it. A
/// member whose IP transports are cleared dials the bare id and can use only the registered part.
/// A claim on a ladder does not write this entry: it settles on the rung that the beacon bound.
pub(crate) fn holder_entry(
    holder: EndpointAddr,
    params: &RendezvousParams,
    offered: &[u16],
) -> EndpointAddr {
    match rendezvous_addr_offering(params, offered) {
        Some(registered) => {
            EndpointAddr::from_parts(holder.id, holder.addrs.into_iter().chain(registered.addrs))
        }
        None => holder,
    }
}
