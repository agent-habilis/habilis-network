use std::net::{Ipv4Addr, SocketAddr};

use iroh::address_lookup::memory;
use iroh::{Endpoint, EndpointAddr};

use crate::lookup::{add_peer_addr, replace_peer_addr};
use crate::util::clock::Instant;

use super::{RendezvousParams, RungRead, RungWatch, rung_is_busy};

/// The rendezvous's **dialable** address: the id plus somewhere to reach it.
///
/// One construction, two callers that must not drift — the hint a joiner
/// pre-registers on its peer endpoint (`daemon::setup::register_rendezvous`)
/// and the target `spawn_rival_probe` dials. They are the same address by
/// definition: the probe asks "is anyone serving the identity a joiner would
/// reach?", so asking it anywhere else answers a different question.
///
/// - Private (a non-empty ladder): every loopback rung, because iroh's
///   node-id dial reaches whichever rung our beacon actually bound.
/// - Public: `bootstrap_relay`, the single rung the beacon homes on
///   (`beacon_lookups`) — a relay-direct dial with no lookup round-trip.
/// - `None`: relay disabled and no ladder, so there is nothing to name and
///   only mDNS/DHT can resolve the id.
pub(crate) fn rendezvous_addr(params: &RendezvousParams) -> Option<EndpointAddr> {
    let mut address = EndpointAddr::new(params.id);
    if !params.bind_ports.is_empty() {
        for &port in &params.bind_ports {
            address = address.with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
        return Some(address);
    }
    Some(address.with_relay_url(params.bootstrap_relay.clone()?))
}

/// [`rendezvous_addr`] without the rungs of `withheld`: the address that a member registers for the
/// rendezvous id while those rungs are busy and not read as ours ([`RungWatch::withheld_rungs`]).
pub(crate) fn rendezvous_addr_without(
    params: &RendezvousParams,
    withheld: &[u16],
) -> Option<EndpointAddr> {
    rendezvous_addr(params).map(|address| keeping_rungs(address, |port| !withheld.contains(&port)))
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

/// The rungs of the ladder that somebody holds, read by a bind that fails: instant, no probe. A
/// member that starts does not know yet whether the holder is our beacon, so it keeps these out of
/// the book until a probe answers.
pub(crate) fn busy_rungs(params: &RendezvousParams) -> Vec<u16> {
    params
        .bind_ports
        .iter()
        .copied()
        .filter(|&port| rung_is_busy(port))
        .collect()
}

/// Put the rung `port` back among the addresses of the rendezvous id, when a probe said nothing
/// of it and the book does not name it yet: a host too loaded to answer holds our beacon on it
/// all the same. The endpoint is told too, as in [`settle_on_rung`].
pub(crate) async fn admit_rung(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    port: u16,
) {
    let entry = peer_book.get_endpoint_info(params.id);
    let held: bool = entry.is_some_and(|info| info.ip_addrs().any(|socket| socket.port() == port));
    if held {
        return;
    }
    let holder = rendezvous_holder_addr(params, port);
    add_peer_addr(peer_book, holder.clone());
    if let Err(error) = peer.add_endpoint_addr(holder).await {
        tracing::debug!(target: "habilis_network::beacon", %error, port, "the endpoint did not take the rung");
    }
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
    withheld: &[u16],
) -> EndpointAddr {
    match rendezvous_addr_without(params, withheld) {
        Some(registered) => {
            EndpointAddr::from_parts(holder.id, holder.addrs.into_iter().chain(registered.addrs))
        }
        None => holder,
    }
}
