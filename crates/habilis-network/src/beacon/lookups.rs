use crate::protocol::meshes::{LookupOpts, RelayChoice};

use super::RendezvousParams;

/// The beacon mirrors the peer's *address-lookups* (so a joiner
/// resolves `rendezvous_id` via whichever it enabled) but homes on a
/// **single** relay rung — `params.bootstrap_relay`, the first
/// reachable rung of the ladder that its own walk read. Unlike a peer
/// (which spreads across the whole multi-relay set for resilience), the
/// beacon stays on one rung, so that its home does not move with the
/// latency of the relays. A joiner does not need to know that rung: its
/// registration (`daemon::setup::register_rendezvous`) names every rung of
/// the ladder (`rendezvous_addr`), so the relay-direct dial reaches the beacon
/// on whichever rung it homes. A `None` rung ⇒ relay off for the beacon
/// (joiners use mDNS/DHT).
pub(crate) fn beacon_lookups(params: &RendezvousParams) -> LookupOpts {
    LookupOpts::new(
        params
            .bootstrap_relay
            .clone()
            .map_or(RelayChoice::Disabled, |rung| {
                RelayChoice::Custom(vec![rung])
            }),
    )
    .mdns(params.lookups.mdns)
    .dht(params.lookups.dht)
}
