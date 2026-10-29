use crate::protocol::mesh::{LookupOpts, RelayChoice};

use super::RendezvousParams;

/// The beacon mirrors the peer's *address-lookups* (so a joiner
/// resolves `rendezvous_id` via whichever it enabled) but homes on a
/// **single** relay rung — `params.bootstrap_relay`, the first
/// reachable rung of the ladder. Unlike a peer (which spreads
/// across the whole multi-relay set for resilience), the beacon must be
/// at the one deterministic rung the joiner pre-registers
/// (`daemon::setup::register_rendezvous`), or the relay-direct dial
/// finds nothing. A `None` rung ⇒ relay off for the beacon (joiners use
/// mDNS/DHT).
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
