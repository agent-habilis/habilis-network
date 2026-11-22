//! What the DHT lookup of an endpoint puts in the DHT.

use crate::protocol::meshes::RelayChoice;

/// What the DHT lookup of an endpoint puts in the DHT. Every endpoint resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::lookup) enum Publish {
    /// Nothing. Only the beacon speaks for the rendezvous: a peer that published its own address
    /// would put the address of its host in a public DHT, for no gain.
    Nothing,
    /// The relay URL of the endpoint, the default of the DHT lookup. No IP address is public.
    RelayOnly,
    /// Every address of the endpoint, with no filter: its private LAN addresses too. A mesh with no
    /// relay lookup has no relay URL to publish, and a record with no address is not published at all.
    WithAddresses,
}

impl Publish {
    /// What an endpoint publishes. The beacon publishes under its own key, which is the key of the
    /// rendezvous. A mesh with a relay lookup keeps the IP addresses of the beacon out of the DHT.
    pub(in crate::lookup) fn of(is_beacon: bool, relay_lookup: &RelayChoice) -> Self {
        match (is_beacon, relay_lookup) {
            (false, _) => Self::Nothing,
            (true, RelayChoice::Disabled) => Self::WithAddresses,
            (true, _) => Self::RelayOnly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Publish;
    use crate::protocol::meshes::RelayChoice;

    /// Only the beacon publishes, and a mesh with no relay lookup is the one that puts the IP addresses
    /// of the beacon in the DHT.
    #[test]
    fn only_the_beacon_publishes_and_only_a_mesh_with_no_relay_lookup_publishes_addresses() {
        let _guard = ::habilis_network_test_tracing::init();
        for relay in [RelayChoice::Disabled, RelayChoice::Pinned] {
            assert_eq!(
                Publish::of(false, &relay),
                Publish::Nothing,
                "a peer publishes nothing ({relay:?})"
            );
        }
        assert_eq!(
            Publish::of(true, &RelayChoice::Disabled),
            Publish::WithAddresses,
            "the beacon of a mesh with no relay lookup has no relay URL to publish"
        );
        assert_eq!(
            Publish::of(true, &RelayChoice::Pinned),
            Publish::RelayOnly,
            "the beacon of a mesh with a relay lookup keeps its IP addresses out of the DHT"
        );
    }
}
