//! What the DHT lookup of an endpoint puts in the DHT.

use crate::lookup::EndpointRole;

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
    /// What an endpoint of this role publishes. The beacon publishes under its own key, which is the key of the
    /// rendezvous. The role says if the mesh is configured with a relay lookup, so the decision is made once, from
    /// the configuration, and not from the relay that the beacon homes on at the moment.
    pub(in crate::lookup) fn of(role: EndpointRole) -> Self {
        match role {
            EndpointRole::Peer | EndpointRole::Underlay => Self::Nothing,
            EndpointRole::Beacon => Self::RelayOnly,
            EndpointRole::BeaconWithoutRelay => Self::WithAddresses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Publish;
    use crate::lookup::EndpointRole;

    /// Only the beacon publishes, and only the beacon of a mesh with no relay lookup puts the IP addresses of the host
    /// in the DHT.
    #[test]
    fn only_the_beacon_publishes_and_only_a_mesh_with_no_relay_lookup_publishes_addresses() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(Publish::of(EndpointRole::Peer), Publish::Nothing, "a peer");
        assert_eq!(
            Publish::of(EndpointRole::Underlay),
            Publish::Nothing,
            "an underlay"
        );
        assert_eq!(
            Publish::of(EndpointRole::BeaconWithoutRelay),
            Publish::WithAddresses,
            "the beacon of a mesh with no relay lookup has no relay URL to publish"
        );
        assert_eq!(
            Publish::of(EndpointRole::Beacon),
            Publish::RelayOnly,
            "the beacon of a mesh with a relay lookup keeps its IP addresses out of the DHT"
        );
    }
}
