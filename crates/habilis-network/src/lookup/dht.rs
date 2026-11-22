//! The mainline-DHT leg of the lookup layer: operator-free, eternal
//! publish/resolve of the seed-derived `rendezvous_id` via pkarr on the
//! `BitTorrent` mainline DHT. Wired only when `--dht` is in the allowlist;
//! it is the slow-but-always-there backstop and one of the
//! independently-sufficient reliability layers (see the lookup glossary
//! in AGENTS.md).

use std::time::Duration;

use anyhow::{Context, Result};
use iroh::Endpoint;
use iroh::address_lookup::AddrFilter;
use iroh_mainline_address_lookup::{Builder, DhtAddressLookup};

mod publish;
pub(in crate::lookup) use publish::Publish;

/// How long the publish task of the DHT lookup waits before it puts the record again. The task puts once, and a
/// put that fails (no node answered yet) is the only try until this delay passes: the library default is one hour,
/// and for the beacon of a DHT-only mesh an hour with no record is an hour in which nobody can join. The delay
/// also keeps the record alive, which the DHT forgets.
const REPUBLISH_AFTER: Duration = Duration::from_secs(60);

/// The builder of the DHT lookup of `endpoint`. The builder publishes only with a secret key, and
/// `Builder::into_address_lookup` is the only place that sets one: a builder that is built by hand
/// needs the key of the endpoint, or it never publishes (the DHT-only mesh formed nobody).
fn builder(endpoint: &Endpoint, publish: Publish) -> Builder {
    let builder = DhtAddressLookup::builder().republish_delay(REPUBLISH_AFTER);
    let secret = endpoint.secret_key().clone();
    match publish {
        Publish::Nothing => builder.no_publish(),
        Publish::RelayOnly => builder.secret_key(secret),
        Publish::WithAddresses => builder
            .secret_key(secret)
            .addr_filter(AddrFilter::unfiltered()),
    }
}

/// Wire the mainline-DHT address-lookup onto a bound endpoint. In iroh 1.0 the
/// provider is a companion crate added to the endpoint's address-lookup
/// services. It resolves for every endpoint, and it publishes what `publish` says.
pub(super) fn wire(endpoint: &Endpoint, publish: Publish) -> Result<()> {
    let lookup = builder(endpoint, publish)
        .build()
        .context("building mainline-DHT address-lookup")?;
    endpoint
        .address_lookup()
        .map_err(|err| anyhow::anyhow!("{err:?}"))
        .context("endpoint has no address-lookup services for DHT")?
        .add(lookup);
    tracing::debug!(?publish, "mainline DHT address-lookup wired");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use iroh::address_lookup::{AddressLookup, EndpointData};
    use iroh::{Endpoint, RelayUrl, SecretKey, TransportAddr};
    use n0_future::{StreamExt as _, time};
    use n0_mainline::{DhtBuilder, Testnet};

    use super::{DhtAddressLookup, Publish, builder};
    use crate::lookup;
    use crate::protocol::meshes::LookupOpts;

    /// The relay URL and the IP address of the endpoint, as it would tell the lookup.
    fn endpoint_data() -> (EndpointData, RelayUrl, SocketAddr) {
        let relay: RelayUrl = "https://relay.example/".parse().expect("a relay URL");
        let ip = SocketAddr::from(([203, 0, 113, 7], 4433));
        let data = EndpointData::new(vec![
            TransportAddr::Relay(relay.clone()),
            TransportAddr::Ip(ip),
        ]);
        (data, relay, ip)
    }

    /// A loopback endpoint with a key that the test knows: no lookup is wired on it.
    async fn endpoint_with_key(secret: SecretKey) -> Endpoint {
        let lookups = LookupOpts::loopback();
        let handles = lookup::TransportHandles::default();
        let bound =
            lookup::build_endpoint_keeping_mdns(&lookups, Some(secret), None, Vec::new(), handles);
        let (endpoint, _) = bound.await.expect("a loopback endpoint");
        let closer = endpoint.clone();
        habilis_network_test_tracing::at_end(async move { closer.close().await });
        endpoint
    }

    /// A DHT client that knows the nodes of the local testnet and no other node: the bootstrap list
    /// replaces the public one. The crate n0-mainline 0.5.0 has no bind address, so the sockets of the testnet
    /// and of its clients bind 0.0.0.0; they send to these loopback addresses only, which the run of
    /// the test under `sandbox-exec` with every non-loopback send denied proves.
    fn local_dht(testnet: &Testnet) -> DhtBuilder {
        for entry in &testnet.bootstrap {
            let address: SocketAddr = entry.parse().expect("a bootstrap node is an IP address");
            assert!(
                address.ip().is_loopback(),
                "a bootstrap node off the host: {entry}"
            );
        }
        let mut dht = DhtBuilder::default();
        dht.bootstrap(&testnet.bootstrap);
        dht
    }

    /// What a second member reads from a DHT for `id`: the addresses of the record, or none.
    async fn resolved(testnet: &Testnet, id: iroh::EndpointId) -> Vec<TransportAddr> {
        let dht = local_dht(testnet);
        let reading = DhtAddressLookup::builder().dht_builder(dht).no_publish();
        let reader = reading.build().expect("a reader");
        let Some(mut items) = reader.resolve(id) else {
            return Vec::new();
        };
        let wait = time::timeout(Duration::from_secs(3), items.next()).await;
        match wait {
            Ok(Some(Ok(item))) => item.endpoint_info().data.addrs().cloned().collect(),
            _ => Vec::new(),
        }
    }

    /// What a joiner finds in a local DHT after `publish` made the lookup of the endpoint publish the
    /// relay URL and the IP address of the endpoint.
    async fn found_after(publish: Publish) -> Vec<TransportAddr> {
        let testnet = Testnet::new(3).await.expect("a local DHT");
        let secret = SecretKey::generate();
        let id = secret.public();
        let endpoint = endpoint_with_key(secret).await;
        let dht = local_dht(&testnet);
        // A short delay: one put that fails must not leave the record out for the whole wait of the test.
        let building = builder(&endpoint, publish)
            .dht_builder(dht)
            .republish_delay(Duration::from_millis(300));
        let lookup = building.build().expect("the lookup of the endpoint");

        lookup.publish(&endpoint_data().0);
        let mut found = Vec::new();
        for _ in 0..20 {
            found = resolved(&testnet, id).await;
            if !found.is_empty() {
                break;
            }
        }
        found
    }

    /// The first lookup of a mesh with only `dht` had nothing to read: it was built with no key, so
    /// it never published.
    #[test]
    fn the_beacon_of_a_dht_only_mesh_publishes_its_relay_and_its_ip_address() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (_, relay, ip) = endpoint_data();

                let found = found_after(Publish::WithAddresses).await;

                assert!(
                    found.contains(&TransportAddr::Relay(relay)),
                    "a joiner finds no record of the rendezvous in the DHT: {found:?}"
                );
                assert!(
                    found.contains(&TransportAddr::Ip(ip)),
                    "the record holds no IP address, so a mesh with no relay lookup has no way in: {found:?}"
                );
            },
        );
    }

    /// With a relay lookup the record holds the relay URL and no IP address.
    #[test]
    fn the_beacon_of_a_mesh_with_a_relay_lookup_keeps_its_ip_address_out_of_the_dht() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (_, relay, ip) = endpoint_data();

                let found = found_after(Publish::RelayOnly).await;

                assert!(found.contains(&TransportAddr::Relay(relay)), "{found:?}");
                assert!(
                    !found.contains(&TransportAddr::Ip(ip)),
                    "the IP address of the host is in the public DHT: {found:?}"
                );
            },
        );
    }

    /// A peer endpoint resolves and publishes nothing.
    #[test]
    fn a_peer_endpoint_publishes_nothing_to_the_dht() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let found = found_after(Publish::Nothing).await;

                assert!(
                    found.is_empty(),
                    "a peer put a record in the DHT: {found:?}"
                );
            },
        );
    }
}
