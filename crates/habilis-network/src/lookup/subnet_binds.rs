// A browser has no network interface to list.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use iroh::endpoint::{BindOpts, Builder};

use super::nic::Nic;

/// The `IPv4` sockets an endpoint binds when two interfaces of the host share a subnet, or `None`
/// when no two do.
///
/// One socket on `0.0.0.0` advertises the address of every interface. Two interfaces in one
/// subnet then give a peer two addresses that reach the host through the same wire, and the host
/// answers on the interface of its routing table, not on the one the packet came in on. On macOS
/// that send fails with `No route to host`, and the handshake never completes. One address per
/// subnet leaves a single path in each subnet.
///
/// The interface of the default route wins its subnet. If none of the interfaces of a subnet
/// carries it, the lowest index wins. Exactly one chosen address is the default route of the
/// endpoint, and that is the first one that is on the default route of the host.
pub(super) fn one_address_per_subnet(nics: &[Nic]) -> Option<Vec<Nic>> {
    let mut subnets: BTreeMap<(u32, u8), Vec<&Nic>> = BTreeMap::new();
    for nic in nics {
        subnets.entry(subnet_of(nic)).or_default().push(nic);
    }
    if subnets.values().all(|members| members.len() < 2) {
        return None;
    }

    let mut chosen: Vec<Nic> = subnets
        .into_values()
        .filter_map(|members| {
            members
                .into_iter()
                .min_by_key(|nic| (!nic.on_default_route, nic.index))
                .cloned()
        })
        .collect();
    chosen.sort_by_key(|nic| nic.index);

    let default = chosen
        .iter()
        .position(|nic| nic.on_default_route)
        .unwrap_or(0);
    for (position, nic) in chosen.iter_mut().enumerate() {
        nic.on_default_route = position == default;
    }
    Some(chosen)
}

fn subnet_of(nic: &Nic) -> (u32, u8) {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(nic.prefix_len))
        .unwrap_or(0);
    (u32::from(nic.address) & mask, nic.prefix_len)
}

/// The `IPv4` addresses of the interfaces of this host that carry traffic: up, not loopback, and
/// not link-local.
fn local_nics() -> Vec<Nic> {
    let default_route: Option<u32> = netdev::get_default_interface()
        .ok()
        .map(|interface| interface.index);
    let mut nics: Vec<Nic> = Vec::new();
    for interface in netdev::get_interfaces() {
        if !interface.is_up() || interface.is_loopback() {
            continue;
        }
        for net in &interface.ipv4 {
            if net.addr().is_link_local() {
                continue;
            }
            nics.push(Nic {
                name: interface.name.clone(),
                index: interface.index,
                address: net.addr(),
                prefix_len: net.prefix_len(),
                on_default_route: default_route == Some(interface.index),
            });
        }
    }
    nics
}

/// Binds `builder` to one address per subnet when two interfaces share a subnet, and leaves it
/// on the wildcard socket otherwise.
///
/// Known limit: an interface that comes up after the bind has no socket, so a peer on a new
/// subnet reaches this endpoint only over the relay until the endpoint is built again.
pub(super) fn bind_one_address_per_subnet(builder: Builder) -> Result<Builder> {
    bind_nics(builder, &local_nics())
}

fn bind_nics(builder: Builder, nics: &[Nic]) -> Result<Builder> {
    let Some(binds) = one_address_per_subnet(nics) else {
        return Ok(builder);
    };
    let chosen: Vec<(&String, Ipv4Addr)> =
        binds.iter().map(|nic| (&nic.name, nic.address)).collect();
    tracing::info!(
        target: "habilis_network::lookup",
        ?chosen,
        "two interfaces share a subnet: one address per subnet"
    );
    let mut builder = builder.clear_ip_transports();
    for nic in &binds {
        let options = BindOpts::default()
            .set_prefix_len(nic.prefix_len)
            .set_is_default_route(nic.on_default_route);
        builder = builder
            .bind_addr_with_opts((nic.address, 0), options)
            .with_context(|| format!("failed to bind {} on {}", nic.address, nic.name))?;
    }
    builder
        .bind_addr_with_opts("[::]:0", BindOpts::default().set_is_required(false))
        .context("failed to bind the IPv6 socket")
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode};

    use super::{Nic, bind_nics, one_address_per_subnet};

    fn nic(
        name: &str,
        index: u32,
        address: [u8; 4],
        prefix_len: u8,
        on_default_route: bool,
    ) -> Nic {
        Nic {
            name: name.into(),
            index,
            address: Ipv4Addr::from(address),
            prefix_len,
            on_default_route,
        }
    }

    /// The interface table of nyc-macmini1 with Ethernet and Wi-Fi on.
    fn macmini() -> Vec<Nic> {
        vec![
            nic("en0", 6, [192, 168, 1, 97], 24, true),
            nic("en1", 12, [192, 168, 1, 143], 24, false),
            nic("utun8", 26, [100, 99, 190, 117], 32, false),
        ]
    }

    #[test]
    fn two_interfaces_in_one_subnet_keep_the_address_of_the_default_route() {
        let _guard = ::habilis_network_test_tracing::init();
        let binds = one_address_per_subnet(&macmini()).expect("the subnet is shared");
        let names: Vec<&str> = binds.iter().map(|nic| nic.name.as_str()).collect();
        assert_eq!(
            names,
            ["en0", "utun8"],
            "the default-route address of the shared subnet and the VPN"
        );
    }

    #[test]
    fn the_default_route_wins_over_a_lower_index() {
        let _guard = ::habilis_network_test_tracing::init();
        let nics = vec![
            nic("en0", 6, [192, 168, 1, 97], 24, false),
            nic("en1", 12, [192, 168, 1, 143], 24, true),
        ];
        let binds = one_address_per_subnet(&nics).expect("the subnet is shared");
        let names: Vec<&str> = binds.iter().map(|nic| nic.name.as_str()).collect();
        assert_eq!(
            names,
            ["en1"],
            "the default route wins over the lower index"
        );
    }

    #[test]
    fn the_order_of_the_interfaces_does_not_change_the_choice() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut nics = macmini();
        nics.reverse();
        let binds = one_address_per_subnet(&nics).expect("the subnet is shared");
        let names: Vec<&str> = binds.iter().map(|nic| nic.name.as_str()).collect();
        assert_eq!(
            names,
            ["en0", "utun8"],
            "the default-route address of the shared subnet and the VPN"
        );
    }

    #[test]
    fn a_host_with_one_interface_per_subnet_keeps_the_wildcard_socket() {
        let _guard = ::habilis_network_test_tracing::init();
        let nics = vec![
            nic("en0", 6, [192, 168, 1, 97], 24, true),
            nic("en5", 9, [10, 0, 0, 4], 24, false),
        ];
        assert_eq!(
            one_address_per_subnet(&nics),
            None,
            "no subnet is shared, so the wildcard socket stays"
        );
    }

    #[test]
    fn without_the_default_route_in_the_subnet_the_lowest_index_wins() {
        let _guard = ::habilis_network_test_tracing::init();
        let nics = vec![
            nic("en7", 14, [10, 0, 0, 9], 24, false),
            nic("en5", 9, [10, 0, 0, 4], 24, false),
            nic("en0", 6, [192, 168, 1, 97], 24, true),
        ];
        let binds = one_address_per_subnet(&nics).expect("the subnet is shared");
        let names: Vec<&str> = binds.iter().map(|nic| nic.name.as_str()).collect();
        assert_eq!(
            names,
            ["en0", "en5"],
            "the lowest index of the shared subnet, and the other subnet"
        );
    }

    #[test]
    fn exactly_one_chosen_address_is_the_default_route() {
        let _guard = ::habilis_network_test_tracing::init();
        // One interface with two subnets carries the default route on both addresses.
        let nics = vec![
            nic("en0", 6, [192, 168, 1, 97], 24, true),
            nic("en0", 6, [10, 0, 0, 2], 24, true),
            nic("en1", 12, [192, 168, 1, 143], 24, false),
        ];
        let binds = one_address_per_subnet(&nics).expect("the subnet is shared");
        let defaults = binds.iter().filter(|nic| nic.on_default_route).count();
        assert_eq!(defaults, 1, "one default socket, got {binds:?}");
    }

    #[test]
    fn a_host_whose_default_route_is_in_no_chosen_subnet_still_gets_one_default_socket() {
        let _guard = ::habilis_network_test_tracing::init();
        let nics = vec![
            nic("en1", 12, [192, 168, 1, 143], 24, false),
            nic("en2", 13, [192, 168, 1, 150], 24, false),
        ];
        let binds = one_address_per_subnet(&nics).expect("the subnet is shared");
        assert_eq!(
            binds.len(),
            1,
            "one address for the shared subnet, got {binds:?}"
        );
        assert!(
            binds[0].on_default_route,
            "the only address is the default route"
        );
    }

    /// The wiring: two interfaces in one subnet give an endpoint one bound `IPv4` socket.
    #[tokio::test]
    async fn an_endpoint_binds_one_socket_for_two_interfaces_in_one_subnet() {
        let _guard = ::habilis_network_test_tracing::init();
        let nics = vec![
            nic("lo-a", 1, [127, 0, 0, 1], 8, true),
            nic("lo-b", 2, [127, 0, 0, 1], 8, false),
        ];
        let builder = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled);
        let endpoint = bind_nics(builder, &nics)
            .expect("the bind list is valid")
            .bind()
            .await
            .expect("bind the endpoint");
        let v4: Vec<SocketAddr> = endpoint
            .bound_sockets()
            .into_iter()
            .filter(SocketAddr::is_ipv4)
            .collect();
        assert_eq!(v4.len(), 1, "one IPv4 socket, got {v4:?}");
        assert_eq!(
            v4[0].ip(),
            Ipv4Addr::LOCALHOST,
            "the socket is on the chosen address"
        );
        endpoint.close().await;
    }
}
