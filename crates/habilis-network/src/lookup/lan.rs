use tokio::sync::mpsc;

// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.
#[cfg(feature = "host")]
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result};
#[cfg(feature = "host")]
use iroh::endpoint::PortmapperConfig;
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMode, SecretKey};

use crate::protocol::mesh::{LookupOpts, RelayChoice};

use iroh_gossip::proto;
/// The LAN members of our mesh, as the event loop reads them. `None` where the endpoint has no
/// mDNS handle: that is the off switch of the LAN arm.
///
/// # Errors
/// Returns an error if the tag does not fit the user data of the endpoint.
pub(crate) async fn lan_contacts(
    endpoint: &Endpoint,
    mdns: Option<super::MdnsHandle>,
    topic: &proto::TopicId,
) -> Result<Option<mpsc::Receiver<super::LanEvent>>> {
    #[cfg(all(feature = "host", feature = "mdns"))]
    if let Some(handle) = mdns {
        // The tag first, so that the record we announce already says that we are a member.
        tag_as_member(endpoint, topic)?;
        return Ok(Some(
            super::mdns::spawn_lan_contacts(&handle, lan_member_tag(topic), endpoint.id()).await,
        ));
    }
    #[cfg(not(all(feature = "host", feature = "mdns")))]
    let _ = (endpoint, mdns, topic);
    Ok(None)
}

/// What a member of a mesh puts in the user data of its endpoint, so that another member can tell
/// it from a beacon, a probe, or an endpoint of another mesh in the same mDNS service. It hashes
/// the topic id of the mesh, which already folds in the name, the config and the password: two
/// rooms with the same name and different passwords do not share a tag.
#[cfg(all(feature = "host", feature = "mdns"))]
#[must_use]
pub(crate) fn lan_member_tag(topic: &proto::TopicId) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    let topic_bytes = topic.as_bytes();
    let digest = Sha256::new()
        .chain_update(b"habilis-network/lan-member/1")
        .chain_update(topic_bytes)
        .finalize();
    let mut tag = String::from("hn1:");
    for byte in &digest[..8] {
        let _ = write!(tag, "{byte:02x}");
    }
    tag
}

/// Mark the endpoint as a member of the mesh with this topic, in the mDNS record it announces.
/// The tag is set after the endpoint is built, because the member endpoint exists before the mesh
/// is known, and an injected endpoint is built by the caller. iroh announces the new record at
/// once.
/// # Errors
/// Returns an error if the tag does not fit the user data of an endpoint.
#[cfg(all(feature = "host", feature = "mdns"))]
pub(crate) fn tag_as_member(endpoint: &Endpoint, topic: &proto::TopicId) -> Result<()> {
    let tag = lan_member_tag(topic)
        .parse()
        .context("the member tag does not fit the endpoint user data")?;
    endpoint.set_user_data_for_address_lookup(Some(tag));
    Ok(())
}

/// [`build_endpoint`], and the mDNS handle when the endpoint has one.
/// # Errors
/// As [`build_endpoint`].
#[cfg_attr(
    not(feature = "host"),
    expect(
        unused_variables,
        reason = "`bind_port` feeds the loopback `bind_addr` below, which is `host`-only"
    )
)]
pub(crate) async fn build_endpoint_keeping_mdns(
    lookups: &LookupOpts,
    secret_key: Option<SecretKey>,
    bind_port: Option<u16>,
    alpns: Vec<Vec<u8>>,
    transports: super::TransportHandles,
) -> Result<(Endpoint, Option<super::MdnsHandle>)> {
    // A peer endpoint carrying a custom transport also pins a key, so it is
    // *not* a beacon; the presence of a handle disambiguates.
    let is_beacon = secret_key.is_some() && transports.is_empty() && !transports.underlay;
    let underlay = transports.underlay;
    let network = lookups.network_label();
    let mut builder = if lookups.is_loopback() {
        debug_assert!(
            !lookups.mdns && !lookups.dht && lookups.relay_lookup == RelayChoice::Disabled,
            "loopback-only mesh must resolve to all-off lookups"
        );
        // Loopback-only = strictly loopback, **zero external network calls**.
        // `Minimal` picks the rustls crypto provider without N0's
        // DNS/relay defaults; we then lock down every path that could
        // touch a non-loopback host: `bind_addr` 127.0.0.1,
        // `RelayMode::Disabled` (no relay; no address-lookup is wired
        // for a loopback-only mesh so no DNS/pkarr/mDNS/DHT either), and
        // `PortmapperConfig::Disabled` — the one remaining default-on
        // reach (UPnP/PCP/NAT-PMP to the LAN gateway, on even with the
        // relay off). With relay + portmapper off, iroh's netcheck has
        // no external targets (local-interface report only).
        // `bind_port` is the deterministic rendezvous port when
        // co-hosting the beacon, else 0 (ephemeral).
        {
            let builder = Endpoint::builder(presets::Minimal);
            #[cfg(feature = "host")]
            let builder = {
                let bind_socket = SocketAddrV4::new(Ipv4Addr::LOCALHOST, bind_port.unwrap_or(0));
                builder
                    .bind_addr(bind_socket)
                    .context("failed to set bind address")?
                    .portmapper_config(PortmapperConfig::Disabled)
            };
            builder.relay_mode(RelayMode::Disabled)
        }
    } else {
        // `Minimal` (not `presets::N0`): N0-DNS is intentionally not
        // wired (the relay ladder is the fast path; DHT is the
        // operator-free eternal backstop). `Minimal` still sets the
        // rustls crypto provider. The mDNS / DHT address-lookups are
        // wired **after** bind (below) — in iroh 1.0 they live in
        // companion crates and need the bound endpoint's id.
        Endpoint::builder(presets::Minimal)
            .relay_mode(super::relay::relay_mode(&lookups.relay_lookup))
    };

    #[cfg(all(feature = "host", feature = "iroh-test-utils"))]
    let underlay_id = secret_key.as_ref().map(SecretKey::public);
    if let Some(secret_key) = secret_key {
        builder = builder.secret_key(secret_key);
    }

    // ALPNs the endpoint accepts inbound connections for. Empty for the gossip /
    // rendezvous endpoints (their Router registers `GOSSIP_ALPN`); a transfer
    // producer passes its ALPN (e.g. `FILE_ALPN`) so it can `endpoint.accept()`
    // directly.
    if !alpns.is_empty() {
        builder = builder.alpns(alpns);
    }

    let options = transports.options;
    builder = super::install_transports(builder, &transports);
    // Tests only: the underlay is an endpoint of its own, and a test that takes
    // paths away from a pair (`habilis_network_iroh_webrtc_transport::block_ip_to`)
    // needs a selector on it that reads the same tables. An underlay with a
    // `WebRtcHandle` already runs `WebRtcPreferred` (see `install_transports`),
    // which reads them. This one is for an underlay without a handle, which would
    // otherwise run iroh's default selector: it gets `MultihopLadder`.
    #[cfg(all(feature = "host", feature = "iroh-test-utils"))]
    if let Some(id) = underlay_id.filter(|_| underlay && transports.webrtc.is_none()) {
        builder = builder.path_selector(
            habilis_network_iroh_multihop_transport::underlay_path_selector(
                habilis_network_iroh_multihop_transport::UnderlayId::new(id),
            ),
        );
    }
    // Data-plane exclusivity: with IP cleared, a WebRTC-only peer cannot
    // silently fall back onto a hole-punched path, so a run that *claims* to be
    // WebRTC-only can be shown to be one. The relay is left alone on purpose —
    // it is the rendezvous, not a data path, and clearing it would leave the
    // JSEP exchange nowhere to happen.
    //
    // Non-wasm only, and not because of a feature gate: `clear_ip_transports`
    // does not *exist* on a wasm build of iroh, because a browser has no IP
    // transports to clear. The flag is already satisfied there by construction.
    #[cfg(not(target_arch = "wasm32"))]
    if !options.udp {
        // `clear_ip_transports` only — deliberately **not**
        // `clear_address_lookup`. That was the first attempt and it silently
        // broke everything: `add_peer_addr` registers a `MemoryLookup` on the
        // endpoint, and the zero-lookup bootstrap *is* that registration
        // (`register_rendezvous` pre-registers the rendezvous at its relay
        // rung). Clearing the lookup store leaves the peer unable to dial
        // anything at all — it sat at `link_len=0, meshed=false` while still
        // seeing the roster through the beacon, which reads like a NAT problem
        // and is not one. The IP *discovery* legs are skipped further down
        // instead, where mDNS and DHT are wired.
        builder = builder.clear_ip_transports();
        tracing::info!(
            target: "habilis_network::lookup",
            "IP transports cleared; data must ride WebRTC (relay kept for rendezvous)"
        );
    }

    // Transport config is left at iroh's defaults, but for the memory windows: iroh tunes
    // keep-alive / idle (and the per-path multipath settings) for its
    // holepunching, and its own docs warn that adjusting them "may cause
    // suboptimal usage". A prior aggressive 10s idle / 5s keep-alive override
    // fought that tuning — marginal / distant links falsely idle-timed-out,
    // HyParView refilled from passive, and the resulting NeighborDown/Up churn
    // drove a per-connection memory leak. So we set only the memory windows of a connection
    // (decision D11), never the keep-alive, the idle timeout or the multipath settings.
    builder = builder.transport_config(super::endpoint::quic_limits());

    // For the private rendezvous endpoint this returns `AddrInUse`
    // when another member already holds the deterministic port — the
    // caller treats that as "someone else is the beacon" and retries.
    let endpoint = builder.bind().await.context("failed to bind endpoint")?;
    // Post-bind address-lookup wiring: in iroh 1.0 the mDNS / mainline-DHT
    // providers are companion crates built from the bound endpoint's id and
    // added to its lookup services. Loopback-only meshes wire none (asserted
    // above). The relay leg is configured pre-bind via `relay_mode`.
    // These are wired *after* bind (iroh 1.0 moved them to companion crates
    // that need the bound endpoint's id), so `clear_address_lookup` above does
    // not reach them — they have to be skipped here as well. Both exist to find
    // IP paths, so an instance with IP off has no use for either.
    #[cfg(all(feature = "host", feature = "mdns"))]
    let mdns_handle = if lookups.mdns && options.udp {
        Some(super::mdns::wire(&endpoint)?)
    } else {
        None
    };
    #[cfg(not(all(feature = "host", feature = "mdns")))]
    let mdns_handle: Option<super::MdnsHandle> = None;
    if lookups.dht && options.udp {
        #[cfg(all(feature = "host", feature = "dht"))]
        super::dht::wire(&endpoint)?;
    }
    tracing::info!(target: "habilis_network::lookup",
        network,
        mdns = lookups.mdns,
        dht = lookups.dht,
        relay = ?lookups.relay_lookup,
        role = if underlay {
            "underlay"
        } else if is_beacon {
            "beacon"
        } else {
            "peer"
        },
        endpoint_id = %endpoint.id(),
        "endpoint bound"
    );
    Ok((endpoint, mdns_handle))
}
