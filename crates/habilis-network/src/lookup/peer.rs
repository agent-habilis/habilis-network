#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
#[cfg(feature = "multihop")]
use crate::transport::webrtc;
#[cfg(feature = "multihop")]
use crate::util::tuning;
// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

use anyhow::Result;
use iroh::{Endpoint, SecretKey};

use crate::protocol::mesh::{LookupOpts, RelayChoice};
#[cfg(feature = "multihop")]
use crate::transport::PayloadPath;

/// The normal peer endpoint: a fresh random identity, no
/// pinned port. Thin intent-named wrapper over `build_endpoint`
/// so call sites don't carry the rendezvous-only `None, None`.
/// # Errors
/// Binding the socket fails, or an address-lookup service cannot be wired.
pub async fn build_peer_endpoint(lookups: &LookupOpts) -> Result<Endpoint, super::EndpointError> {
    super::build_endpoint(
        lookups,
        None,
        None,
        Vec::new(),
        super::TransportHandles::default(),
    )
    .await
}

/// The multi-hop handle configuration this engine uses for a mesh: whether the
/// relay may carry cells is the mesh's `relay` rule, the other numbers are the
/// engine's. A caller that builds its own handle to inject uses this.
#[cfg(feature = "multihop")]
#[must_use]
pub fn multihop_handle_config(
    relay_payload: PayloadPath,
) -> habilis_network_iroh_multihop_transport::HandleConfig {
    habilis_network_iroh_multihop_transport::HandleConfig::default()
        .with_relay_payload(relay_payload.relay_allowed())
        .with_vector_max_age(tuning::LINKSTATE_MAX_AGE)
        .with_relay_stuck_after(tuning::MULTIHOP_RELAY_STUCK)
}

/// [`multihop_handle_config`] for a browser: the same numbers, and the link cost of
/// `HandleConfig::for_browser`, so that routes avoid a browser as a hop. Chosen by the browser
/// build of `build_member_endpoint`, and not by the target: a native member made to look like a
/// browser can use it too.
#[cfg(feature = "multihop")]
#[cfg_attr(
    all(feature = "host", not(test)),
    expect(
        dead_code,
        reason = "the browser build of `build_member_endpoint` is its caller"
    )
)]
#[must_use]
pub(crate) fn browser_handle_config(
    relay_payload: PayloadPath,
) -> habilis_network_iroh_multihop_transport::HandleConfig {
    multihop_handle_config(relay_payload).with_link_cost(
        habilis_network_iroh_multihop_transport::HandleConfig::for_browser().link_cost,
    )
}

/// Assert that an injected endpoint agrees with the mesh it joins.
///
/// [`InjectedEndpoint::bind`](crate::runtime::InjectedEndpoint::bind) already
/// checks the identities, so only the mesh-dependent part is left here: whether
/// the relay may carry the cells of the multi-hop handle, and whether the endpoint
/// can reach the rendezvous that the mesh uses.
///
/// # Errors
/// The multi-hop handle lets the relay carry cells on a mesh whose transport list
/// has no `relay`.
pub(crate) fn check_injected_against_mesh(
    endpoint: &Endpoint,
    relay_payload: bool,
    mesh_lookups: &LookupOpts,
    mesh_relay_transport: bool,
) -> Result<()> {
    // Whether the relay may carry cells is a rule of the mesh, in its id. A
    // handle that lets it, on a mesh that does not, would carry other peers'
    // cells over the relay.
    anyhow::ensure!(
        !relay_payload || mesh_relay_transport,
        "injected multihop handle lets the relay carry cells but the mesh's transport \
         list has no `relay`: build the handle with `relay_payload` off"
    );

    // The other half of the injection contract, and the half that had no check
    // at all. A caller that injects an endpoint built for one reach into a mesh
    // derived at another gets a setup that comes up clean and does not work:
    // the mesh registers its rendezvous somewhere the endpoint has no transport
    // to dial, so peers never find each other, while the node reports success.
    // One log line would have caught a share bound loopback-only whose mesh was
    // busy publishing a public rendezvous.
    // Keyed on whether the mesh *expects* a relay, not on whether it is
    // loopback. An mDNS-only mesh is neither loopback nor relayed, and having no
    // relay address is exactly right for it — warning there would be a false
    // alarm, which is its own defect.
    let endpoint_has_relay = endpoint
        .addr()
        .addrs
        .iter()
        .any(|address| matches!(address, iroh::TransportAddr::Relay(_)));
    let mesh_wants_relay = mesh_lookups.relay_lookup != RelayChoice::Disabled;
    if mesh_wants_relay && !endpoint_has_relay {
        tracing::warn!(
            "injected endpoint advertises no relay address but the mesh rendezvous \
             is on a relay; peers will not find each other until one comes up"
        );
    } else if !mesh_wants_relay && endpoint_has_relay {
        tracing::warn!(
            "injected endpoint has a relay address but the mesh does not use one; \
             the rendezvous will bootstrap without it"
        );
    }
    Ok(())
}

/// A peer endpoint with the `WebRTC` transport registered, plus the handle that
/// owns its session registry.
///
/// The key is minted here and pinned, because the transport advertises
/// `custom_addr(local_id)` as the address peers dial it on — so it has to know
/// the endpoint's identity, but the endpoint is built *with* the transport.
/// Getting this wrong is silent: the endpoint comes up fine and every `WebRTC`
/// dial goes to an address nobody listens on.
///
/// Registration is additive, so IP and relay stay available. A native peer
/// still prefers iroh's own hole-punched paths; for a browser this is the only
/// direct path there is.
///
/// # Errors
/// Returns an error if the endpoint fails to bind.
pub async fn build_peer_webrtc(
    lookups: &LookupOpts,
    options: super::TransportOpts,
) -> Result<
    (
        Endpoint,
        habilis_network_iroh_webrtc_transport::WebRtcHandle,
    ),
    super::EndpointError,
> {
    let (endpoint, handle, _mdns) = build_peer_webrtc_with(lookups, options, None)
        .await
        .map_err(super::EndpointError::internal)?;
    Ok((endpoint, handle))
}

/// [`build_peer_webrtc`], reporting the endpoint's connections to `admission`,
/// which keeps one entry per peer and drops the connections that are gone.
///
/// # Errors
/// Returns an error if the endpoint fails to bind.
pub(crate) async fn build_peer_webrtc_with(
    lookups: &LookupOpts,
    options: super::TransportOpts,
    admission: Option<&crate::transport::SignalAdmission>,
) -> Result<(
    Endpoint,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    Option<super::MdnsHandle>,
)> {
    let secret = mint_secret();
    let handle = build_webrtc_handle(secret.public());
    let gossip = build_gossip_handle(options, secret.public(), admission);
    let (endpoint, mdns) = super::build_endpoint_keeping_mdns(
        lookups,
        Some(secret),
        None,
        Vec::new(),
        super::TransportHandles {
            #[cfg(feature = "multihop")]
            multihop: None,
            webrtc: Some(handle.clone()),
            gossip: gossip.clone(),
            admission: admission.cloned(),
            underlay: false,
            options,
        },
    )
    .await?;
    debug_assert_eq!(
        endpoint.id(),
        handle.transport().local_id(),
        "the WebRTC transport must advertise this endpoint's identity"
    );
    Ok((endpoint, handle, mdns))
}

/// The gossip handle of a member endpoint, made from the key that the endpoint will bind, when
/// `opts` has gossip. The budget is set here: the crate's default is none, and the engine never
/// runs without one. The admission table keeps the handle: the table sees the connections, so
/// it is what tells the handle which peers are established and which pairs a higher rung
/// carries, and the event loop reads the handle back from it.
fn build_gossip_handle(
    options: super::TransportOpts,
    local: iroh::EndpointId,
    admission: Option<&crate::transport::SignalAdmission>,
) -> Option<habilis_network_iroh_gossip_transport::GossipHandle> {
    options.gossip.then(|| {
        let handle = habilis_network_iroh_gossip_transport::GossipHandle::new(local);
        handle.set_budget(Some(
            habilis_network_iroh_gossip_transport::DEFAULT_BUDGET_BYTES_PER_SEC,
        ));
        if let Some(admission) = admission {
            admission.set_gossip(handle.clone());
        }
        handle
    })
}

/// Build the target's `WebRtcHandle`. The constructors differ — str0m natively,
/// a `RTCPeerConnection` hub in a tab — but the handle type does not, so this is
/// the one place the split shows.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn build_webrtc_handle(
    local: iroh::EndpointId,
) -> habilis_network_iroh_webrtc_transport::WebRtcHandle {
    habilis_network_iroh_webrtc_transport::WebRtcHandle::new(
        habilis_network_iroh_webrtc_transport::WebRtcTransport::new(local),
    )
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn build_webrtc_handle(
    local: iroh::EndpointId,
) -> habilis_network_iroh_webrtc_transport::WebRtcHandle {
    habilis_network_iroh_webrtc_transport::WebRtcHandle::hub(local)
}

/// A fresh random identity. Every endpoint of one peer is built from the one
/// key this returns, so that a peer is one peer on every path.
fn mint_secret() -> SecretKey {
    let mut key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut key_bytes);
    SecretKey::from_bytes(&key_bytes)
}

/// A peer endpoint with the multi-hop **and** the `WebRTC` transport
/// registered, with the handles that own their state: the
/// [`MultihopHandle`](habilis_network_iroh_multihop_transport::MultihopHandle)
/// (forwarding underlay and routing table) and the `WebRTC` session registry.
///
/// One key is the peer's identity on every path: the application endpoint (UDP
/// and relay), the `WebRTC` address and the multi-hop hop identity. It is minted
/// here, before any endpoint exists, because each handle has to know the
/// identity its endpoint will bind.
///
/// The underlay is the exception, on purpose. It is an internal forwarding
/// endpoint on a key derived from the peer's, so it is stable across restarts and
/// the link-vector, which the peer signs, names it. A relay delivers a packet that names an id to one
/// endpoint registered under it, so an underlay on the application key would
/// take the application endpoint's relayed packets, or lose its own (measured:
/// 12 of 12 relay-only dials went to the endpoint that registered second). The
/// underlay needs the relay to punch through a NAT, so it cannot share the id.
///
/// # Errors
/// Returns an error if either endpoint fails to bind.
// The engine builds through `build_peer_multihop_with`; this is the form without
// the `WebRTC` leg of the underlay, which the tests of the receive path build with.
#[cfg(all(feature = "host", test))]
pub(crate) async fn build_peer_multihop(
    lookups: &LookupOpts,
    options: super::TransportOpts,
    admission: Option<&crate::transport::SignalAdmission>,
    relay_payload: PayloadPath,
) -> Result<(
    Endpoint,
    habilis_network_iroh_multihop_transport::MultihopHandle,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
)> {
    let (endpoint, handle, webrtc, _underlay_webrtc, _mdns) = build_peer_multihop_with(
        lookups,
        options,
        admission,
        multihop_handle_config(relay_payload),
        None,
    )
    .await?;
    Ok((endpoint, handle, webrtc))
}

/// [`build_peer_multihop`], and with `underlay_cap` set the underlay also gets a
/// `WebRTC` leg: its own `WebRtcHandle`, an admission table with that cap (G),
/// and the signal protocol on its router, answered for gossip neighbors only.
/// See [`crate::transport::underlay_webrtc`]. `None`, or an instance with
/// `WebRTC` off, leaves the underlay on IP and the relay.
///
/// # Errors
/// Returns an error if either endpoint fails to bind.
#[cfg(feature = "multihop")]
pub(crate) async fn build_peer_multihop_with(
    lookups: &LookupOpts,
    options: super::TransportOpts,
    admission: Option<&crate::transport::SignalAdmission>,
    handle_config: habilis_network_iroh_multihop_transport::HandleConfig,
    underlay_cap: Option<usize>,
) -> Result<(
    Endpoint,
    habilis_network_iroh_multihop_transport::MultihopHandle,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    Option<underlay_webrtc::UnderlayWebRtc>,
    Option<super::MdnsHandle>,
)> {
    let secret = mint_secret();
    let webrtc = build_webrtc_handle(secret.public());
    let gossip = build_gossip_handle(options, secret.public(), admission);
    let underlay_secret = habilis_network_iroh_multihop_transport::underlay_secret(&secret);
    // The `WebRTC` leg of the underlay: the handle and the table are made before
    // the endpoint, because the endpoint takes the transport and reports its
    // connections to the table from the first handshake on.
    let underlay_leg = underlay_cap.filter(|_| options.webrtc).map(|cap| {
        (
            build_webrtc_handle(underlay_secret.public()),
            crate::transport::SignalAdmission::new_route_table(cap),
        )
    });
    let underlay: Endpoint = super::build_endpoint(
        lookups,
        Some(underlay_secret),
        None,
        Vec::new(),
        super::TransportHandles {
            underlay: true,
            webrtc: underlay_leg.as_ref().map(|(handle, _)| handle.clone()),
            admission: underlay_leg.as_ref().map(|(_, table)| table.clone()),
            // The underlay has IP sockets only when the node does: a node run without `udp`
            // has no IP on any of its endpoints, and its underlay rides WebRTC and the relay.
            options: super::TransportOpts {
                udp: options.udp,
                ..super::TransportOpts::default()
            },
            ..super::TransportHandles::default()
        },
    )
    .await?;
    let mut protocols = habilis_network_iroh_transport_util::ProtocolSet::default();
    let mut underlay_webrtc = None;
    if let Some((handle, table)) = underlay_leg {
        let allowed = underlay_webrtc::Allowed::default();
        let ice = crate::transport::IceProfile {
            host_only: lookups.is_loopback(),
        };
        // The underlay is an endpoint of its own, with lookup services of its own, so it has
        // an address book of its own.
        let book = super::address_book(&underlay);
        let acceptor: crate::transport::WebRtcSignalAcceptor =
            crate::transport::WebRtcSignalAcceptor::new(
                handle.clone(),
                underlay.clone(),
                book.clone(),
                underlay.id(),
                table.clone(),
                ice,
            );
        protocols = protocols.with_protocol(
            crate::transport::MESH_WEBRTC_SIGNAL_ALPN.to_vec(),
            underlay_webrtc::UnderlaySignalGate::new(acceptor, allowed.clone()),
        );
        // A session that attached is used only after a connect that completes, and
        // the nudge is that connect: see `webrtc::nudge_acceptor::nudge_session`.
        protocols = protocols.with_protocol(webrtc::NUDGE_ALPN.to_vec(), webrtc::NudgeAcceptor);
        underlay_webrtc = Some(underlay_webrtc::UnderlayWebRtc {
            handle,
            admission: table,
            endpoint: underlay.clone(),
            book,
            allowed,
        });
    }
    let handle = habilis_network_iroh_multihop_transport::MultihopHandle::with_protocols(
        &secret,
        underlay,
        handle_config,
        protocols,
    )?;
    let (endpoint, mdns) = super::build_endpoint_keeping_mdns(
        lookups,
        Some(secret),
        None,
        Vec::new(),
        super::TransportHandles {
            multihop: Some(handle.clone()),
            webrtc: Some(webrtc.clone()),
            gossip: gossip.clone(),
            admission: admission.cloned(),
            underlay: false,
            options,
        },
    )
    .await?;
    Ok((endpoint, handle, webrtc, underlay_webrtc, mdns))
}
