use iroh::Endpoint;
use iroh::address_lookup::memory;

use crate::util::clock::Instant;
use crate::util::tuning;

use crate::lookup::{EndpointRole, TransportHandles, build_endpoint};

use super::{
    RendezvousParams, RungRead, RungWatch, Walk, beacon_lookups, rung_is_busy, rung_ladder,
};

use crate::{lookup, transport};
/// The transports of the beacon of a public rendezvous. It carries a `WebRTC` handle, so the handles do not
/// tell that it is the beacon, and the role says it: only the beacon publishes the rendezvous to the DHT.
fn public_beacon_handles(
    webrtc: &habilis_network_iroh_webrtc_transport::WebRtcHandle,
    admission: &transport::SignalAdmission,
) -> TransportHandles {
    TransportHandles {
        webrtc: Some(webrtc.clone()),
        admission: Some(admission.clone()),
        role: EndpointRole::Beacon,
        ..TransportHandles::default()
    }
}

/// Build the rendezvous endpoint (see module docs for the one-beacon /
/// claim-if-free / identity-probe rationale). Public: one
/// ephemeral-port endpoint. Private: bind the first **free** ladder
/// rung; on `AddrInUse`, probe — *ours* ⇒ `None` (stay a peer),
/// *foreign* ⇒ next rung. `None` also covers public build failure /
/// every rung foreign-squatted (≈0); the next tick retries.
pub(crate) async fn build_rendezvous_endpoint(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    rungs: &mut RungWatch,
) -> Walk {
    let node = peer.id();
    let lookups = beacon_lookups(params);
    if params.answers_jsep() {
        // The public probe-before-claim that used to run here — the analog
        // of the private rung identity-probe below — now runs off the loop
        // (`spawn_rival_probe`), and `ensure` only reaches this point once
        // its verdict says the rendezvous is free. Everything left is a
        // bind.
        //
        // A public rendezvous carries the `WebRTC` transport and answers
        // JSEP: a browser-shaped peer has no IP to punch with, so on a mesh
        // whose relay is lookup only the data channel is the only path its
        // rendezvous link can ever be admitted on.
        let webrtc = lookup::build_webrtc_handle(params.secret.public());
        // Made before the endpoint: the endpoint reports its connections to it
        // from the first handshake on.
        let admission = transport::SignalAdmission::new(tuning::MAX_CONNECTIONS);
        let transport_handles = public_beacon_handles(&webrtc, &admission);
        let endpoint = build_endpoint(
            &lookups,
            Some(params.secret.clone()),
            None,
            Vec::new(),
            transport_handles,
        )
        .await
        .ok();
        if endpoint.is_some() {
            tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(), "beacon assumed: bound public rendezvous endpoint (ephemeral port)");
        } else {
            tracing::debug!(target: "habilis_network::beacon", "public beacon endpoint build failed; next tick retries");
        }
        return endpoint.map_or(Walk::Nothing, |endpoint| {
            Walk::Bound(endpoint, Some((webrtc, admission)))
        });
    }
    // The private ladder. The walk is instant: it binds a free rung when every lower rung is
    // foreign (by answer, or by silence for the whole window), reads what the probe tasks
    // reported about the busy ones, and asks for what it does not know.
    let now = Instant::now();
    let ladder: Vec<(usize, u16)> = params.bind_ports.iter().copied().enumerate().collect();
    for (index, port) in ladder {
        // The bind is what says that a rung is free, rung by rung: it is instant, and the answer
        // of a socket check could differ from it. A rung that does not bind is read.
        match build_endpoint(
            &lookups,
            Some(params.secret.clone()),
            Some(port),
            Vec::new(),
            TransportHandles {
                role: EndpointRole::Beacon,
                ..TransportHandles::default()
            },
        )
        .await
        {
            Ok(endpoint) => {
                tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "beacon assumed: bound rendezvous ladder rung");
                rungs.forget();
                rungs.clear_foreign(port);
                // No `WebRTC` on the ladder: a loopback mesh has no browsers.
                return Walk::Bound(endpoint, None);
            }
            Err(error) => {
                tracing::trace!(target: "habilis_network::beacon", node = %node.fmt_short(), port, %error, "rung does not bind: read it");
            }
        }
        match rungs.reading(port, now) {
            RungRead::Ours => {
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "rung already serves our beacon; staying peer");
                return Walk::Rival(port);
            }
            RungRead::Foreign | RungRead::SilentLongEnough => {
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "rung held by a foreign mesh, or silent for the whole window; trying next rung");
                rungs.mark_foreign(port);
                rung_ladder::forget_rungs(params, peer, peer_book, |rung| rung == port).await;
            }
            RungRead::Silent => {
                if rungs.refused(port) {
                    rung_ladder::forget_rungs(params, peer, peer_book, |rung| rung == port).await;
                }
                // A silent rung is not put in the book: nobody proved it to be ours, and a foreign
                // beacon on a loaded host reads silent before it reads foreign. The walk waits for
                // the reading to go stale and asks again, so that a rung that stays silent is bound
                // only once it has been silent for the whole window.
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "rung says nothing; staying peer for now");
                return Walk::Nothing;
            }
            RungRead::Unknown => {
                // This rung is asked, and so is every later rung that looks busy: eight silent
                // rungs are resolved in one window, not eight. The socket check only picks the
                // rungs to ask early; the walk itself binds or reads one rung at a time.
                rungs.ask(params, node, port, true);
                for &later_port in &params.bind_ports[index + 1..] {
                    if rung_is_busy(later_port)
                        && rungs.reading(later_port, now) == RungRead::Unknown
                    {
                        rungs.ask(params, node, later_port, true);
                    }
                }
                return Walk::Nothing;
            }
        }
    }
    tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), "no rendezvous ladder rung taken; staying peer");
    if params.bind_ports.is_empty() {
        Walk::Nothing
    } else {
        Walk::NoRung
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use iroh::SecretKey;

    use crate::lookup::{self, EndpointRole};
    use crate::transport;
    use crate::util::tuning;

    /// The beacon of a public rendezvous carries a `WebRTC` handle and is the beacon still: a role that
    /// the handles do not give is lost, and then the DHT publish does not run on the public path.
    #[test]
    fn the_beacon_of_a_public_rendezvous_has_the_beacon_role() {
        let _guard = ::habilis_network_test_tracing::init();
        let webrtc = lookup::build_webrtc_handle(SecretKey::generate().public());
        let admission = transport::SignalAdmission::new(tuning::MAX_CONNECTIONS);

        let handles = super::public_beacon_handles(&webrtc, &admission);

        assert_eq!(
            handles.role,
            EndpointRole::Beacon,
            "the public beacon has the beacon role, whatever transports it carries"
        );
        assert!(
            handles.webrtc.is_some(),
            "it still carries the WebRTC handle"
        );
    }
}
