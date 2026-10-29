use iroh::Endpoint;
use iroh::address_lookup::memory;

use crate::util::clock::Instant;

use crate::lookup::{TransportHandles, build_endpoint};

use super::rung_ladder::{admit_rung, forget_rungs};
use super::{RendezvousParams, RungRead, RungWatch, Walk, beacon_lookups, rung_is_busy};

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
        let webrtc = crate::lookup::build_webrtc_handle(params.secret.public());
        // Made before the endpoint: the endpoint reports its connections to it
        // from the first handshake on.
        let admission = crate::transport::SignalAdmission::new(crate::transport::MAX_DIRECT_PEERS);
        let transport_handles = TransportHandles {
            webrtc: Some(webrtc.clone()),
            admission: Some(admission.clone()),
            ..TransportHandles::default()
        };
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
    for (index, &port) in params.bind_ports.iter().enumerate() {
        // The bind is what says that a rung is free, rung by rung: it is instant, and the answer
        // of a socket check could differ from it. A rung that does not bind is read.
        match build_endpoint(
            &lookups,
            Some(params.secret.clone()),
            Some(port),
            Vec::new(),
            TransportHandles::default(),
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
                forget_rungs(params, peer, peer_book, |rung| rung == port).await;
            }
            RungRead::Silent => {
                if rungs.refused(port) {
                    forget_rungs(params, peer, peer_book, |rung| rung == port).await;
                } else {
                    admit_rung(params, peer, peer_book, port).await;
                }
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "rung says nothing; staying peer for now");
                return Walk::Nothing;
            }
            RungRead::Unknown => {
                // This rung is asked, and so is every later rung that looks busy: eight silent
                // rungs are resolved in one window, not eight. The socket check only picks the
                // rungs to ask early; the walk itself binds or reads one rung at a time.
                rungs.ask(params, node, port, true);
                for &later_port in params.bind_ports.iter().skip(index + 1) {
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
