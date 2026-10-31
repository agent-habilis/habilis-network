//! The offer round: sends one offer and waits for its answer.

use super::{dial_signal, nudge_acceptor};
use crate::daemon::handler_ctx::HandlerCtx;
use crate::transport::admission::AdmissionGuard;

use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use iroh::{EndpointAddr, EndpointId};

use crate::transport::LOG_TARGET;

use crate::daemon::state;
use crate::lookup::EndpointError;
use crate::transport::probe;

use n0_future::task;
use n0_future::time::Instant;
/// What an offer is for, which decides what happens once its session attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    /// The rendezvous: graft at once, and say so.
    Rendezvous,
    /// The rendezvous, while its link is up on the relay: the link is the graft, so only the
    /// connection is nudged onto the session.
    RendezvousLinked,
    /// A pair that needs the lane: graft at once.
    Lane,
    /// A pair with UDP on both ends: detach instead if UDP won. Only this kind
    /// waits on that check, which dials the unicast lane: a lane pair's graft
    /// has to fire inside the freshly proven window, and the rendezvous accepts
    /// no unicast at all. The check holds the admission slot for up to 8 s
    /// after the round (a 3 s dial, then 5 s for UDP to be selected).
    UdpRace,
    /// A pair with UDP on both ends whose direct path is known dead (its proof was stale and
    /// was taken back): nothing to judge, so the frames parked for it flush at once. The
    /// connection that was open before the attach is nudged onto the session, as in the race.
    AfterLoss,
}

/// The shared tail of every offer: hold the admission slot in a spawned
/// task (released by `Drop`, so the slot comes back whether the task
/// returns, is dropped, or is aborted at shutdown), run the JSEP round,
/// note a cap refusal — and on attach report the proven path, so the
/// loop's `DirectOutcome` arm grafts inside the freshly proven window.
/// Without that send nothing ever moves a webrtc-shaped peer out of
/// `Pending`: the session attaches and the graft still never fires
/// (observed native↔browser: `links_pending=1` for the life of a cell).
/// Written once — the two offer entry points had grown diverging copies.
pub(crate) fn spawn_offer_round(
    state: &mut state::EventLoopState,
    context: &HandlerCtx<'_>,
    peer: EndpointId,
    address: EndpointAddr,
    handle: WebRtcHandle,
    guard: AdmissionGuard,
    offer: Offer,
) {
    let endpoint = context.endpoint.clone();
    let book = state.address_book.clone();
    let admission = state.webrtc_admission.clone();
    let ice = state.webrtc_ice;
    let proven = state.direct_proven.clone();
    let pool = state.unicast_pool.clone();
    let epoch = guard.epoch();
    let node = endpoint.id();
    let task = task::spawn(async move {
        let _guard = guard;
        let started = Instant::now();
        tracing::debug!(target: LOG_TARGET, node = %node.fmt_short(), %peer, book = ?book.get_endpoint_info(peer), "offer round started");
        if let Err(error) = Box::pin(dial_signal(&endpoint, &book, address, &handle, ice)).await {
            if matches!(error, EndpointError::CapRefused { .. }) {
                admission.note_refused(peer);
            }
            tracing::debug!(target: LOG_TARGET, %peer, %error, age_ms = started.elapsed().as_millis(), "webrtc offer failed");
            return;
        }
        tracing::debug!(target: LOG_TARGET, node = %node.fmt_short(), %peer, age_ms = started.elapsed().as_millis(), "offer round ended: signalled");
        // The peer took the round: it is not refusing us, so its wait starts over.
        admission.note_success(peer);
        admission.sync_gossip();
        // A connection opened before the attach rides the session only after a connect.
        if matches!(
            offer,
            Offer::UdpRace | Offer::AfterLoss | Offer::RendezvousLinked
        ) {
            nudge_acceptor::nudge_session(&endpoint, peer).await;
        }
        // The race is judged on the connection after the nudge.
        if offer == Offer::UdpRace && pool.udp_won(peer).await {
            // UDP won while the round ran: the session would sit unused and hold
            // one of the direct-peer slots.
            if handle.detach(&peer) {
                tracing::debug!(target: LOG_TARGET, %peer, "udp won the race; webrtc session detached");
            }
        } else if offer == Offer::RendezvousLinked {
            tracing::info!(target: LOG_TARGET, %peer, "webrtc session attached to the linked rendezvous");
        } else {
            if offer == Offer::Rendezvous {
                tracing::info!(target: LOG_TARGET, %peer, "webrtc session attached to the rendezvous");
            }
            let _ = proven.send(probe::DirectOutcome {
                peer,
                direct: true,
                answered: false,
            });
        }
    });
    state
        .webrtc_admission
        .track(peer, epoch, task.abort_handle());
}
