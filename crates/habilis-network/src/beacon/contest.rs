use iroh::address_lookup::memory;
use iroh::{Endpoint, EndpointId};

use super::{Held, Rendezvous, RendezvousParams, RungWatch, claim};

/// Two holders of one beacon: this node and a rival that it has read. One struct for the pair,
/// because both are an `EndpointId` and a swap compiles and flips the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Contest {
    pub(crate) own: EndpointId,
    pub(crate) rival: EndpointId,
}

impl Contest {
    /// Whether this holder lets go of its beacon for the rival: the lower member id keeps the
    /// rendezvous. Both holders compute it from the same two ids, so exactly one yields.
    pub(crate) fn own_yields(self) -> bool {
        self.rival < self.own
    }
}

/// Apply an off-loop probe's verdict: claim the rendezvous if it is free.
///
/// Re-checks the beacon slot first, because up to [`HEAL_PROBE`] passed
/// while the probe ran and the loop kept moving — a reclaim tick or a
/// re-stand-up may have taken the role in the meantime, and claiming twice
/// binds the duplicate same-id copy the probe exists to prevent.
pub(crate) async fn claim_after_probe(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    found_rival: bool,
    rungs: &mut RungWatch,
) -> bool {
    if found_rival {
        tracing::debug!(target: "habilis_network::beacon", node = %peer.id().fmt_short(), "public rendezvous already served by a beacon; staying peer");
        return false;
    }
    if !releasable(current) {
        return false;
    }
    claim::claim_holder(params, peer, peer_book, current, rungs).await == Held::Claimed
}

/// Whether the beacon slot is free to (re)claim: empty, or holding a
/// rendezvous whose co-host task has ended.
///
/// A dead one is [`Rendezvous::shed`], never dropped: the co-host *task*
/// ending says nothing about the endpoint, which is still open and still
/// registered under `rendezvous_id`. Dropping it there abandons a live socket
/// — iroh logs `Endpoint dropped without calling Endpoint::close` and joiners
/// keep resolving to a corpse until the QUIC idle timeout.
pub(crate) fn releasable(current: &mut Option<Rendezvous>) -> bool {
    if current
        .as_ref()
        .is_some_and(|rendezvous| !rendezvous.task.is_finished())
    {
        return false;
    }
    if let Some(dead) = current.take() {
        tracing::info!(target: "habilis_network::beacon", "beacon released (co-host task ended); attempting re-stand-up");
        dead.shed();
    }
    true
}
