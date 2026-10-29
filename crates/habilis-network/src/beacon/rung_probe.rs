use std::net::{Ipv4Addr, SocketAddr};

use iroh::{Endpoint, EndpointAddr, EndpointId};

use crate::lookup::{ProbeAnswer, probe_answer};
use crate::util::tuning::RENDEZVOUS_PROBE;

/// Probe a `AddrInUse` private rung: is the listener *our* mesh's
/// rendezvous, or an unrelated mesh that happened to derive the same
/// port? A loopback `connect` to `rendezvous_id` succeeds only if the
/// listener presents that exact node id (iroh validates it during the
/// TLS handshake) — a foreign rendezvous (different key) is rejected,
/// a dead socket times out. Resolves in milliseconds against a live
/// loopback listener; the timeout only guards a pathological socket.
///
/// `prober` must be a **throwaway** endpoint, never this member's peer
/// endpoint, and that is a correctness requirement rather than hygiene.
/// The dial goes out on `GOSSIP_ALPN`, which is exactly what the beacon's
/// gossip accepts and adopts as a peer connection. Dialed from our own
/// endpoint it arrives as a second connection *from us*, and
/// `PeerState::accept_conn` promotes the newcomer to our **active**
/// connection, superseding the real one. Closing the probe then reads to
/// the beacon as our active connection dropping: it marks us
/// disconnected and emits `NeighborDown`. The probe would tear down the
/// very link whose existence it is asking about — and on a ticker, kill
/// it again every time it was re-established. From a throwaway identity
/// the beacon sees a stranger arrive and leave, which costs it nothing.
/// [`spawn_rival_probe`] takes the same precaution for the public path.
///
/// **One attempt, and four answers.** A rung whose listener failed the identity is foreign for
/// certain: the verifier rejected its key, or iroh reads the identity as another. A rung that
/// refused or said nothing is not: a busy or starting beacon of our own mesh refuses, a host too
/// loaded to answer reads as silence, and a bind cannot be taken back. So the walk binds on
/// [`ProbeAnswer::Foreign`] at once, and on silence or a refusal only after the rung has stayed
/// silent for [`RECLAIM_WINDOW`] across walks (see `build_rendezvous_endpoint`). A walk costs
/// one attempt on a silent rung, not three.
pub(crate) async fn rung_answer(
    prober: &Endpoint,
    rendezvous_id: EndpointId,
    port: u16,
) -> ProbeAnswer {
    let address = EndpointAddr::new(rendezvous_id)
        .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    let answer = probe_answer(prober, address, RENDEZVOUS_PROBE).await;
    tracing::trace!(target: "habilis_network::beacon", port, ?answer, "private rung identity-probe");
    answer
}

/// Tests only: the members whose rung probe says nothing whatever is there. It stands for a host
/// too loaded to answer, and it is per member: a process-wide dial would make every in-process
/// member misread at once, which is not what a loaded host does.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
static BLIND_RUNG_PROBES: std::sync::Mutex<std::collections::BTreeSet<EndpointId>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Make the rung probe of `member` read silence (`blind`), or let it read the truth again.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(crate) fn set_blind_rung_probes(member: EndpointId, blind: bool) {
    let mut members = BLIND_RUNG_PROBES.lock().expect("no poison");
    if blind {
        members.insert(member);
    } else {
        members.remove(&member);
    }
}

/// Whether a test made the rung probe of `member` read silence. It is always false outside the
/// `iroh-test-utils` build.
pub(crate) fn rung_probes_are_blind(member: EndpointId) -> bool {
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    {
        BLIND_RUNG_PROBES
            .lock()
            .expect("no poison")
            .contains(&member)
    }
    #[cfg(not(all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    {
        let _ = member;
        false
    }
}

/// Whether somebody holds `port`: a socket of ours cannot be bound there. Instant, and no side
/// effect, so a walk can tell which rungs of a ladder are busy without binding one.
pub(crate) fn rung_is_busy(port: u16) -> bool {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err()
}
