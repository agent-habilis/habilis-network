//! Which peer pairs need a WebRTC lane.

use super::udp_transport::UdpTransport;

use iroh::EndpointAddr;

/// Start a `WebRTC` negotiation with `peer`, if one is wanted and not already
/// running. Fire-and-forget: the caller does **not** wait, and the graft
/// proceeds over whatever path is available.
///
/// An earlier version of this gated the graft — held the peer out of the gossip
/// overlay until a direct session existed — on the theory that iroh will not
/// move a live connection onto a transport attached later, so a link formed
/// first stays on the relay. That reasoning is correct, but the cure was worse:
/// running it against a real CLI peer and two browser peers, the CLI reached
/// `link_len=0, meshed=false` and never joined the overlay at all. The
/// higher-id side waits to be dialled, the lower-id side only dials when it
/// sees a `PeerInfo`, and when that ordering does not line up the pair simply
/// never links. Mesh membership is the thing that must not be fragile.
///
/// So: gossip links form immediately, over the relay if that is what is
/// available, and the direct session is negotiated alongside. Connections
/// opened *after* attach — unicast, blob — take the `WebRTC` path. The gossip
/// link for that pair may stay relayed, which is a real cost and the reason
/// `peers_direct` and `peers_gossip` are reported separately rather than as one
/// number.
///
/// **Who offers is decided by id order** — the lower `EndpointId` dials. Both
/// sides compute the same answer with no round trip, so simultaneous mutual
/// offers (which collide on duplicate attach) cannot happen. This mirrors the
/// tie-break `lifecycle` already applies to the gossip dial itself.
/// Does this peer need the `WebRTC` lane to be reachable at all?
///
/// True only when it advertises no IP transport whatsoever — the shape of a
/// browser, which has no IP stack under wasm and so publishes relay addresses
/// only, and of a native peer deliberately run with its IP transports cleared.
///
/// A native peer still discovering its own addresses briefly advertises none.
/// That reads as "unknown" rather than "browser", so no lane is opened for it,
/// and the next `retry_sessions` round sees the settled address.
/// An address carrying *no* transports is not a browser, it is a peer we know
/// nothing about yet, and the two must not be confused. The retry pass had no
/// address to hand and built a bare one, so every native peer read as relay-only
/// and got a data channel it did not need — spending the direct-peer slots the
/// browsers were waiting for.
pub(crate) fn needs_webrtc_lane(addr: &EndpointAddr) -> bool {
    !addr.is_empty() && addr.ip_addrs().next().is_none()
}

/// The local-node twin of [`needs_webrtc_lane`]: does *this* node need the
/// lane? Answered from the node's own transport set, never from its address
/// snapshot — that snapshot is empty while the relay link is down, and empty
/// reads as "unknown" for a remote but must not for ourselves. A wasm node
/// reads `false`: `TransportOpts::within` clears UDP there.
pub(crate) fn local_needs_webrtc_lane(has_udp_transport: UdpTransport) -> bool {
    has_udp_transport == UdpTransport::Absent
}
