//! The time budgets of the pool: dial, path selection, and the cooldowns.

use std::time::Duration;

/// How long an inline dial keeps trying before giving up. Deliberately short —
/// far under the application's 90s discovery deadline — because the dial blocks the send,
/// and an unreachable peer should surface as an error now, not stall the
/// caller. The addressee's `EndpointAddr` is already registered with the
/// endpoint (`add_peer_addr`), so a reachable peer resolves well inside this.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// After a failed dial the endpoint goes on cooldown: further cold sends to it
/// error immediately instead of re-dialing. The dial blocks the event loop, so
/// without this a burst of directed frames to one dead peer (a 16-shard repair
/// reply, a flushed backlog) serializes a [`DIAL_TIMEOUT`] stall per frame —
/// the cooldown bounds that to one stall per window per peer.
pub(super) const DIAL_FAILURE_COOLDOWN: Duration = Duration::from_secs(10);

/// The error of a cold send to a peer on the dial-failure cooldown.
pub(crate) const COOLDOWN_REFUSED: &str = "unicast dial on cooldown after a recent failure";

/// How long a *fresh* inline dial may wait for iroh to select a non-relay
/// path before the send is refused. Shorter than the accept side's
/// `PROBE_DEADLINE`: this wait blocks the event loop exactly like the dial
/// itself, so it gets a dial-sized budget, not an accept-sized one — and a
/// punch or a `WebRTC` path-open lands in single-digit seconds when it lands
/// at all.
pub(in crate::transport) const PATH_SELECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a connection stays busy after a send finished, if the peer has not read the frame. A
/// reader that is slower than this is not protected: the connection can be evicted under its frame.
pub(super) const BUSY_AFTER_FINISH: Duration = Duration::from_secs(2);

/// How long one send may take: the open of the stream and the write of the frame. A peer that accepts the
/// connection and reads nothing fills its limit of streams, and the open then waits. Each send sits in a task of
/// its own, so a wait without a bound grows the tasks of this node for as long as the peer makes it send. The
/// budget is the dial's, because a send that waits this long is as dead as a peer that does not answer a dial.
pub(super) const SEND_TIMEOUT: Duration = Duration::from_secs(3);

/// The error of a send that passed [`SEND_TIMEOUT`]. A caller that tells the two apart reads it.
pub(super) const SEND_TIMED_OUT: &str = "unicast send timed out";
