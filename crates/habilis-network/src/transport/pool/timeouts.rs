//! The time budgets of the pool: dial, path selection, and the cooldowns.

use std::time::Duration;

use crate::util::tuning::QUIC_PATH_IDLE_TIMEOUT;

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

/// The error of a probe that the ceiling refuses: the node is at its ceiling of direct connections,
/// and a probe that no send waits on evicts nobody.
pub(crate) const AT_CEILING: &str = "unicast dial skipped: the node is at its ceiling";

/// The error of a cold send to a peer on the dial-failure cooldown.
pub(crate) const COOLDOWN_REFUSED: &str = "unicast dial on cooldown after a recent failure";

/// How long a *fresh* inline dial may wait for iroh to select a non-relay
/// path before the send is refused. Shorter than the accept side's
/// `PROBE_DEADLINE`: this wait blocks the event loop exactly like the dial
/// itself, so it gets a dial-sized budget, not an accept-sized one — and a
/// punch or a `WebRTC` path-open lands in single-digit seconds when it lands
/// at all.
pub(super) const PATH_SELECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a pinned connection, one that rides multihop for a peer that the node could not dial
/// directly, stays open with no send. It is shorter than the idle timeout of a direct connection: a
/// route through other members costs the members that forward for it.
pub(crate) const PINNED_IDLE: Duration = super::super::ceiling::EXTRA_IDLE;

/// The error of a redial that the pool does not make: the peer is pinned, and a route that pinned it
/// may be gone. The next send plans the dial with a fresh route.
pub(super) const PINNED_REDIAL: &str = "pinned peer: the next send plans a fresh route";

/// How long the open of the stream and the write of the frame may take. Both are local: a peer that
/// accepts the connection and reads nothing fills its limit of streams, and the open then waits.
/// Each send sits in a task of its own, so a wait without a bound grows the tasks of this node for
/// as long as the peer makes it send. The budget is the dial's, because a send that waits this long
/// is as dead as a peer that does not answer a dial.
pub(super) const SEND_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a send waits for the peer: once for `HELD`, and once for the end of the frame. The
/// transport under the connection can need its whole path idle timeout to leave a path that died
/// with no signal, and then the frame needs the time of a normal send, which is [`SEND_TIMEOUT`]. A
/// shorter wait turns every failover of a path into a failed send. The cost is the same number: a
/// send to a peer that is gone answers "not delivered" after this time, and the connection is busy
/// in the ledger until then. One send waits at most [`SEND_TIMEOUT`] and this time twice, and the
/// pool sends a second time after a lost connection, so one call waits at most twice that.
pub(crate) const SEND_ANSWER_TIMEOUT: Duration =
    QUIC_PATH_IDLE_TIMEOUT.saturating_add(SEND_TIMEOUT);

/// The error of a send that passed [`SEND_TIMEOUT`] or [`SEND_ANSWER_TIMEOUT`]. A caller that tells
/// the two apart reads it.
pub(super) const SEND_TIMED_OUT: &str = "unicast send timed out";
