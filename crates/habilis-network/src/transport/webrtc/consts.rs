//! The ALPNs, the deadlines and the direct-peer cap of the WebRTC plane.

use std::time;
/// ALPN for the JSEP exchange. Wire-load-bearing in the same way
/// `crate::transport::UNICAST_ALPN` is: both ends must agree, so it moves only with a
/// deliberate protocol break.
pub const MESH_WEBRTC_SIGNAL_ALPN: &[u8] = b"habilis-mesh/webrtc-signal/1";

/// How long to let one negotiation run before giving up.
///
/// Generous because it covers candidate gathering on both sides plus the
/// DTLS/SCTP handshake, and a false timeout costs the whole session. Note the
/// browser side gathers with a vanilla-ICE budget of its own (candidates ride
/// inside the SDP; there is no trickle message), so this must comfortably
/// exceed it.
///
/// Compiled on both targets so the arithmetic below is target-independent.
/// Only the native backend passes it *into* str0m — the browser backend takes
/// no deadline parameter at all, so for a tab [`SignalDeadlines::round`] is the
/// only bound that exists.
#[cfg_attr(
    target_arch = "wasm32",
    expect(
        dead_code,
        reason = "the browser backend takes no deadline; kept on both targets per the note above"
    )
)]
pub(crate) const JSEP_DEADLINE: time::Duration = time::Duration::from_secs(20);

/// One leg of the envelope exchange: dial, open, write, then wait for the
/// peer's envelope.
///
/// The wait covers the *peer's* SDP construction, which is the expensive part.
/// A browser answerer pays a TURN-credential fetch (≤1.5s) plus a full
/// vanilla-ICE gathering budget (≤10s) before its answer exists; a CLI answerer
/// pays up to two 2s STUN probes. 20s is comfortably past the worst honest path
/// and leaves room for a relay round trip on a throttled tab.
pub(crate) const SIGNAL_EXCHANGE_DEADLINE: time::Duration = time::Duration::from_secs(20);

/// The whole round, either role.
///
/// Strictly greater than the sum of the two legs, so that in every honest
/// failure an *inner* deadline fires first and names the phase; this one only
/// catches a peer that stalls somewhere with no budget of its own. It also sits
/// below two `alive` ticks, so a peer that always times out is retried on the
/// following tick rather than being skipped indefinitely.
pub(crate) const SIGNAL_ROUND_DEADLINE: time::Duration = time::Duration::from_secs(45);

/// The default of C, the ceiling of direct connections one node holds (64): the `WebRTC`
/// sessions and the unicast connections together. A node sets its own with
/// `SetupParams::max_direct`; `0` takes this value.
///
/// It is deliberately not the same knob as HyParView's `active_view_capacity` (G): that one
/// sizes the gossip overlay and is fixed when the mesh is built. Each direct connection costs
/// memory and, in a browser, up to a full ICE gathering budget — so the ceiling is real, not
/// notional. A newcomer past C evicts the least valuable peer, see
/// `crate::transport::ceiling`; no offer is refused for it.
///
/// Public so the CLI and the browser can render a denominator. A node with its
/// own ceiling reports it with [`crate::transport::admission::SignalAdmission::cap`], because
/// this constant is only the default.
pub const MAX_DIRECT_PEERS: usize = 64;

/// The ALPN a nudge connects on. Its acceptor ([`super::nudge_acceptor::NudgeAcceptor`]) closes
/// every connection at once: the connect exists only for what iroh does when
/// it completes, which is to try the UDP punch again and re-run path selection
/// over every connection to the peer, moving them onto a newly attached
/// session's path or back to UDP. A connect that fails does neither. Not the
/// signal ALPN (its acceptor detaches a session on a fresh connection) nor
/// unicast (its acceptor holds a connection).
pub const NUDGE_ALPN: &[u8] = b"habilis-mesh/nudge/0";
