/// Label of the single data channel each session carries. Both ends must use
/// the same string or the channel never opens.
pub const DATA_CHANNEL_LABEL: &str = "iroh";

/// Bound on queued outbound datagrams per session. Overflow drops the datagram
/// (QUIC above retransmits); blocking would stall iroh's shared send loop
/// across every transport.
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) const OUT_QUEUE: usize = 256;

/// Bound on inbound datagrams fanned in from all sessions toward QUIC.
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) const IN_QUEUE: usize = 512;

/// The default STUN servers, as `host:port`. Both backends derive their own
/// spelling from this — the native gather uses these verbatim, the browser
/// prefixes each with `stun:`.
///
/// Two servers, deliberately, and from two *operators* — that is the redundancy
/// that counts, so one being down is not an outage. These only ever learn our
/// public ip:port; no traffic flows through them.
///
/// `stun1`, not the bare `stun.l.google.com`: blocklists name the latter
/// explicitly and null-route it to 0.0.0.0, which is worse than NXDOMAIN — the
/// agent waits out a timeout on an unroutable address instead of failing fast.
/// Measured behind an `AdGuard` resolver: `stun.l.google.com` → 0.0.0.0,
/// `stun1..4.l.google.com` → 74.125.250.129. `stun2/3/4` share one address with
/// `stun1`, so they would be redundancy in name only, and every extra server
/// costs a srflx candidate per local interface.
pub const DEFAULT_STUN_HOSTS: [&str; 2] = ["stun1.l.google.com:19302", "stun.cloudflare.com:3478"];
