// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

use iroh::EndpointAddr;

/// What the LAN says about the other members of our mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(all(feature = "host", feature = "mdns")),
    expect(
        dead_code,
        reason = "only the mDNS forwarder makes these, and it needs `host` and `mdns`"
    )
)]
pub(crate) enum LanEvent {
    /// A member of our mesh announced itself, with the addresses it announced.
    Seen(EndpointAddr),
    /// A record expired. It may name an endpoint that was never a member: the listener ignores it
    /// when it holds nothing for the id.
    Gone(iroh::EndpointId),
}
