// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};

/// Bounded `GOSSIP_ALPN` connect-probe. On a mesh whose relay is lookup
/// only the far side's accept gate holds and finally closes this connection;
/// the probe wants only the resolution side effect, so that is harmless.
/// Dialing forces iroh to
/// (re)resolve and (re)path `target` via the configured
/// address-lookups; the connection is only ever wanted for that side
/// effect. `true` iff a connection was established within `timeout`
/// (a foreign / dead / unreachable target yields `false`); callers
/// wanting only the resolution side effect ignore the bool.
pub async fn probe_connect(endpoint: &Endpoint, target: EndpointAddr, timeout: Duration) -> bool {
    super::probe_answer::probe_answer(endpoint, target, timeout).await
        == super::probe_answer::ProbeAnswer::Ours
}
