use std::net::SocketAddr;

use serde::Serialize;

/// This machine's network capability, read from iroh's net-report — the data
/// behind `doctor`'s Network section and its hole-punch verdict. The
/// net-report fields are `Option` because the endpoint can bind locally even
/// when no report completes (offline / slow): then only `node_id` /
/// `local_addrs` are known and the rest stay `None`.
///
/// # Examples
///
/// A network capability names the node and the addresses that it can be reached at. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::NetworkCapability;
///
/// # fn demo(capability: NetworkCapability) -> String {
/// capability.node_id
/// # }
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct NetworkCapability {
    /// The node id, in hex.
    pub node_id: String,
    /// The local addresses of the node.
    pub local_addrs: Vec<SocketAddr>,
    /// `false` ⇒ no net-report finished within the probe budget; the fields
    /// below are then all `None` (we can't distinguish "unknown" from "no").
    pub report_obtained: bool,
    /// Whether `IPv4` UDP works.
    pub udp_v4: Option<bool>,
    /// Whether `IPv6` UDP works.
    pub udp_v6: Option<bool>,
    /// The hole-punch signal: `Some(false)` ⇒ endpoint-independent NAT (direct
    /// hole punching works); `Some(true)` ⇒ address-dependent (symmetric) NAT
    /// (direct punch unlikely, traffic relays); `None` ⇒ insufficient probes.
    pub mapping_varies_by_dest: Option<bool>,
    /// The public `IPv4` address, if known.
    pub public_v4: Option<String>,
    /// The public `IPv6` address, if known.
    pub public_v6: Option<String>,
    /// The relay that the node prefers, if any.
    pub preferred_relay: Option<String>,
    /// The latency to the preferred relay, in milliseconds.
    pub preferred_relay_latency_ms: Option<u64>,
    /// Whether a captive portal was seen.
    pub captive_portal: Option<bool>,
}
