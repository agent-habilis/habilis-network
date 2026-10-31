//! The lookup layer: building the iroh endpoint for a mesh mode and
//! wiring the selected lookups onto it. Each lookup mechanism lives in
//! its own submodule — [`mdns`] (LAN multicast), [`dht`] (mainline DHT),
//! and [`relay`] (the relay ladder + bootstrap-rung selection/failover).

mod build_mesh;

mod address_book;

mod underlay_leg;

mod peer;

mod probe;
mod probe_answer;

mod lan;
mod lan_event;
mod mdns_handle;

mod endpoint;

#[cfg(feature = "host")]
mod capability;
#[cfg(all(feature = "host", feature = "dht"))]
mod dht;
mod error;
#[cfg(all(feature = "host", feature = "mdns"))]
mod mdns;
mod relay;
mod transport_handles;
mod transport_opts;

// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

/// A local relay server every side of a test can reach: plain HTTP, so the
/// engine dials `ws://` with no TLS — and so can a **browser**, which owns
/// its own trust store and refuses a self-signed certificate with no
/// override (`iroh::test_utils::run_relay_server` is https-only). No QUIC
/// address discovery: a tab has no UDP, and the tests that use this force
/// the relay to be the only path anyway.
#[cfg(all(any(test, feature = "iroh-test-utils"), not(target_arch = "wasm32")))]
#[cfg_attr(
    not(feature = "iroh-test-utils"),
    expect(
        unreachable_pub,
        reason = "`net` re-exports it only with `iroh-test-utils`"
    )
)]
pub mod test_relay;

#[cfg(feature = "host")]
pub use capability::{NetworkCapability, probe as capability_probe};
pub use error::EndpointError;
pub use relay::{RENDEZVOUS_RELAY_LADDER, probe_ladder, relay_ladder};
pub(crate) use relay::{
    RungRefresh, StoppableTask, plan_rung_refresh, select_bootstrap_rung, spawn_relay_monitor,
};
pub use transport_handles::TransportHandles;
pub use transport_opts::TransportOpts;

#[cfg(all(feature = "multihop", not(feature = "host")))]
pub(crate) use peer::browser_handle_config;
#[cfg(all(feature = "host", test))]
pub(crate) use peer::build_peer_multihop;
#[cfg(feature = "multihop")]
pub(crate) use peer::build_peer_multihop_with;
#[cfg(feature = "multihop")]
pub use peer::multihop_handle_config;
pub use peer::{build_peer_endpoint, build_peer_webrtc};
pub(crate) use peer::{build_peer_webrtc_with, build_webrtc_handle, check_injected_against_mesh};

pub use probe::probe_connect;
pub(crate) use probe_answer::{ProbeAnswer, probe_answer};

pub use endpoint::build_endpoint;

pub(crate) use build_mesh::build_mesh;

pub(crate) use address_book::replace_peer_addr;
pub use address_book::{add_peer_addr, address_book};

#[cfg(all(feature = "host", feature = "iroh-test-utils"))]
pub use underlay_leg::set_underlay_leg_off;
#[cfg(feature = "multihop")]
pub(crate) use underlay_leg::underlay_cap;

pub(crate) use endpoint::install_transports;
pub(crate) use lan::{build_endpoint_keeping_mdns, lan_contacts};
pub(crate) use lan_event::LanEvent;
pub use mdns_handle::MdnsHandle;

#[cfg(test)]
mod tests;
