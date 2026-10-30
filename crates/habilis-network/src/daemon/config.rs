//! Inputs the event loop is constructed from.
//!
//! [`EventLoopConfig`] is produced by `daemon::setup::setup_mesh` and
//! consumed by [`daemon::run`](super::run). Split out of `mod.rs` so the
//! orchestrator file reads as pure lifecycle narrative.

mod co_host_policy;
pub use co_host_policy::{CoHostPolicy, DIRECTORY_ADVERTISER_COHOST};
mod driver_mode;
pub use driver_mode::DriverMode;
mod endpoint_owner;
pub(crate) use endpoint_owner::EndpointOwner;
mod event_loop_config;
pub use event_loop_config::EventLoopConfig;

pub(crate) use event_loop_config::{
    Endpoints, MeshSpec, RendezvousConfig, RuntimeConfig, TransportSet,
};
