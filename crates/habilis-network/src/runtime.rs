//! Standing a node up and driving it: resolve inputs, build the config, run.
//!
//! The whole lifecycle is three calls — `Params::resolve()` →
//! [`setup_mesh`] → [`Node::spawn`] (or [`run`] for a consumer that owns the
//! task itself). [`EventLoopConfig`] is opaque between the second and third.

pub use crate::daemon::config::{
    CoHostPolicy, DIRECTORY_ADVERTISER_COHOST, DriverMode, EventLoopConfig,
};
pub use crate::daemon::event_loop::run;
pub use crate::daemon::node::Node;
pub use crate::daemon::params::{
    CreateParams, JoinParams, Resolved, TopicParams, derive_topic_mesh, derive_topic_mesh_config,
    derive_topic_mesh_with,
};
pub use crate::daemon::setup::{
    BROWSER_HAS_NO_PATH, BROWSER_NEEDS_RELAY_LOOKUP, InjectedEndpoint, SetupKind, SetupParams,
    refuse_in_browser, setup_mesh,
};
#[cfg(feature = "host")]
pub use crate::daemon::validate_owner_pid;

/// The session state file the daemon writes for external readers — its sole
/// writer. Daemon-session state, not a generic filesystem helper.
///
/// Host-only: a browser has no filesystem to write it to. The node itself runs
/// fine without one — the state file is a readout for external processes, not
/// something the loop depends on.
#[cfg(feature = "host")]
pub mod state_file {
    pub use crate::daemon::state_file::{
        ReadySnapshot, SessionEntry, SessionIdentity, StateFile, read_identity, read_session_entry,
        read_snapshot,
    };
}

/// The local control socket a CLI-driven daemon serves, and its client half.
///
/// Host-only: unix sockets and named pipes have no wasm32 equivalent. An
/// in-process driver — which is what a browser always is — takes typed requests
/// through [`Node::send`] instead, and binds nothing.
#[cfg(feature = "host")]
pub mod ipc {
    pub use crate::transport::ipc::{
        Addressed, NoDaemon, active_socket_paths, json_ack, json_error, json_ok_msg, send,
        send_to_path,
    };
}

/// Per-process dials, installed once at startup. No environment variables:
/// every knob is a `const` default a consumer may override through this.
pub mod tuning {
    pub use crate::util::tuning::{
        NODE_INBOUND_CAP, POLL_LONG_MIN_CYCLE_MS, READY_FRESH_SECS, READY_MAX_SECS,
        READY_POLL_INTERVAL_MS, Tuning, advertise_interval_secs, directory_expiry_secs,
        directory_private_for_test, init, ping_window_secs,
    };
}
