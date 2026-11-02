mod ipc_request;
mod node_driver;

// `embed` re-exports it only on host, so off host nothing outside the crate names it.
#[cfg(feature = "host")]
pub use ipc_request::IpcRequest;
#[cfg(not(feature = "host"))]
pub(crate) use ipc_request::IpcRequest;
pub use node_driver::NodeDriver;
