//! What a bind of the IPC endpoint gives back.

use interprocess::local_socket::tokio::Listener;

#[cfg(windows)]
use super::ipc_marker::IpcMarker;

/// What [`bind`](super::listener::bind) gives back: the accepting listener, and
/// on Windows the marker that makes it findable.
pub(crate) struct Bound {
    pub(crate) listener: Listener,
    #[cfg(windows)]
    pub(crate) marker: IpcMarker,
}
