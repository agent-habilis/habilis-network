//! A transport waiting for the node's sender.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::mesh::mailboxes::Mailboxes;
use crate::mesh::mesh_transport::MeshTransport;
use crate::mesh::outbound::Outbound;

use std::fmt;
/// A transport waiting for the node's sender.
///
/// See [`RollbackDriver::new`].
///
/// # Examples
///
/// A pending transport becomes a transport once it is given the outbound channel, and it knows no peers at first.
///
/// ```
/// use habilis_network_netplay::{Outbound, RollbackDriver};
///
/// use habilis_network_netplay::Config;
///
/// struct Game;
///
/// impl Config for Game {
///     type Input = u8;
///     type State = u32;
///     type Address = u8;
/// }
///
/// let (_driver, pending) = RollbackDriver::<Game>::new();
/// let (outbox, _inbox) = tokio::sync::mpsc::channel::<Outbound>(8);
/// let transport = pending.connect(outbox);
/// assert!(transport.known_peers().next().is_none());
/// ```
#[derive(Clone)]
pub struct PendingTransport<T: Config> {
    // the pending transport shares the mailboxes with the driver
    mailboxes: Arc<Mailboxes<T>>,
}

impl<T: Config> fmt::Debug for PendingTransport<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTransport")
            .finish_non_exhaustive()
    }
}

impl<T: Config> PendingTransport<T> {
    // the pending transport shares the mailboxes with the driver
    pub(super) fn new(mailboxes: Arc<Mailboxes<T>>) -> Self {
        Self { mailboxes }
    }

    /// Finish wiring, given `Node::sender()`.
    #[must_use]
    pub fn connect(self, outbox: mpsc::Sender<Outbound>) -> MeshTransport<T> {
        MeshTransport::new(self.mailboxes, outbox)
    }
}
