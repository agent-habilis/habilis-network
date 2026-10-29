//! A transport waiting for the node's sender.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::mesh::mailboxes::Mailboxes;
use crate::mesh::mesh_transport::MeshTransport;
use crate::mesh::outbound::Outbound;

/// A transport waiting for the node's sender.
///
/// See [`RollbackDriver::new`].
pub struct PendingTransport<T: Config> {
    // the pending transport shares the mailboxes with the driver
    mailboxes: Arc<Mailboxes<T>>,
}

impl<T: Config> std::fmt::Debug for PendingTransport<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
