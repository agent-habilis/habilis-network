//! The [`Transport`] the session drives, backed by the driver's mailboxes.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::mesh::driver::{Mailboxes, Outbound, RollbackDriver, encode};
use crate::transport::{Message, Transport};

/// A [`Transport`] over a habilis-network mesh.
///
/// Addresses are peers' public keys — the signed identity on every frame,
/// not the cosmetic nickname.
pub struct MeshTransport<T: Config> {
    mailboxes: Arc<Mailboxes<T>>,
    outbox: mpsc::Sender<Outbound>,
}

/// Cloning shares the mailboxes rather than copying them, which is what
/// lets a consumer keep one handle for the lobby and hand another to each
/// successive match's session — [`P2PSession`](crate::P2PSession) takes
/// its transport by value, so without this a session could only ever be
/// built once.
///
/// Only **one** clone may be driven as a [`Transport`] at a time.
/// [`Transport::receive_all`] drains the shared inbound mailbox, so two
/// live sessions would steal each other's packets. One match at a time is
/// the intended shape; the lobby handle never implements that half.
impl<T: Config> Clone for MeshTransport<T> {
    fn clone(&self) -> Self {
        Self {
            mailboxes: Arc::clone(&self.mailboxes),
            outbox: self.outbox.clone(),
        }
    }
}

impl<T: Config> std::fmt::Debug for MeshTransport<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshTransport")
            .field("capacity", &self.outbox.max_capacity())
            .finish_non_exhaustive()
    }
}

impl<T: Config> RollbackDriver<T> {
    /// Build a driver and the transport that talks to it.
    ///
    /// Hand the driver to `Node::spawn`, then pass the node's
    /// `sender()` to [`PendingTransport::connect`] to finish wiring:
    ///
    /// ```ignore
    /// let (driver, pending) = RollbackDriver::<MyGame>::new();
    /// let node = Node::spawn(config, driver, None, false);
    /// let transport = pending.connect(node.sender());
    /// ```
    ///
    /// Split in two because the outbound channel only exists once the node
    /// has been spawned, and the node needs the driver to spawn.
    #[must_use]
    pub fn new() -> (Self, PendingTransport<T>) {
        let mailboxes = Arc::new(Mailboxes::new());
        (
            Self::from_mailboxes(Arc::clone(&mailboxes)),
            PendingTransport { mailboxes },
        )
    }
}

/// A transport waiting for the node's sender.
///
/// See [`RollbackDriver::new`].
pub struct PendingTransport<T: Config> {
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
    /// Finish wiring, given `Node::sender()`.
    #[must_use]
    pub fn connect(self, outbox: mpsc::Sender<Outbound>) -> MeshTransport<T> {
        MeshTransport {
            mailboxes: self.mailboxes,
            outbox,
        }
    }
}

impl<T: Config> MeshTransport<T> {
    /// Queue a lobby packet for every peer in the mesh roster.
    pub fn broadcast_lobby<S: serde::Serialize>(&self, value: &S) {
        if let Some(payload) = encode(value) {
            let _ = self.outbox.try_send(Outbound::Lobby { payload });
        }
    }

    /// Take every lobby packet received since the last call, as
    /// `(sender public key, raw JSON)`.
    #[must_use]
    pub fn drain_lobby(&self) -> Vec<(String, String)> {
        self.mailboxes
            .lobby
            .lock()
            .map(|mut lobby| std::mem::take(&mut *lobby))
            .unwrap_or_default()
    }

    /// This peer's own public key, once the node's event loop has started.
    ///
    /// `None` until then: the identity comes from `HandlerCtx`, which does
    /// not exist before `Node::spawn`. Poll it before building a
    /// [`super::Lobby`].
    #[must_use]
    pub fn local_pubkey(&self) -> Option<String> {
        self.mailboxes
            .local_pubkey
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    /// Whether a peer's public key can be addressed yet — true once we have
    /// received any frame from them.
    #[must_use]
    pub fn knows(&self, pubkey: &str) -> bool {
        self.mailboxes
            .directory
            .lock()
            .is_ok_and(|directory| directory.contains_key(pubkey))
    }

    /// Every peer we can address, as `(public key, nickname)`.
    #[must_use]
    pub fn known_peers(&self) -> Vec<(String, String)> {
        self.mailboxes
            .directory
            .lock()
            .map(|directory| {
                directory
                    .iter()
                    .map(|(pubkey, nickname)| (pubkey.clone(), nickname.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Bound to `Address = String` deliberately: over a mesh a peer *is* its
/// public-key hex, and pretending the address type is open would mean
/// inventing a conversion that only ever has one sensible implementation.
impl<T: Config<Address = String>> Transport<T> for MeshTransport<T> {
    fn send_to(&mut self, message: &Message<T::Input>, addr: &String) {
        let Some(payload) = encode(message) else {
            return;
        };
        // `try_send`, never `send().await`: this is called from the frame
        // loop, which must not block on the event loop draining. A full
        // queue means the loop is badly backed up, and dropping is the right
        // answer anyway — the protocol resends unacked inputs.
        let _ = self.outbox.try_send(Outbound::Rollback {
            to: addr.clone(),
            payload,
        });
    }

    fn receive_all(&mut self) -> Vec<(String, Message<T::Input>)> {
        let Ok(mut inbound) = self.mailboxes.inbound.lock() else {
            return Vec::new();
        };
        inbound.drain(..).collect()
    }
}
