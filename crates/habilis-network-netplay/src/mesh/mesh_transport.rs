//! The [`Transport`] the session drives, backed by the driver's mailboxes.

use std::sync::Arc;

use habilis_network::protocol::{AuthorKey, Nickname};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::mesh::mailboxes::Mailboxes;
use crate::mesh::outbound::Outbound;
use crate::mesh::rollback_driver;
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

impl<T: Config> MeshTransport<T> {
    pub(super) fn new(mailboxes: Arc<Mailboxes<T>>, outbox: mpsc::Sender<Outbound>) -> Self {
        Self { mailboxes, outbox }
    }

    /// Queue a lobby packet for every peer in the mesh roster.
    pub fn broadcast_lobby<S: serde::Serialize>(&self, value: &S) {
        if let Some(payload) = rollback_driver::encode(value) {
            let _ = self.outbox.try_send(Outbound::Lobby { payload });
        }
    }

    /// Take every lobby packet received since the last call, as
    /// `(sender public key, raw JSON)`.
    pub fn drain_lobby(&self) -> impl Iterator<Item = (AuthorKey, String)> {
        self.mailboxes
            .lobby
            .lock()
            .map(|mut lobby| std::mem::take(&mut *lobby))
            .unwrap_or_default()
            .into_iter()
    }

    /// This peer's own public key, once the node's event loop has started.
    ///
    /// `None` until then: the identity comes from `HandlerCtx`, which does
    /// not exist before `Node::spawn`. Poll it before building a
    /// [`super::Lobby`].
    #[must_use]
    pub fn local_pubkey(&self) -> Option<AuthorKey> {
        self.mailboxes
            .local_pubkey
            .lock()
            .ok()
            .and_then(|slot| *slot)
    }

    /// Whether a peer's public key can be addressed yet — true once we have
    /// received any frame from them.
    #[must_use]
    pub fn knows(&self, pubkey: &AuthorKey) -> bool {
        self.mailboxes
            .directory
            .lock()
            .is_ok_and(|directory| directory.contains_key(pubkey))
    }

    /// Every peer we can address, as `(public key, nickname)`.
    pub fn known_peers(&self) -> impl Iterator<Item = (AuthorKey, Nickname)> {
        let peers: Vec<(AuthorKey, Nickname)> = self
            .mailboxes
            .directory
            .lock()
            .map(|directory| {
                directory
                    .iter()
                    .map(|(pubkey, nickname)| (*pubkey, nickname.clone()))
                    .collect()
            })
            .unwrap_or_default();
        peers.into_iter()
    }
}

/// Bound to `Address = AuthorKey` deliberately: over a mesh a peer *is* the
/// key that signs its frames, and pretending the address type is open would
/// mean inventing a conversion that only ever has one sensible implementation.
impl<T: Config<Address = AuthorKey>> Transport<T> for MeshTransport<T> {
    fn send_to(&mut self, message: &Message<T::Input>, addr: &AuthorKey) {
        let Some(payload) = rollback_driver::encode(message) else {
            return;
        };
        // `try_send`, never `send().await`: this is called from the frame
        // loop, which must not block on the event loop draining. A full
        // queue means the loop is badly backed up, and dropping is the right
        // answer anyway — the protocol resends unacked inputs.
        let _ = self
            .outbox
            .try_send(Outbound::Rollback { to: *addr, payload });
    }

    fn receive_all(&mut self) -> Vec<(AuthorKey, Message<T::Input>)> {
        let Ok(mut inbound) = self.mailboxes.inbound.lock() else {
            return Vec::new();
        };
        inbound.drain(..).collect()
    }
}
