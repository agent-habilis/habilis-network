//! The mailboxes the frame loop and the event loop share.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use habilis_network::protocol::{AuthorKey, Nickname};

use crate::config::Config;
use crate::transport::Message;

/// Everything the frame loop and the event loop share.
///
/// Cloning shares the mailboxes rather than copying them; the driver keeps
/// one handle and each transport another.
pub(crate) struct Mailboxes<T: Config> {
    /// Decoded rollback packets, tagged with the sender's public key.
    pub(crate) inbound: Mutex<VecDeque<(AuthorKey, Message<T::Input>)>>,
    /// Raw lobby packets, tagged with the sender's public key.
    pub(crate) lobby: Mutex<Vec<(AuthorKey, String)>>,
    /// This peer's own public key, known only once the event loop starts.
    pub(crate) local_pubkey: Mutex<Option<AuthorKey>>,
    /// public key -> nickname, learned from inbound frames.
    ///
    /// Needed because `send_app` addresses by `Nickname` while inputs are
    /// filed by public key — the protocol treats nicknames as cosmetic and
    /// explicitly non-unique, so they cannot be the identity.
    pub(crate) directory: Mutex<HashMap<AuthorKey, Nickname>>,
}

impl<T: Config> std::fmt::Debug for Mailboxes<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Mailboxes").finish_non_exhaustive()
    }
}

impl<T: Config> Mailboxes<T> {
    pub(crate) fn new() -> Self {
        Self {
            inbound: Mutex::new(VecDeque::new()),
            lobby: Mutex::new(Vec::new()),
            local_pubkey: Mutex::new(None),
            directory: Mutex::new(HashMap::new()),
        }
    }
}
