//! The mailboxes the frame loop and the event loop share.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use habilis_network::protocol::{AuthorKey, Nickname};

use crate::config::Config;
use crate::transport::Message;

use std::fmt;
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
    /// Public key -> nickname, learned from inbound frames. The nickname is a label for display;
    /// the key is the identity, and a packet is addressed by key.
    pub(crate) directory: Mutex<HashMap<AuthorKey, Nickname>>,
}

impl<T: Config> fmt::Debug for Mailboxes<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
