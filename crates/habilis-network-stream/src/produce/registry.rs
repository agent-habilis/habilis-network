//! The registry of a node's open streams, by public id.

use std::collections::HashMap;
use std::sync::Mutex;

use habilis_network::iroh::endpoint::{Connection, SendStream};
use habilis_network::protocol::ct_eq;
use tokio::sync::oneshot;

use crate::code;
use crate::hash::{StreamId, StreamSecret};

/// A consumer, admitted: the connection and the half the producer writes.
pub(super) struct Link {
    pub(super) conn: Connection,
    pub(super) send: SendStream,
}

/// One open stream. `waiting` is taken by the first consumer that presents the
/// secret; afterwards the stream is spent.
pub(super) struct Entry {
    pub(super) secret: StreamSecret,
    pub(super) waiting: Option<oneshot::Sender<Link>>,
}

/// Every stream a node has open, by public id.
#[derive(Default)]
pub(crate) struct Registry(Mutex<HashMap<StreamId, Entry>>);

impl Registry {
    pub(super) fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<StreamId, Entry>> {
        self.0.lock().expect("the stream registry is poisoned")
    }

    pub(super) fn open(&self, id: StreamId, secret: StreamSecret) -> oneshot::Receiver<Link> {
        let (waiting, attached) = oneshot::channel();
        self.entries().insert(
            id,
            Entry {
                secret,
                waiting: Some(waiting),
            },
        );
        attached
    }

    pub(super) fn forget(&self, id: &StreamId) {
        self.entries().remove(id);
    }

    /// Forget `id` unless a consumer has claimed it; `true` when forgotten.
    /// Under the lock [`claim`](Self::claim) takes, so a consumer that has
    /// presented the secret cannot be dropped between its claim and its link.
    pub(super) fn forget_unless_claimed(&self, id: &StreamId) -> bool {
        let mut entries = self.entries();
        if entries.get(id).is_some_and(|entry| entry.waiting.is_none()) {
            return false;
        }
        entries.remove(id);
        true
    }

    /// Everything open is abandoned: every waiting producer's `attached` ends.
    pub(crate) fn clear(&self) {
        self.entries().clear();
    }

    /// The one consumer slot for `id`, if `secret` opens it. Taking the slot and
    /// checking it was free are one critical section, so two consumers racing
    /// the same hash cannot both be admitted.
    pub(super) fn claim(
        &self,
        id: &StreamId,
        secret: &StreamSecret,
    ) -> Result<oneshot::Sender<Link>, u32> {
        let mut entries = self.entries();
        match entries.get_mut(id) {
            Some(entry) if ct_eq(secret.as_bytes(), entry.secret.as_bytes()) => {
                entry.waiting.take().ok_or(code::TAKEN)
            }
            Some(_) | None => Err(code::UNKNOWN),
        }
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Registry")
            .field("open", &self.entries().len())
            .finish()
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Link")
            .field("remote", &self.conn.remote_id())
            .finish_non_exhaustive()
    }
}
