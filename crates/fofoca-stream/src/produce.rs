//! The producer's side: the registry of open streams, the handler that admits
//! a consumer to one, and the [`Producer`] that writes to it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use fofoca::iroh::endpoint::{Connection, SendStream};
use fofoca::iroh::protocol::{AcceptError, ProtocolHandler};
use fofoca::net::direct::{PROBE_DEADLINE, refuse_unless_direct};
use fofoca::protocol::ct_eq;
use tokio::sync::oneshot;

use crate::code;
use crate::hash::{ID_LEN, SECRET_LEN, StreamHash};

/// How long a connection may take to present `id ‖ secret`. Nothing the peer
/// has proved yet, so it gets no more than a slow link needs.
const PRE_AUTH: Duration = Duration::from_secs(10);

/// How long `close` waits for the consumer to acknowledge the last bytes.
/// Closing the connection before that can cut the tail of the stream.
const DRAIN: Duration = Duration::from_secs(5);

/// A consumer, admitted: the connection and the half the producer writes.
struct Link {
    conn: Connection,
    send: SendStream,
}

/// One open stream. `waiting` is taken by the first consumer that presents the
/// secret; afterwards the stream is spent.
struct Entry {
    secret: [u8; SECRET_LEN],
    waiting: Option<oneshot::Sender<Link>>,
}

/// Every stream a node has open, by public id.
#[derive(Default)]
pub(crate) struct Registry(Mutex<HashMap<[u8; ID_LEN], Entry>>);

impl Registry {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; ID_LEN], Entry>> {
        // A panic while holding the lock leaves a map that is still whole.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn open(&self, id: [u8; ID_LEN], secret: [u8; SECRET_LEN]) -> oneshot::Receiver<Link> {
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

    fn forget(&self, id: &[u8; ID_LEN]) {
        self.entries().remove(id);
    }

    /// Forget `id` unless a consumer has claimed it; `true` when forgotten.
    /// Under the lock [`claim`](Self::claim) takes, so a consumer that has
    /// presented the secret cannot be dropped between its claim and its link.
    fn forget_unless_claimed(&self, id: &[u8; ID_LEN]) -> bool {
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
    fn claim(
        &self,
        id: &[u8; ID_LEN],
        secret: &[u8; SECRET_LEN],
    ) -> Result<oneshot::Sender<Link>, u32> {
        let mut entries = self.entries();
        match entries.get_mut(id) {
            Some(entry) if ct_eq(secret, &entry.secret) => entry.waiting.take().ok_or(code::TAKEN),
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

/// The `ProtocolHandler` for [`crate::STREAM_ALPN`]: admit one consumer to one
/// stream and hand its connection to the waiting [`Producer`].
#[derive(Debug, Clone)]
pub(crate) struct StreamAcceptor {
    pub(crate) registry: Arc<Registry>,
    pub(crate) relay_transport: bool,
}

impl ProtocolHandler for StreamAcceptor {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // Before reading a byte, and before the slot is taken: a consumer
        // refused here must not spend the hash.
        if !refuse_unless_direct(
            &conn,
            self.relay_transport,
            PROBE_DEADLINE,
            code::RELAY_REFUSED,
        )
        .await
        {
            return Ok(());
        }
        let Ok(Ok((send, header))) = n0_future::time::timeout(PRE_AUTH, read_header(&conn)).await
        else {
            conn.close(code::UNKNOWN.into(), b"no stream request");
            return Ok(());
        };
        let (id, secret) = header;
        match self.registry.claim(&id, &secret) {
            Ok(waiting) => {
                if waiting
                    .send(Link {
                        conn: conn.clone(),
                        send,
                    })
                    .is_err()
                {
                    // The producer went away between the claim and now: the
                    // stream existed and this consumer was admitted, so
                    // abandoned, not unknown. The same answer `Producer::drop`
                    // gives when the link landed before it (its `try_recv`).
                    conn.close(code::ABANDONED.into(), b"abandoned");
                    return Ok(());
                }
                // The producer owns the connection now; this task only keeps
                // the handler alive for its lifetime.
                conn.closed().await;
            }
            Err(refusal) => conn.close(refusal.into(), b"refused"),
        }
        Ok(())
    }
}

async fn read_header(conn: &Connection) -> Result<(SendStream, ([u8; ID_LEN], [u8; SECRET_LEN]))> {
    let (send, mut recv) = conn.accept_bi().await?;
    let mut id = [0; ID_LEN];
    let mut secret = [0; SECRET_LEN];
    recv.read_exact(&mut id).await?;
    recv.read_exact(&mut secret).await?;
    Ok((send, (id, secret)))
}

/// One stream's writing end. It admits exactly one consumer.
///
/// Dropped without [`close`](Self::close), the stream is abandoned: a consumer
/// not yet attached is refused as unknown, and one already reading gets an
/// error instead of an end of stream.
#[derive(Debug)]
pub struct Producer {
    hash: StreamHash,
    registry: Arc<Registry>,
    attach: Option<oneshot::Receiver<Link>>,
    link: Option<Link>,
    closed: bool,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Link")
            .field("remote", &self.conn.remote_id())
            .finish_non_exhaustive()
    }
}

impl Producer {
    pub(crate) fn new(hash: StreamHash, registry: Arc<Registry>) -> Self {
        let attach = registry.open(hash.id, hash.secret);
        Self {
            hash,
            registry,
            attach: Some(attach),
            link: None,
            closed: false,
        }
    }

    /// The hash a consumer opens this stream with.
    #[must_use]
    pub fn hash(&self) -> &StreamHash {
        &self.hash
    }

    /// Wait until the consumer is admitted.
    ///
    /// # Errors
    /// The node closed before any consumer arrived.
    pub async fn attached(&mut self) -> Result<()> {
        if self.link.is_some() {
            return Ok(());
        }
        let attach = self.attach.as_mut().context("the stream is closed")?;
        let link = attach
            .await
            .map_err(|_| anyhow::anyhow!("the stream node closed before a consumer arrived"))?;
        self.attach = None;
        self.link = Some(link);
        Ok(())
    }

    /// Write `bytes`, waiting first for the consumer to attach and then for
    /// room: QUIC flow control paces the producer to the consumer.
    ///
    /// # Errors
    /// The node closed, or the consumer went away.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.attached().await?;
        let link = self.link.as_mut().context("the stream is closed")?;
        link.send
            .write_all(bytes)
            .await
            .map_err(|error| anyhow::anyhow!("the consumer went away: {error}"))
    }

    /// End the stream: the consumer reads everything written, then the end of
    /// stream. Waits for a consumer if none has attached yet, so an empty
    /// stream still reaches one.
    ///
    /// # Errors
    /// The node closed before any consumer arrived, or the consumer went away.
    pub async fn close(mut self) -> Result<()> {
        self.attached().await?;
        let link = self.link.as_mut().context("the stream is closed")?;
        link.send
            .finish()
            .map_err(|error| anyhow::anyhow!("the consumer went away: {error}"))?;
        let _ = n0_future::time::timeout(DRAIN, link.send.stopped()).await;
        link.conn.close(code::DONE.into(), b"done");
        self.closed = true;
        Ok(())
    }
}

impl Producer {
    /// End the stream if a consumer has claimed it, as [`close`](Self::close)
    /// does; otherwise abandon it at once instead of waiting for one. A
    /// consumer that arrives later is refused as unknown.
    ///
    /// # Errors
    /// As [`close`](Self::close), once a consumer has claimed the stream.
    pub async fn close_or_abandon(self) -> Result<()> {
        if self.link.is_none() && self.registry.forget_unless_claimed(&self.hash.id) {
            return Ok(());
        }
        self.close().await
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        self.registry.forget(&self.hash.id);
        if self.closed {
            return;
        }
        // A link can wait in the hand-off when nothing polled `attached()`.
        // Dropped there, its send half finishes, and the consumer would read
        // an empty, cleanly ended stream instead of an abandoned one.
        let waiting = self
            .attach
            .as_mut()
            .and_then(|attach| attach.try_recv().ok());
        if let Some(link) = self.link.as_ref().or(waiting.as_ref()) {
            link.conn.close(code::ABANDONED.into(), b"abandoned");
        }
    }
}
