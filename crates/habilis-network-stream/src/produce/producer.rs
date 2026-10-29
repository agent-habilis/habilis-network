//! One stream's writing end: the [`Producer`].

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;

use super::registry::{Link, Registry};
use crate::code;
use crate::error::StreamError;
use crate::hash::StreamHash;

/// How long `close` waits for the consumer to acknowledge the last bytes.
/// Closing the connection before that can cut the tail of the stream.
const DRAIN: Duration = Duration::from_secs(5);

/// One stream's writing end. It admits exactly one consumer.
///
/// Dropped without [`close`](Self::close), the stream is abandoned: a consumer
/// not yet attached is refused as unknown, and one already reading gets an
/// error instead of an end of stream.
#[derive(Debug)]
pub struct Producer {
    hash: StreamHash,
    // the producer shares the registry with the node
    registry: Arc<Registry>,
    attach: Option<oneshot::Receiver<Link>>,
    link: Option<Link>,
    closed: bool,
}

impl Producer {
    // the node and each producer share the registry
    pub(crate) fn new(hash: StreamHash, registry: Arc<Registry>) -> Self {
        let attach = registry.open(hash.id, hash.secret.clone());
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
    /// # Errors
    /// [`StreamError::Closed`] when the stream is closed, or
    /// [`StreamError::NodeClosed`] when the node closed before a consumer arrived.
    pub async fn attached(&mut self) -> Result<(), StreamError> {
        if self.link.is_some() {
            return Ok(());
        }
        let attach = self.attach.as_mut().ok_or(StreamError::Closed)?;
        let link = attach.await.map_err(|_| StreamError::NodeClosed)?;
        self.attach = None;
        self.link = Some(link);
        Ok(())
    }

    /// Write `bytes`, waiting first for the consumer to attach and then for
    /// room: QUIC flow control paces the producer to the consumer.
    ///
    /// # Errors
    /// # Errors
    /// [`StreamError::NodeClosed`] or [`StreamError::Closed`] as for
    /// [`attached`](Self::attached), or [`StreamError::ConsumerGone`] when the consumer went away.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        self.attached().await?;
        let link = self.link.as_mut().ok_or(StreamError::Closed)?;
        link.send
            .write_all(bytes)
            .await
            .map_err(|error| StreamError::ConsumerGone(error.into()))
    }

    /// End the stream: the consumer reads everything written, then the end of
    /// stream. Waits for a consumer if none has attached yet, so an empty
    /// stream still reaches one.
    ///
    /// # Errors
    /// # Errors
    /// [`StreamError::NodeClosed`] or [`StreamError::Closed`] as for
    /// [`attached`](Self::attached), or [`StreamError::ConsumerGone`] when the consumer went away.
    pub async fn close(mut self) -> Result<(), StreamError> {
        self.attached().await?;
        let link = self.link.as_mut().ok_or(StreamError::Closed)?;
        link.send
            .finish()
            .map_err(|error| StreamError::ConsumerGone(error.into()))?;
        let _ = n0_future::time::timeout(DRAIN, link.send.stopped()).await;
        link.connection.close(code::DONE.into(), b"done");
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
    /// # Errors
    /// As [`close`](Self::close), once a consumer has claimed the stream.
    pub async fn close_or_abandon(self) -> Result<(), StreamError> {
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
            link.connection.close(code::ABANDONED.into(), b"abandoned");
        }
    }
}
