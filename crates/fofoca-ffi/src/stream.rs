//! Blocking stream handles for a foreign caller: a node, the producers it
//! creates, and the readers it opens. Every handle holds the node's tokio
//! runtime, so they can be closed in any order.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use fofoca_stream::{Producer, Reader, StreamHash, StreamNode, StreamOpts};

/// A stream node, driven synchronously from a foreign caller's thread.
#[expect(
    missing_debug_implementations,
    reason = "a tokio Runtime has no Debug impl"
)]
pub struct Streams {
    /// `None` after [`Streams::close`].
    node: Option<StreamNode>,
    /// Last in every handle here: fields drop in order, and what the handle
    /// holds must go while the runtime it needs still runs.
    runtime: Arc<tokio::runtime::Runtime>,
}

impl Streams {
    /// Stand up a node with `opts`.
    ///
    /// # Errors
    /// Invalid options, or an endpoint that fails to bind.
    pub fn bind(opts: &StreamOpts) -> Result<Self> {
        let runtime = runtime()?;
        let node = runtime.block_on(StreamNode::bind(opts))?;
        Ok(Self {
            runtime: Arc::new(runtime),
            node: Some(node),
        })
    }

    /// Stand up a node that can reach the producer of `hash`.
    ///
    /// # Errors
    /// `hash` does not decode, or the endpoint fails to bind.
    pub fn bind_for(hash: &str) -> Result<Self> {
        let hash: StreamHash = hash.parse()?;
        let runtime = runtime()?;
        let node = runtime.block_on(StreamNode::bind_for(&hash))?;
        Ok(Self {
            runtime: Arc::new(runtime),
            node: Some(node),
        })
    }

    /// Open a new stream for one consumer.
    ///
    /// # Errors
    /// The node is closed.
    pub fn create(&self) -> Result<Writer> {
        let producer = self.runtime.block_on(self.node()?.create());
        let hash = producer.hash().encode();
        Ok(Writer {
            runtime: Arc::clone(&self.runtime),
            producer: Some(producer),
            hash,
        })
    }

    /// Take the consumer slot of the stream behind `hash`.
    ///
    /// # Errors
    /// `hash` does not decode, the producer cannot be reached, or it refuses.
    pub fn open(&self, hash: &str) -> Result<ReadEnd> {
        let hash: StreamHash = hash.parse()?;
        let reader = self.runtime.block_on(self.node()?.open(&hash))?;
        Ok(ReadEnd {
            runtime: Arc::clone(&self.runtime),
            reader,
            leftover: Bytes::new(),
            ended: false,
        })
    }

    /// Shut the node down. Every stream still open is abandoned.
    pub fn close(&mut self) {
        if let Some(node) = self.node.take() {
            self.runtime.block_on(node.close());
        }
    }

    fn node(&self) -> Result<&StreamNode> {
        self.node.as_ref().context("this stream node is closed")
    }
}

/// A producer, driven synchronously.
#[expect(
    missing_debug_implementations,
    reason = "a tokio Runtime has no Debug impl"
)]
pub struct Writer {
    /// `None` after [`Writer::close`].
    producer: Option<Producer>,
    hash: String,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl Writer {
    /// The hash the one consumer opens this stream with.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Write all of `bytes`. `Ok(false)` when no consumer attached within
    /// `timeout`: nothing was written. Once one has, the write runs to the
    /// end, paced by the consumer.
    ///
    /// # Errors
    /// The stream is closed, or the consumer went away.
    pub fn write(&mut self, bytes: &[u8], timeout: Duration) -> Result<bool> {
        let producer = self.producer.as_mut().context("this stream is closed")?;
        self.runtime.block_on(async {
            match n0_future::time::timeout(timeout, producer.attached()).await {
                Err(_elapsed) => Ok(false),
                Ok(attached) => {
                    attached?;
                    producer.write(bytes).await?;
                    Ok(true)
                }
            }
        })
    }

    /// End the stream. With a consumer attached, it reads everything written
    /// and then the end of stream. With none, the stream is abandoned rather
    /// than waited on, and a later consumer is refused as unknown.
    ///
    /// # Errors
    /// The consumer went away before the end of stream reached it.
    pub fn close(&mut self) -> Result<()> {
        match self.producer.take() {
            Some(producer) => self.runtime.block_on(producer.close_or_abandon()),
            None => Ok(()),
        }
    }
}

/// What [`ReadEnd::read`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    /// This many bytes are in the caller's buffer.
    Bytes(usize),
    Timeout,
    /// The producer closed the stream; nothing more will come.
    End,
}

/// A reader, driven synchronously. Bytes that do not fit the caller's buffer
/// are kept for the next read, as `read(2)` does.
#[expect(
    missing_debug_implementations,
    reason = "a tokio Runtime has no Debug impl"
)]
pub struct ReadEnd {
    reader: Reader,
    leftover: Bytes,
    ended: bool,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl ReadEnd {
    /// Fill `buf` with the next bytes, waiting at most `timeout` for them.
    ///
    /// # Errors
    /// The producer refused or abandoned the stream, or the link was lost.
    pub fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<Read> {
        if self.leftover.is_empty() && !self.ended {
            let reader = &mut self.reader;
            // Inside `block_on`: the timer registers with the runtime's reactor
            // when it is created, and there is none out here.
            let next = self
                .runtime
                .block_on(async { n0_future::time::timeout(timeout, reader.read()).await });
            match next {
                Err(_elapsed) => return Ok(Read::Timeout),
                Ok(chunk) => match chunk? {
                    Some(chunk) => self.leftover = chunk,
                    None => self.ended = true,
                },
            }
        }
        if self.leftover.is_empty() {
            return Ok(Read::End);
        }
        let taken = self.leftover.len().min(buf.len());
        buf[..taken].copy_from_slice(&self.leftover.split_to(taken));
        Ok(Read::Bytes(taken))
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the stream runtime")
}
