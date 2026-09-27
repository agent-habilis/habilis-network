//! Byte streams for the browser: [`fofoca_stream`] behind three wasm-bindgen
//! classes. A tab can produce a stream as well as read one.

use std::cell::RefCell;
use std::rc::Rc;

use fofoca_stream::{StreamHash, StreamOpts};
use n0_future::future::or;
use tokio::sync::{Mutex, watch};
use wasm_bindgen::prelude::*;

use crate::to_js_error;

/// The node, shared with every producer and reader it hands out. JS frees a
/// handle it no longer refers to, and a page keeps its producer but not the
/// node that made it: without these clones the node, and its endpoint, went
/// away at the next garbage collection. `None` after [`StreamNode::close`];
/// the inner `Rc` keeps the node alive across an `open` in flight.
type Slot = Rc<RefCell<Option<Rc<fofoca_stream::StreamNode>>>>;

/// One endpoint that creates and opens streams. It never joins a mesh.
#[expect(
    missing_debug_implementations,
    reason = "the node's endpoint has nothing a caller would want printed"
)]
#[wasm_bindgen]
pub struct StreamNode {
    node: Slot,
}

#[wasm_bindgen]
impl StreamNode {
    /// Stand up a node with `opts_json`, a JSON encoding of
    /// `fofoca_stream::StreamOpts` (`lookup`, `transport`, `relayUrls`,
    /// `paths`). A browser node needs a lookup (`relay`).
    ///
    /// # Errors
    /// The options fail to parse or are invalid, or the endpoint fails to bind.
    pub async fn bind(opts_json: String) -> Result<StreamNode, JsValue> {
        console_error_panic_hook::set_once();
        let opts: StreamOpts = serde_json::from_str(&opts_json)
            .map_err(|error| to_js_error(&format!("invalid options: {error}")))?;
        let node = fofoca_stream::StreamNode::bind(&opts)
            .await
            .map_err(|error| to_js_error(&format!("{error:#}")))?;
        Ok(Self::holding(node))
    }

    /// Stand up a node that can reach the producer of `hash`.
    ///
    /// # Errors
    /// `hash` does not decode, or the endpoint fails to bind.
    #[wasm_bindgen(js_name = forHash)]
    pub async fn for_hash(hash: String) -> Result<StreamNode, JsValue> {
        console_error_panic_hook::set_once();
        let hash: StreamHash = hash.parse().map_err(|error| to_js_error(&error))?;
        let node = fofoca_stream::StreamNode::bind_for(&hash)
            .await
            .map_err(|error| to_js_error(&format!("{error:#}")))?;
        Ok(Self::holding(node))
    }

    fn holding(node: fofoca_stream::StreamNode) -> Self {
        Self {
            node: Rc::new(RefCell::new(Some(Rc::new(node)))),
        }
    }

    fn node(&self) -> Result<Rc<fofoca_stream::StreamNode>, JsValue> {
        self.node
            .borrow()
            .clone()
            .ok_or_else(|| to_js_error("this stream node is closed"))
    }

    /// Open a new stream for one consumer.
    ///
    /// # Errors
    /// The node is closed.
    pub async fn create(&self) -> Result<Producer, JsValue> {
        let node = self.node()?;
        let producer = node.create().await;
        self.closed_meanwhile(node).await?;
        Ok(Producer {
            hash: producer.hash().encode(),
            end: Mutex::new(Some(producer)),
            ending: watch::channel(Ending::Open).0,
            _node: Rc::clone(&self.node),
        })
    }

    /// Take the consumer slot of the stream behind `hash`.
    ///
    /// # Errors
    /// `hash` does not decode, the producer cannot be reached, or it refuses.
    pub async fn open(&self, hash: String) -> Result<Reader, JsValue> {
        let hash: StreamHash = hash.parse().map_err(|error| to_js_error(&error))?;
        let node = self.node()?;
        let reader = node.open(&hash).await;
        self.closed_meanwhile(node).await?;
        let reader = reader.map_err(|error| js(&error))?;
        Ok(Reader {
            end: Mutex::new(Some(reader)),
            closing: watch::channel(false).0,
            _node: Rc::clone(&self.node),
        })
    }

    /// Shut the node down; streams still open on it are abandoned.
    pub async fn close(&self) {
        let node = self.node.borrow_mut().take();
        // A `create` or `open` in flight still holds the node; it finishes
        // the shutdown when it lets go (`closed_meanwhile`).
        if let Some(node) = node.and_then(|node| Rc::try_unwrap(node).ok()) {
            node.close().await;
        }
    }

    /// After a call that held `node` across an await: if a `close` came in
    /// the meantime, shut the node down, as that close could not, and fail
    /// the call.
    async fn closed_meanwhile(&self, node: Rc<fofoca_stream::StreamNode>) -> Result<(), JsValue> {
        if self.node.borrow().is_some() {
            return Ok(());
        }
        if let Ok(node) = Rc::try_unwrap(node) {
            node.close().await;
        }
        Err(to_js_error("this stream node is closed"))
    }
}

/// How far a producer has been told to wind down. Ordered: an abandon also
/// ends everything a close ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Ending {
    Open,
    Closing,
    Abandoned,
}

/// Resolves once `ending` reaches `at`. Every wait below races this, because
/// each one holds the handle's lock: a close must not queue behind an
/// `attached()` that waits for a reader who may never come.
async fn reached(ending: &watch::Sender<Ending>, at: Ending) {
    let _ = ending.subscribe().wait_for(|now| *now >= at).await;
}

fn js(error: &anyhow::Error) -> JsValue {
    to_js_error(&format!("{error:#}"))
}

/// One stream's writing end.
#[expect(
    missing_debug_implementations,
    reason = "a producer's link has nothing a caller would want printed"
)]
#[wasm_bindgen]
pub struct Producer {
    hash: String,
    end: Mutex<Option<fofoca_stream::Producer>>,
    ending: watch::Sender<Ending>,
    _node: Slot,
}

#[wasm_bindgen]
impl Producer {
    /// The hash the one consumer opens this stream with.
    #[must_use]
    pub fn hash(&self) -> String {
        self.hash.clone()
    }

    /// Resolves once the consumer is attached.
    ///
    /// # Errors
    /// The stream is closed, or its node closed first.
    pub async fn attached(&self) -> Result<(), JsValue> {
        let mut guard = self.end.lock().await;
        let producer = guard.as_mut().ok_or_else(closed)?;
        or(
            async { producer.attached().await.map_err(|error| js(&error)) },
            async {
                reached(&self.ending, Ending::Closing).await;
                Err(closed())
            },
        )
        .await
    }

    /// Write `bytes`, once the consumer is attached, paced by it.
    ///
    /// # Errors
    /// The stream is closed, or the consumer went away.
    pub async fn write(&self, bytes: Vec<u8>) -> Result<(), JsValue> {
        let mut guard = self.end.lock().await;
        let producer = guard.as_mut().ok_or_else(closed)?;
        // Waiting for the reader ends at a close; writing to one ends only at
        // an abandon, so a close never cuts bytes already on their way.
        or(
            async { producer.attached().await.map_err(|error| js(&error)) },
            async {
                reached(&self.ending, Ending::Closing).await;
                Err(closed())
            },
        )
        .await?;
        or(
            async { producer.write(&bytes).await.map_err(|error| js(&error)) },
            async {
                reached(&self.ending, Ending::Abandoned).await;
                Err(closed())
            },
        )
        .await
    }

    /// End the stream. With a reader attached, it reads everything written,
    /// then the end. With none, the stream is abandoned at once, and a reader
    /// that comes later is refused.
    ///
    /// # Errors
    /// The reader went away before the end reached it.
    pub async fn close(&self) -> Result<(), JsValue> {
        self.ending.send_if_modified(|now| {
            let open = *now == Ending::Open;
            if open {
                *now = Ending::Closing;
            }
            open
        });
        let producer = self.end.lock().await.take();
        let Some(producer) = producer else {
            return Ok(());
        };
        // An abandon that comes while the end drains still abandons: dropping
        // the close drops the producer, which closes the link `ABANDONED`.
        or(
            async {
                producer
                    .close_or_abandon()
                    .await
                    .map_err(|error| js(&error))
            },
            async {
                reached(&self.ending, Ending::Abandoned).await;
                Err(to_js_error("this stream was abandoned"))
            },
        )
        .await
    }

    /// Give the stream up without ending it: a reader gets an error, not the
    /// end of stream.
    pub async fn abandon(&self) {
        self.ending.send_replace(Ending::Abandoned);
        drop(self.end.lock().await.take());
    }
}

fn closed() -> JsValue {
    to_js_error("this stream is closed")
}

/// One stream's reading end.
#[expect(
    missing_debug_implementations,
    reason = "a reader's link has nothing a caller would want printed"
)]
#[wasm_bindgen]
pub struct Reader {
    end: Mutex<Option<fofoca_stream::Reader>>,
    closing: watch::Sender<bool>,
    _node: Slot,
}

#[wasm_bindgen]
impl Reader {
    /// The next bytes, in order; `undefined` at the end of the stream.
    ///
    /// # Errors
    /// The producer refused or abandoned the stream, the link was lost, or
    /// this reader was closed: a reader that gave up did not see the end.
    pub async fn read(&self) -> Result<Option<Vec<u8>>, JsValue> {
        let mut guard = self.end.lock().await;
        let Some(reader) = guard.as_mut() else {
            return Err(reader_closed());
        };
        or(
            async {
                reader
                    .read()
                    .await
                    .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
                    .map_err(|error| js(&error))
            },
            async {
                let _ = self.closing.subscribe().wait_for(|closing| *closing).await;
                Err(reader_closed())
            },
        )
        .await
    }

    /// Give the stream up. A read in flight fails as closed.
    pub async fn close(&self) {
        self.closing.send_replace(true);
        drop(self.end.lock().await.take());
    }
}

fn reader_closed() -> JsValue {
    to_js_error("this reader is closed")
}
