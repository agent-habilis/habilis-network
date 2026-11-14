//! The accept side of the chunk plane: the `ProtocolHandler` the Router runs for `CHUNKS_ALPN`. It reads one
//! request from each bidirectional stream, hands it to the event loop, and writes back the answer that the loop
//! gives. It decides nothing about the request: the loop checks the member, the budget and the root.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::{mpsc, oneshot};

use crate::chunk_fetch::ABSENT;
use crate::util::tuning::{CHUNK_STREAM_TIMEOUT, CHUNK_STREAMS_PER_PEER, DIRECT_IDLE_BACKSTOP};

use super::webrtc::close_code::{IDLE, UNICAST_RELAY_REFUSED};
use super::{LOG_TARGET, PayloadPath, payload_path};

use n0_future::{task, time as n0future_time};

/// ALPN for the chunk plane: one request and one answer on a bidirectional stream. Wire-load-bearing like
/// `UNICAST_ALPN`: both ends must agree, so it moves only with a deliberate protocol break.
pub(crate) const CHUNKS_ALPN: &[u8] = b"habilis-mesh/chunks/1";

/// The most bytes that a request of the chunk plane takes. A request is 37 bytes at most, so a longer one is
/// not read to its end.
const MAX_REQUEST_BYTES: usize = 64;

/// One request that a peer sent, the endpoint of its connection, and the place for the answer. The connection is
/// authenticated, so `from` is the peer that opened the stream.
#[derive(Debug)]
pub(crate) struct ChunkAsk {
    pub(crate) from: EndpointId,
    pub(crate) request: Vec<u8>,
    pub(crate) reply: oneshot::Sender<Vec<u8>>,
}

/// The streams that each endpoint has open.
#[derive(Debug, Clone, Default)]
struct OpenStreams {
    // shared by the accept tasks of all connections that the Router runs, so the cap is one for each endpoint
    open: Arc<Mutex<HashMap<EndpointId, usize>>>,
}

/// The place of one open stream. The place is given back when the stream ends.
#[derive(Debug)]
struct StreamSlot {
    open: OpenStreams,
    peer: EndpointId,
}

impl OpenStreams {
    /// A place for a new stream of `peer`, or `None` when `peer` has `CHUNK_STREAMS_PER_PEER` open.
    fn take(&self, peer: EndpointId) -> Option<StreamSlot> {
        let mut open = self.open.lock().ok()?;
        let count = open.entry(peer).or_insert(0);
        if *count >= CHUNK_STREAMS_PER_PEER {
            return None;
        }
        *count += 1;
        Some(StreamSlot {
            open: self.clone(),
            peer,
        })
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let Ok(mut open) = self.open.open.lock() else {
            return;
        };
        if let Some(count) = open.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.peer);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ChunkAcceptor {
    tx: mpsc::Sender<ChunkAsk>,
    relay_transport: PayloadPath,
    streams: OpenStreams,
    /// How long one stream can take, from the request to the end of the answer.
    deadline: Duration,
    /// How long an accepted connection can carry no new stream before it is closed.
    idle: Duration,
}

impl ChunkAcceptor {
    pub(crate) fn new(tx: mpsc::Sender<ChunkAsk>, relay_transport: PayloadPath) -> Self {
        Self {
            tx,
            relay_transport,
            streams: OpenStreams::default(),
            deadline: CHUNK_STREAM_TIMEOUT,
            idle: DIRECT_IDLE_BACKSTOP,
        }
    }

    /// The answer to the request on `recv`. The request is read up to its cap, handed to the loop, and the loop
    /// gives the answer. Every failure on the way is the absent answer.
    async fn answer(&self, peer: EndpointId, recv: &mut RecvStream) -> Vec<u8> {
        let Ok(request) = recv.read_to_end(MAX_REQUEST_BYTES).await else {
            return ABSENT.to_vec();
        };
        let (reply, answered) = oneshot::channel();
        let ask = ChunkAsk {
            from: peer,
            request,
            reply,
        };
        if self.tx.try_send(ask).is_err() {
            tracing::debug!(target: LOG_TARGET, "chunk inbox full or closed; request answered absent");
            return ABSENT.to_vec();
        }
        answered.await.unwrap_or_else(|_| ABSENT.to_vec())
    }

    /// Serves one stream: the answer, written inside the deadline of the stream.
    async fn serve(&self, peer: EndpointId, mut send: SendStream, mut recv: RecvStream) {
        // The place stays taken until the answer is written.
        let slot = self.streams.take(peer);
        let answer: Vec<u8> = if slot.is_some() {
            n0future_time::timeout(self.deadline, self.answer(peer, &mut recv))
                .await
                .unwrap_or_else(|_| ABSENT.to_vec())
        } else {
            ABSENT.to_vec()
        };
        let written = n0future_time::timeout(self.deadline, async {
            send.write_all(&answer).await.ok()?;
            send.finish().ok()
        })
        .await;
        if written.ok().flatten().is_none() {
            tracing::debug!(target: LOG_TARGET, "chunk answer not written");
        }
        drop(slot);
    }
}

impl ProtocolHandler for ChunkAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The sender checks its own selected path, but an old build or a hostile peer may not.
        if !payload_path::refuse_unless_direct(
            &connection,
            self.relay_transport,
            payload_path::PROBE_DEADLINE,
            UNICAST_RELAY_REFUSED,
        )
        .await
        {
            return Ok(());
        }
        let peer = connection.remote_id();
        loop {
            match n0future_time::timeout(self.idle, connection.accept_bi()).await {
                Ok(Ok((send, recv))) => {
                    // Each stream has its own task, so a stream that waits for the loop holds back no other
                    // stream of the connection. The cap of open streams bounds the tasks of an endpoint.
                    let acceptor = self.clone();
                    task::spawn(async move { acceptor.serve(peer, send, recv).await });
                }
                Ok(Err(_closed)) => break,
                Err(_idle) => {
                    tracing::debug!(target: LOG_TARGET, "closing an idle accepted chunk connection");
                    connection.close(IDLE.into(), b"idle");
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::{Duration, Instant};

    use iroh::endpoint::{Connection, presets};
    use iroh::protocol::Router;
    use tokio::sync::mpsc;
    use tokio::{task, time};

    use super::{
        ABSENT, CHUNKS_ALPN, ChunkAcceptor, ChunkAsk, OpenStreams, PayloadPath, StreamSlot,
    };
    use crate::util::tuning::CHUNK_STREAMS_PER_PEER;
    use crate::{lookup, testing};

    /// A client connected to a server, and what the test closes at its end: an endpoint that is dropped without a
    /// close logs an error, and the log of the error fails the tests that run in the same moment.
    struct Pair {
        connection: Connection,
        router: Router,
        client: iroh::Endpoint,
    }

    impl Pair {
        async fn close(self) {
            self.connection.close(0u32.into(), b"done");
            self.client.close().await;
            self.router.shutdown().await.expect("the router shuts down");
        }
    }

    /// A server that runs `acceptor` for the chunk ALPN, and a client connected to it.
    async fn connected(acceptor: ChunkAcceptor) -> Pair {
        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(CHUNKS_ALPN, acceptor)
            .spawn();
        let client = bind().await;
        lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
        let connection = client
            .connect(server.id(), CHUNKS_ALPN)
            .await
            .expect("connect");
        Pair {
            connection,
            router,
            client,
        }
    }

    /// One request on a new stream, and the answer to it, or `None` when the stream ends with no answer within 8 s.
    async fn ask(connection: &Connection, request: &[u8]) -> Option<Vec<u8>> {
        let exchange = async {
            let (mut send, mut recv) = connection.open_bi().await.ok()?;
            send.write_all(request).await.ok()?;
            send.finish().ok()?;
            recv.read_to_end(1 << 20).await.ok()
        };
        time::timeout(Duration::from_secs(8), exchange)
            .await
            .ok()
            .flatten()
    }

    /// The next request that reaches the loop. A test does not wait longer than 5 s for one.
    async fn next_ask(asks: &mut mpsc::Receiver<ChunkAsk>) -> ChunkAsk {
        time::timeout(Duration::from_secs(5), asks.recv())
            .await
            .expect("a request within 5 s")
            .expect("the inbox is open")
    }

    fn acceptor(capacity: usize, deadline: Duration) -> (ChunkAcceptor, mpsc::Receiver<ChunkAsk>) {
        let (tx, rx) = mpsc::channel(capacity);
        let mut acceptor = ChunkAcceptor::new(tx, PayloadPath::RelayAllowed);
        acceptor.deadline = deadline;
        (acceptor, rx)
    }

    #[tokio::test]
    async fn a_request_reaches_the_loop_with_the_endpoint_of_its_connection_and_the_answer_goes_back()
     {
        let (acceptor, mut asks) = acceptor(8, Duration::from_secs(5));
        let pair = connected(acceptor).await;
        let connection = pair.connection.clone();
        let answerer = task::spawn(async move {
            let ask = next_ask(&mut asks).await;
            let seen = (ask.from, ask.request.clone());
            ask.reply
                .send(b"the answer".to_vec())
                .expect("the stream waits for the answer");
            seen
        });
        let answer = ask(&connection, b"the request").await;
        assert_eq!(
            answer.as_deref(),
            Some(b"the answer".as_slice()),
            "the answer of the loop must reach the asker"
        );
        let (from, request) = time::timeout(Duration::from_secs(5), answerer)
            .await
            .expect("the answerer ends within 5 s")
            .expect("the answerer does not panic");
        assert_eq!(
            from,
            pair.client.id(),
            "the request must carry the endpoint of its connection"
        );
        assert_eq!(
            request, b"the request",
            "the loop must get the request as it was sent"
        );
        pair.close().await;
    }

    #[tokio::test]
    async fn a_loop_that_does_not_answer_gives_the_absent_answer_after_the_deadline() {
        let (acceptor, mut asks) = acceptor(8, Duration::from_millis(300));
        let pair = connected(acceptor).await;
        let connection = pair.connection.clone();
        // The loop takes the request and holds it, as a stalled loop does.
        let holder = task::spawn(async move {
            let held = next_ask(&mut asks).await;
            time::sleep(Duration::from_secs(5)).await;
            drop(held);
        });
        let answer = ask(&connection, b"the request").await;
        assert_eq!(
            answer.as_deref(),
            Some(ABSENT.as_slice()),
            "a stalled loop must not hold the stream: the asker gets the absent answer"
        );
        holder.abort();
        pair.close().await;
    }

    #[tokio::test]
    async fn a_request_longer_than_any_request_is_answered_absent_and_never_reaches_the_loop() {
        let (acceptor, mut asks) = acceptor(8, Duration::from_secs(5));
        let pair = connected(acceptor).await;
        let connection = pair.connection.clone();
        let answer = ask(&connection, &[7u8; 4096]).await;
        assert_eq!(
            answer.as_deref(),
            Some(ABSENT.as_slice()),
            "a request past the cap must get the absent answer"
        );
        assert!(
            asks.try_recv().is_err(),
            "a request past the cap must not reach the loop"
        );
        pair.close().await;
    }

    #[tokio::test]
    async fn a_request_that_finds_the_inbox_full_is_answered_absent_at_once() {
        let (acceptor, asks) = acceptor(1, Duration::from_secs(5));
        let pair = connected(acceptor).await;
        let connection = pair.connection.clone();
        // The first request fills the inbox, and the loop does not take it.
        let first = task::spawn({
            let connection = connection.clone();
            async move { ask(&connection, b"first").await }
        });
        let waited = Instant::now();
        while asks.is_empty() {
            assert!(
                waited.elapsed() < Duration::from_secs(5),
                "the first request must reach the inbox"
            );
            time::sleep(Duration::from_millis(10)).await;
        }
        let started = Instant::now();
        let second = ask(&connection, b"second").await;
        assert_eq!(
            second.as_deref(),
            Some(ABSENT.as_slice()),
            "a request that finds the inbox full must get the absent answer"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a full inbox must be answered at once and not at the deadline, it took {:?}",
            started.elapsed()
        );
        first.abort();
        drop(asks);
        pair.close().await;
    }

    #[tokio::test]
    async fn the_stream_past_the_cap_of_one_endpoint_is_answered_absent_at_once() {
        let (acceptor, asks) = acceptor(16, Duration::from_secs(5));
        let pair = connected(acceptor).await;
        let connection = pair.connection.clone();
        // The loop takes no request, so each stream that the cap lets in stays open.
        let open: Vec<task::JoinHandle<Option<Vec<u8>>>> = (0..CHUNK_STREAMS_PER_PEER)
            .map(|number| {
                let connection = connection.clone();
                task::spawn(async move {
                    ask(
                        &connection,
                        &[u8::try_from(number).expect("a small number")],
                    )
                    .await
                })
            })
            .collect();
        let waited = Instant::now();
        while asks.len() < CHUNK_STREAMS_PER_PEER {
            assert!(
                waited.elapsed() < Duration::from_secs(5),
                "the streams under the cap must reach the loop"
            );
            time::sleep(Duration::from_millis(10)).await;
        }
        let started = Instant::now();
        let past_cap = ask(&connection, b"past the cap").await;
        assert_eq!(
            past_cap.as_deref(),
            Some(ABSENT.as_slice()),
            "a stream past the cap of its endpoint must get the absent answer"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the stream past the cap must be answered at once, it took {:?}",
            started.elapsed()
        );
        assert_eq!(
            asks.len(),
            CHUNK_STREAMS_PER_PEER,
            "the stream past the cap must not reach the loop"
        );
        for stream in open {
            stream.abort();
        }
        pair.close().await;
    }

    #[test]
    fn an_endpoint_has_a_cap_of_open_streams_and_each_place_comes_back() {
        let streams = OpenStreams::default();
        let peer = testing::endpoint_id(1);
        let slots: Vec<StreamSlot> = (0..CHUNK_STREAMS_PER_PEER)
            .map(|_| streams.take(peer).expect("a place under the cap"))
            .collect();
        assert!(
            streams.take(peer).is_none(),
            "an endpoint past the cap of open streams must get no place"
        );
        assert!(
            streams.take(testing::endpoint_id(2)).is_some(),
            "another endpoint must have its own places"
        );
        drop(slots);
        assert!(
            streams.take(peer).is_some(),
            "the places that the ended streams gave back must be free again"
        );
    }
}
