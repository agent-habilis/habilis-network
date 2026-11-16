//! A node's datagram link over the data lane: batches out to the relay it shares with the
//! destination, datagrams in from the relays it listens on.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use n0_future::task;
use tokio::sync::mpsc;
use url::Url;

use crate::batch;
use crate::event::Event;
use crate::lane::Lane;
use crate::pool::Pool;

/// The datagrams the receiver holds for a consumer that drains slowly. Past this a new one is
/// dropped and counted: QUIC recovers the loss, and memory does not grow.
pub const RECEIVE_CAPACITY: usize = 1024;

/// How many of the best-ranked healthy relays a node listens on. It sends on the first only, so
/// two nodes that disagree on which relay is healthy still meet.
const LISTEN_WIDTH: usize = 2;

/// A datagram that came in, and the endpoint that sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Datagram {
    /// The endpoint id the sender wrote in the header. Nothing here proves it: QUIC refuses a
    /// packet that is not from that endpoint.
    pub from: [u8; 32],
    /// The datagram.
    pub bytes: Vec<u8>,
}

/// A node's link over the data lane.
///
/// # Examples
///
/// A pool listens on its own tag and sends to the tag of a peer. The doc test compiles it but
/// does not run it.
///
/// ```no_run
/// use habilis_network_iroh_nostr_address_lookup::DataPool;
///
/// # async fn demo() {
/// let relays = vec!["wss://relay.example".parse().expect("a relay URL")];
/// let (me, my_tag, peer_tag) = ([1u8; 32], [2u8; 32], [3u8; 32]);
/// let (pool, mut datagrams) = DataPool::open(relays, me, my_tag);
/// pool.send(&peer_tag, b"hello".to_vec());
/// if let Some(datagram) = datagrams.recv().await {
///     println!("{} bytes from {:?}", datagram.bytes.len(), datagram.from);
/// }
/// # }
/// ```
#[derive(Debug)]
pub struct DataPool {
    pool: Pool,
    me: [u8; 32],
    // Read by the pool and written by its receive task.
    dropped: Arc<AtomicU64>,
    _receive: task::AbortOnDropHandle<()>,
}

impl DataPool {
    /// Listen on `self_tag` on the first healthy relays of `ranking`, and send as the endpoint
    /// `me`. `ranking` is the custom relay list in the order every member computes: the caller
    /// passes no relay it does not trust with payload.
    #[must_use]
    pub fn open(
        ranking: Vec<Url>,
        me: [u8; 32],
        self_tag: [u8; 32],
    ) -> (Self, mpsc::Receiver<Datagram>) {
        let (pool, events) = Pool::open(Lane::Data, ranking, LISTEN_WIDTH, &[self_tag]);
        let (out, datagrams): (mpsc::Sender<Datagram>, mpsc::Receiver<Datagram>) =
            mpsc::channel(RECEIVE_CAPACITY);
        // The pool reads the count, and the receive task adds to it.
        let dropped = Arc::new(AtomicU64::new(0));
        let receive = task::spawn(receive(events, out, Arc::clone(&dropped)));
        let link = Self {
            pool,
            me,
            dropped,
            _receive: task::AbortOnDropHandle::new(receive),
        };
        (link, datagrams)
    }

    /// Send `datagram` to the node that listens on `to_tag`. It never blocks: a datagram that
    /// does not fit the queue of the socket is dropped, and QUIC sends it again.
    pub fn send(&self, to_tag: &[u8; 32], datagram: Vec<u8>) {
        self.pool.send_datagram(to_tag, &self.me, datagram);
    }

    /// The datagrams that came in and were dropped because the consumer was behind.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The relays held and connected now, in rank order.
    pub fn connected(&self) -> impl Iterator<Item = Url> + use<> {
        self.pool.connected()
    }
}

/// Read each event as a batch and pass its datagrams on, in order. What is not a batch is
/// dropped.
async fn receive(
    mut events: mpsc::UnboundedReceiver<Event>,
    out: mpsc::Sender<Datagram>,
    // The count the pool reads.
    dropped: Arc<AtomicU64>,
) {
    while let Some(event) = events.recv().await {
        let Ok(decoded) = batch::decode(&event.content) else {
            continue;
        };
        for bytes in decoded.datagrams {
            let datagram = Datagram {
                from: decoded.from,
                bytes,
            };
            match out.try_send(datagram) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
    }
}
