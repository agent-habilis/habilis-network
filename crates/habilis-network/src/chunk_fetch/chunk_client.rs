//! The asker of the chunk fetch: it takes the value that a pointer names from the holders of its chunks, and
//! trusts no byte before it has checked it against the root.

use std::time::Duration;

use habilis_network_chunks::{ChunkMap, Root, chunk_count};
use habilis_network_doc::ChunkPointer;
use iroh::endpoint::{Connection, ReadToEndError};
use iroh::{Endpoint, EndpointAddr};
use n0_future::time as n0future_time;

use super::answer_check::{decode_chunk, decode_map};
use super::{ChunkRequest, FetchError};
use crate::transport::CHUNKS_ALPN;
use crate::util::tuning::CHUNK_STREAM_TIMEOUT;

/// The bytes that open a map answer and a chunk answer: the tag, and for a map the size.
const MAP_HEADER_BYTES: usize = 1 + 8;
const HASH_BYTES: usize = 32;

/// A holder that the fetch can ask, with the connection to it once one is made.
struct Source {
    address: EndpointAddr,
    connection: Option<Connection>,
    /// A source that failed is not asked again in this fetch.
    failed: bool,
}

/// Fetches values from the holders of their chunks over the chunk plane.
#[derive(Debug, Clone)]
pub(crate) struct ChunkClient {
    endpoint: Endpoint,
    /// How long one request can take, from the dial to the end of the answer.
    deadline: Duration,
}

impl ChunkClient {
    pub(crate) fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            deadline: CHUNK_STREAM_TIMEOUT,
        }
    }

    /// Sets how long one request can take.
    pub(crate) fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// The bytes of the value that `pointer` names as the chunks keep them (the seal of a passworded mesh is still on
    /// them), asked of `sources` in order. `stored_size` is their length: the size of the pointer, and the seal. The
    /// bytes are not kept here: the loop that asked keeps them, opens them and resolves the slice in one step, so no
    /// sweep can come between. A source that fails is skipped for the rest of the fetch, and the next one is asked.
    ///
    /// # Errors
    ///
    /// No source gave a map and every chunk that checks against the root. The error is the last one that a source
    /// gave.
    pub(crate) async fn fetch(
        &self,
        sources: &[EndpointAddr],
        pointer: ChunkPointer,
        stored_size: u64,
    ) -> Result<Vec<u8>, FetchError> {
        let mut holders: Vec<Source> = sources
            .iter()
            .map(|address| Source {
                address: address.clone(),
                connection: None,
                failed: false,
            })
            .collect();
        let root = pointer.root();
        let map = self.map_from_any(&mut holders, root, stored_size).await?;
        let mut stored = Vec::with_capacity(usize::try_from(stored_size).unwrap_or(0));
        for index in 0..map.len() {
            let chunk = self.chunk_from_any(&mut holders, &map, index).await?;
            stored.extend_from_slice(&chunk);
        }
        Ok(stored)
    }

    /// The map of `root` from the first source that gives one that checks. The answer is read up to the bytes
    /// that a map of `stored_size` has, and no further.
    async fn map_from_any(
        &self,
        holders: &mut [Source],
        root: Root,
        stored_size: u64,
    ) -> Result<ChunkMap, FetchError> {
        let limit = chunk_count(stored_size)
            .saturating_mul(HASH_BYTES)
            .saturating_add(MAP_HEADER_BYTES);
        let mut last = FetchError::NoSource;
        for holder in holders.iter_mut().filter(|holder| !holder.failed) {
            let answer: Result<ChunkMap, FetchError> = self
                .exchange(holder, ChunkRequest::Map(root), limit, 0)
                .await
                .and_then(|answer| decode_map(&answer, root, stored_size));
            match answer {
                Ok(map) => return Ok(map),
                Err(error) => last = refuse(holder, error),
            }
        }
        Err(last)
    }

    /// Chunk `index` from the first source that gives one that checks against `map`. The answer is read up to the
    /// bytes that the map gives the chunk, and no further.
    async fn chunk_from_any(
        &self,
        holders: &mut [Source],
        map: &ChunkMap,
        index: usize,
    ) -> Result<Vec<u8>, FetchError> {
        let range = map.range_of(index);
        let limit = usize::try_from(range.end - range.start)
            .map_or(usize::MAX, |length| length.saturating_add(1));
        let wire_index =
            u32::try_from(index).map_err(|_| FetchError::Malformed("too many chunks"))?;
        let request = ChunkRequest::Chunk {
            root: map.root(),
            index: wire_index,
        };
        let mut last = FetchError::NoSource;
        for holder in holders.iter_mut().filter(|holder| !holder.failed) {
            let answer: Result<Vec<u8>, FetchError> = self
                .exchange(holder, request, limit, index)
                .await
                .and_then(|answer| decode_chunk(&answer, map, index));
            match answer {
                Ok(chunk) => return Ok(chunk),
                Err(error) => last = refuse(holder, error),
            }
        }
        Err(last)
    }

    /// The connection to `holder`, made on the first call and kept for the next ones.
    async fn connection_to(&self, holder: &mut Source) -> Result<Connection, FetchError> {
        if let Some(connection) = &holder.connection {
            return Ok(connection.clone());
        }
        let connection = self
            .endpoint
            .connect(holder.address.clone(), CHUNKS_ALPN)
            .await
            .map_err(|_| FetchError::Unreachable)?;
        holder.connection = Some(connection.clone());
        Ok(connection)
    }

    /// One request on a new stream of the connection to `holder`, and the answer, read up to `limit` bytes. The
    /// connection is made on the first request. `index` names the chunk for the error of a read that went past
    /// `limit`.
    async fn exchange(
        &self,
        holder: &mut Source,
        request: ChunkRequest,
        limit: usize,
        index: usize,
    ) -> Result<Vec<u8>, FetchError> {
        let attempt = async {
            let connection = self.connection_to(holder).await?;
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|_| FetchError::Unreachable)?;
            send.write_all(&request.encode())
                .await
                .map_err(|_| FetchError::Unreachable)?;
            send.finish().map_err(|_| FetchError::Unreachable)?;
            recv.read_to_end(limit).await.map_err(|error| match error {
                ReadToEndError::TooLong => FetchError::PastDeclaredSize { index },
                ReadToEndError::Read(_) => FetchError::Unreachable,
            })
        };
        n0future_time::timeout(self.deadline, attempt)
            .await
            .unwrap_or(Err(FetchError::Stalled))
    }
}

/// Notes that `holder` gave `error`, and gives the error back. A holder that has not the chunk (the absent answer)
/// can be asked for another; every other error shows a holder that cannot be trusted or reached.
fn refuse(holder: &mut Source, error: FetchError) -> FetchError {
    if error != FetchError::Absent {
        holder.failed = true;
        holder.connection = None;
    }
    error
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::slice;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use habilis_network_chunks::{CHUNK_BYTES_USIZE, ChunkMap};
    use habilis_network_doc::ChunkPointer;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, EndpointAddr};
    use tokio::sync::mpsc;
    use tokio::task;
    use tokio::task::JoinHandle;

    use super::{ChunkClient, FetchError};
    use crate::chunk_fetch::chunk_answer::{ABSENT, encode_chunk, encode_map};
    use crate::chunk_fetch::fixtures::{
        bytes, hold_named_value, hold_named_value_sealed, name_root, state_trusting,
    };
    use crate::chunk_fetch::{ChunkRequest, Holder};
    use crate::daemon::state::{EventLoopState, MeshChunks};
    use crate::protocol::SymmetricKey;
    use crate::protocol::identity::Identity;
    use crate::testing::{fresh_state_with_mesh_key, test_key};
    use crate::transport::{CHUNKS_ALPN, ChunkAcceptor, PayloadPath};

    /// A node of the test: a real endpoint that serves the chunk plane, and the task that plays its event loop.
    struct Node {
        router: Router,
        address: EndpointAddr,
        looper: JoinHandle<()>,
    }

    impl Node {
        async fn close(self) {
            self.looper.abort();
            self.router.shutdown().await.expect("the router shuts down");
        }
    }

    async fn bind() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint")
    }

    /// A node whose loop answers each request with `answer`. A request that gets `None` is held and never answered.
    async fn serve_with(mut answer: impl FnMut(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> Node {
        let endpoint = bind().await;
        let (tx, mut asks) = mpsc::channel(16);
        let acceptor = ChunkAcceptor::new(tx, PayloadPath::RelayAllowed);
        let address = endpoint.addr();
        let router = Router::builder(endpoint)
            .accept(CHUNKS_ALPN, acceptor)
            .spawn();
        let looper = task::spawn(async move {
            let mut held = Vec::new();
            while let Some(ask) = asks.recv().await {
                match answer(&ask.request) {
                    Some(bytes) => drop(ask.reply.send(bytes)),
                    None => held.push(ask),
                }
            }
        });
        Node {
            router,
            address,
            looper,
        }
    }

    /// A node whose loop answers from `state`, as the event loop does.
    async fn serve_state(mut state: Box<EventLoopState>) -> Node {
        let endpoint = bind().await;
        let (tx, mut asks) = mpsc::channel(16);
        let acceptor = ChunkAcceptor::new(tx, PayloadPath::RelayAllowed);
        let address = endpoint.addr();
        let router = Router::builder(endpoint)
            .accept(CHUNKS_ALPN, acceptor)
            .spawn();
        let looper = task::spawn(async move {
            while let Some(ask) = asks.recv().await {
                Holder::serve(&mut state, ask, Instant::now()).await;
            }
        });
        Node {
            router,
            address,
            looper,
        }
    }

    /// The pointer that a value of this length is named by, once its chunks are held.
    fn value() -> Vec<u8> {
        bytes(CHUNK_BYTES_USIZE * 3 + 500)
    }

    /// A script that serves `value` honestly, and changes each chunk answer with `tamper`.
    fn honest(
        value: &[u8],
        mut tamper: impl FnMut(Vec<u8>) -> Vec<u8> + Send + 'static,
    ) -> impl FnMut(&[u8]) -> Option<Vec<u8>> + Send + 'static {
        let map = ChunkMap::build(value);
        let value = value.to_vec();
        move |request| match ChunkRequest::decode(request)? {
            ChunkRequest::Map(_) => Some(encode_map(&map)),
            ChunkRequest::Chunk { index, .. } => {
                let index = usize::try_from(index).ok()?;
                let range = map.range_of(index);
                let chunk = value
                    .get(usize::try_from(range.start).ok()?..usize::try_from(range.end).ok()?)?;
                Some(tamper(encode_chunk(chunk)))
            }
        }
    }

    /// An empty store for the asker, and the pointer of `value`.
    async fn asker_side(value: &[u8]) -> (MeshChunks, ChunkPointer, Endpoint) {
        let root = {
            let author = MeshChunks::open(None).expect("an in-memory store");
            author.put_value(value).await.expect("a value")
        };
        let pointer = ChunkPointer::new(root, u64::try_from(value.len()).expect("a size"));
        (
            MeshChunks::open(None).expect("an in-memory store"),
            pointer,
            bind().await,
        )
    }

    #[tokio::test]
    async fn a_value_put_on_one_node_is_fetched_by_another_with_the_same_bytes() {
        let value = value();
        let client = bind().await;
        let mut state = state_trusting(client.id());
        let peer = Identity::generate();
        let (root, _) = hold_named_value(&mut state, &peer, &value).await;
        let pointer = ChunkPointer::new(root, u64::try_from(value.len()).expect("a size"));
        let author = serve_state(Box::new(state)).await;
        let chunks = MeshChunks::open(None).expect("an in-memory store");
        let fetched: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(
                slice::from_ref(&author.address),
                pointer,
                chunks.stored_size(pointer),
            )
            .await;
        assert_eq!(
            fetched,
            Ok(value),
            "the fetched value must be the bytes that were put"
        );
        client.close().await;
        author.close().await;
    }

    #[tokio::test]
    async fn a_corrupt_chunk_is_refused_and_the_next_source_is_asked() {
        let value = value();
        let (chunks, pointer, client) = asker_side(&value).await;
        let corrupt = serve_with(honest(&value, |mut answer| {
            let last = answer.len() - 1;
            answer[last] ^= 1;
            answer
        }))
        .await;
        let alone: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(
                slice::from_ref(&corrupt.address),
                pointer,
                chunks.stored_size(pointer),
            )
            .await;
        assert!(
            matches!(alone, Err(FetchError::CorruptChunk { .. })),
            "a corrupt chunk must be refused, got {alone:?}"
        );
        let honest_node = serve_with(honest(&value, |answer| answer)).await;
        let sources: [EndpointAddr; 2] = [corrupt.address.clone(), honest_node.address.clone()];
        let fetched: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(&sources, pointer, chunks.stored_size(pointer))
            .await;
        assert_eq!(fetched, Ok(value), "the next source must give the value");
        client.close().await;
        corrupt.close().await;
        honest_node.close().await;
    }

    /// The client reads a map up to the bytes that the pointer allows, and asks for no chunk after a map that is
    /// refused.
    async fn fetch_from_a_liar(map_answer: Vec<u8>) -> (Result<Vec<u8>, FetchError>, usize) {
        let value = value();
        let (chunks, pointer, client) = asker_side(&value).await;
        // The count is shared with the loop of the node that the test reads it from.
        let chunk_requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&chunk_requests);
        let liar = serve_with(move |request| match ChunkRequest::decode(request)? {
            ChunkRequest::Map(_) => Some(map_answer.clone()),
            ChunkRequest::Chunk { .. } => {
                counted.fetch_add(1, Ordering::SeqCst);
                Some(ABSENT.to_vec())
            }
        })
        .await;
        let fetched: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(
                slice::from_ref(&liar.address),
                pointer,
                chunks.stored_size(pointer),
            )
            .await;
        client.close().await;
        liar.close().await;
        (fetched, chunk_requests.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn a_map_that_names_more_chunks_is_cut_at_the_declared_size_and_no_chunk_is_asked() {
        let longer = ChunkMap::build(&bytes(value().len() + CHUNK_BYTES_USIZE));
        let (fetched, chunk_requests) = fetch_from_a_liar(encode_map(&longer)).await;
        assert_eq!(
            fetched,
            Err(FetchError::PastDeclaredSize { index: 0 }),
            "a map past the bytes that the pointer allows must abort the read"
        );
        assert_eq!(
            chunk_requests, 0,
            "no chunk may be asked for after a map that was refused"
        );
    }

    #[tokio::test]
    async fn a_map_that_names_another_size_is_refused_before_any_chunk_is_asked() {
        // The same number of chunks, and a size that the pointer does not name.
        let other = ChunkMap::build(&bytes(value().len() + 10));
        let (fetched, chunk_requests) = fetch_from_a_liar(encode_map(&other)).await;
        assert!(
            matches!(fetched, Err(FetchError::SizeMismatch { .. })),
            "a map of another size must be refused, got {fetched:?}"
        );
        assert_eq!(
            chunk_requests, 0,
            "no chunk may be asked for after a map that was refused"
        );
    }

    #[tokio::test]
    async fn a_chunk_that_passes_the_declared_size_aborts_the_read() {
        let value = value();
        let (chunks, pointer, client) = asker_side(&value).await;
        let flood = serve_with(honest(&value, |_| {
            encode_chunk(&vec![7u8; 8 * 1024 * 1024])
        }))
        .await;
        let started = Instant::now();
        let fetched: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(
                slice::from_ref(&flood.address),
                pointer,
                chunks.stored_size(pointer),
            )
            .await;
        assert_eq!(
            fetched,
            Err(FetchError::PastDeclaredSize { index: 0 }),
            "a chunk past its declared size must abort the fetch"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the read must stop at the declared size and not take the 8 MiB"
        );
        client.close().await;
        flood.close().await;
    }

    #[tokio::test]
    async fn on_a_passworded_mesh_the_value_is_fetched_sealed_and_opened_with_the_key() {
        let key = SymmetricKey::from([5u8; 32]);
        let value = value();
        let client = bind().await;
        let mut state = fresh_state_with_mesh_key(key.clone());
        state
            .proven_endpoints
            .trust(test_key("member"), client.id());
        let peer = Identity::generate();
        let root = hold_named_value_sealed(&mut state, &peer, &value, &key).await;
        let pointer = ChunkPointer::new(root, u64::try_from(value.len()).expect("a size"));
        let author = serve_state(Box::new(state)).await;
        let keyed = MeshChunks::open(None)
            .expect("an in-memory store")
            .key(Some(key.derive(b"chunks")));
        let fetched: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(
                slice::from_ref(&author.address),
                pointer,
                keyed.stored_size(pointer),
            )
            .await;
        let sealed = fetched.expect("the member with the key must fetch the sealed bytes");
        assert_ne!(
            sealed, value,
            "the bytes that travel and rest in the chunks must be sealed"
        );
        assert_eq!(
            keyed
                .open_value(&sealed)
                .expect("the key of the mesh opens them"),
            value,
            "the member with the key must get the value"
        );
        let without = MeshChunks::open(None).expect("an in-memory store");
        let refused: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(
                slice::from_ref(&author.address),
                pointer,
                without.stored_size(pointer),
            )
            .await;
        assert!(
            refused.is_err(),
            "a node with no key expects the unsealed size, so it must not take the sealed value"
        );
        let other = MeshChunks::open(None)
            .expect("an in-memory store")
            .key(Some(SymmetricKey::from([6u8; 32])));
        let with_other_key: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .fetch(
                slice::from_ref(&author.address),
                pointer,
                other.stored_size(pointer),
            )
            .await;
        let fetched_sealed =
            with_other_key.expect("the chunks check against their root whatever the key");
        assert!(
            other.open_value(&fetched_sealed).is_err(),
            "a node with another key must not open the value"
        );
        client.close().await;
        author.close().await;
    }

    #[tokio::test]
    async fn a_member_that_is_not_the_author_serves_the_chunks_after_the_author_is_offline() {
        let value = value();
        let relay_client = bind().await;
        let late_client = bind().await;
        let mut author_state = state_trusting(relay_client.id());
        let peer = Identity::generate();
        let (root, _) = hold_named_value(&mut author_state, &peer, &value).await;
        let pointer = ChunkPointer::new(root, u64::try_from(value.len()).expect("a size"));
        let author = serve_state(Box::new(author_state)).await;
        // The relay fetches from the author, and keeps the chunks, and a slice of the peer names the root there.
        let relay_chunks = MeshChunks::open(None).expect("an in-memory store");
        let from_author: Result<Vec<u8>, FetchError> = ChunkClient::new(relay_client.clone())
            .fetch(
                slice::from_ref(&author.address),
                pointer,
                relay_chunks.stored_size(pointer),
            )
            .await;
        let stored = from_author.expect("the relay must fetch from the author");
        assert_eq!(
            stored, value,
            "the relay must fetch the bytes of the author"
        );
        relay_chunks
            .put_stored(&stored)
            .await
            .expect("the relay keeps what it fetched");
        let mut relay_state = state_trusting(late_client.id());
        relay_state.chunks = relay_chunks;
        name_root(&mut relay_state, &peer, pointer, 1);
        let relay = serve_state(Box::new(relay_state)).await;
        let author_address = author.address.clone();
        author.close().await;
        let chunks = MeshChunks::open(None).expect("an in-memory store");
        let sources: [EndpointAddr; 2] = [author_address, relay.address.clone()];
        let fetched: Result<Vec<u8>, FetchError> = ChunkClient::new(late_client.clone())
            .deadline(Duration::from_secs(2))
            .fetch(&sources, pointer, chunks.stored_size(pointer))
            .await;
        assert_eq!(
            fetched,
            Ok(value),
            "a member that is not the author must serve the chunks when the author is offline"
        );
        relay_client.close().await;
        late_client.close().await;
        relay.close().await;
    }

    #[tokio::test]
    async fn a_stalled_source_does_not_block_the_next_one() {
        let value = value();
        let (chunks, pointer, client) = asker_side(&value).await;
        let stalled = serve_with(|_| None).await;
        let honest_node = serve_with(honest(&value, |answer| answer)).await;
        let started = Instant::now();
        let sources: [EndpointAddr; 2] = [stalled.address.clone(), honest_node.address.clone()];
        let fetched: Result<Vec<u8>, FetchError> = ChunkClient::new(client.clone())
            .deadline(Duration::from_millis(1500))
            .fetch(&sources, pointer, chunks.stored_size(pointer))
            .await;
        assert_eq!(
            fetched,
            Ok(value),
            "the source after the stalled one must give the value"
        );
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "the stalled source must cost one deadline and not one for each chunk, it took {:?}",
            started.elapsed()
        );
        client.close().await;
        stalled.close().await;
        honest_node.close().await;
    }
}
