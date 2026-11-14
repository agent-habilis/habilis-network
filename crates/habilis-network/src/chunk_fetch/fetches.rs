//! The fetches that this node runs for the pointers that wait for their chunks: which ones to start, from whom, and
//! what the event loop does when one ends.

use std::collections::{HashMap, HashSet};

use habilis_network_chunks::Root;
use habilis_network_doc::ChunkPointer;
use habilis_network_util::clock::Instant;
use habilis_network_util::tuning::{
    CHUNK_FETCH_REFUSED_RETRY, CHUNK_FETCH_RETRY, CHUNK_FETCHES_MAX, CHUNK_SOURCES_MAX,
    CHUNK_STORE_BUDGET_BYTES,
};
use iroh::EndpointAddr;
use n0_future::task;
use tokio::sync::mpsc;

use super::{ChunkClient, FetchError, keep_held};
use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip;
use crate::gossip::app::NodeApp;
use crate::gossip::event::NodeEvent;
use crate::protocol::{AuthorKey, Channel};

/// The name of one fetch: the value that the slice of an author names on a channel.
type Wanted = (Channel, AuthorKey, Root);

/// A fetch that ended, with what it got.
#[derive(Debug)]
pub(crate) struct FetchDone {
    pub(crate) channel: Channel,
    pub(crate) author: AuthorKey,
    pub(crate) pointer: ChunkPointer,
    /// The bytes as the chunks keep them, or why no holder gave them.
    pub(crate) result: Result<Vec<u8>, FetchError>,
}

/// The fetches in flight, and when a fetch that failed can start again.
#[derive(Debug)]
pub(crate) struct Fetches {
    done: mpsc::UnboundedSender<FetchDone>,
    /// The fetches in flight, with the bytes that each one will keep.
    running: HashMap<Wanted, u64>,
    retry_after: HashMap<Wanted, Instant>,
}

impl Fetches {
    /// Fetches that report to `done`, the channel that the event loop reads.
    pub(crate) fn new(done: mpsc::UnboundedSender<FetchDone>) -> Self {
        Self {
            done,
            running: HashMap::new(),
            retry_after: HashMap::new(),
        }
    }

    /// How many fetches run, for the tests that check a pointer starts one.
    #[cfg(test)]
    pub(crate) fn running(&self) -> usize {
        self.running.len()
    }

    /// The bytes that this node can still take for the chunks of fetched values: the budget, less what it holds
    /// whole and what the fetches in flight will keep.
    fn byte_room(&self, held: u64, budget: u64) -> u64 {
        let in_flight: u64 = self.running.values().sum();
        budget.saturating_sub(held).saturating_sub(in_flight)
    }

    /// The pointers to fetch now: they wait for chunks, no fetch runs for them, their wait after a failure is over,
    /// and their bytes fit in `byte_room`. At most as many as the cap leaves room for.
    fn due(
        &mut self,
        waiting: Vec<(Channel, AuthorKey, ChunkPointer)>,
        now: Instant,
        byte_room: u64,
        size_of: impl Fn(&ChunkPointer) -> u64,
    ) -> Vec<(Channel, AuthorKey, ChunkPointer)> {
        let wanted: HashSet<Wanted> = waiting
            .iter()
            .map(|(channel, author, pointer)| (*channel, *author, pointer.root()))
            .collect();
        self.retry_after.retain(|name, _| wanted.contains(name));
        let room = CHUNK_FETCHES_MAX.saturating_sub(self.running.len());
        let mut byte_room_left = byte_room;
        let mut due = Vec::new();
        for (channel, author, pointer) in waiting {
            let name = (channel, author, pointer.root());
            let waits = self
                .retry_after
                .get(&name)
                .is_some_and(|after| now < *after);
            if due.len() >= room || self.running.contains_key(&name) || waits {
                continue;
            }
            // A value that does not fit is not fetched now, and the next that fits is. It waits for room.
            let size = size_of(&pointer);
            if size <= byte_room_left {
                byte_room_left -= size;
                due.push((channel, author, pointer));
            }
        }
        due
    }
}

/// The holders to ask for the value of `author`: the author first, then the members that this node knows, with no
/// holder twice, and at most `CHUNK_SOURCES_MAX`.
fn sources_of(state: &EventLoopState, author: &AuthorKey) -> Vec<EndpointAddr> {
    let mut sources: Vec<EndpointAddr> = Vec::new();
    let author_address = state.address_of(author);
    let known = author_address.into_iter().chain(state.member_addresses());
    for address in known {
        if sources.len() < CHUNK_SOURCES_MAX && sources.iter().all(|held| held.id != address.id) {
            sources.push(address);
        }
    }
    sources
}

/// Starts the fetch of each pointer that waits for its chunks, and that no fetch runs for. Each fetch is a task
/// that holds no state of the node: it gets the holders and the size, and reports the bytes to the event loop.
pub(crate) fn start(state: &mut EventLoopState, context: &HandlerCtx<'_>, now: Instant) {
    let waiting = state.docs.unresolved();
    let room = state
        .fetches
        .byte_room(state.held_chunk_bytes(), CHUNK_STORE_BUDGET_BYTES);
    let chunks = &state.chunks;
    let due = state
        .fetches
        .due(waiting, now, room, |pointer| chunks.stored_size(*pointer));
    for (channel, author, pointer) in due {
        let sources = sources_of(state, &author);
        let stored_size = state.chunks.stored_size(pointer);
        let client = ChunkClient::new(context.endpoint.clone());
        let done = state.fetches.done.clone();
        state
            .fetches
            .running
            .insert((channel, author, pointer.root()), stored_size);
        task::spawn(async move {
            let result = client.fetch(&sources, pointer, stored_size).await;
            drop(done.send(FetchDone {
                channel,
                author,
                pointer,
                result,
            }));
        });
    }
}

/// What the sweep tick does for the chunks: a member that left, or lapsed, took its slice, so the chunks that only
/// it named go, and a pointer whose fetch failed, or that found no holder, is fetched again once its wait is over.
pub(crate) async fn on_sweep(state: &mut EventLoopState, context: &HandlerCtx<'_>, now: Instant) {
    keep_held(state).await;
    start(state, context, now);
}

/// What the event loop does when a fetch ends: it opens the bytes, keeps the value with the slice, keeps the chunks
/// so that this node can serve them, sweeps the store, and shows the change, all in this one step. A fetch that
/// failed starts again after a wait, and the view keeps the last complete version.
pub(crate) async fn finish(
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
    done: FetchDone,
    now: Instant,
) {
    let FetchDone {
        channel,
        author,
        pointer,
        result,
    } = done;
    let name = (channel, author, pointer.root());
    state.fetches.running.remove(&name);
    let stored = match result {
        Ok(stored) => stored,
        Err(error) => {
            tracing::debug!(target: "habilis_network::gossip", %error, "a value was not fetched");
            state
                .fetches
                .retry_after
                .insert(name, now + CHUNK_FETCH_RETRY);
            return;
        }
    };
    match resolve(state, (channel, &author), pointer, &stored) {
        Resolution::Kept => {}
        Resolution::Superseded => return,
        Resolution::Refused(reason) => {
            tracing::warn!(target: "habilis_network::gossip", reason, "a fetched value was refused");
            state
                .fetches
                .retry_after
                .insert(name, now + CHUNK_FETCH_REFUSED_RETRY);
            return;
        }
    }
    if let Err(error) = state.chunks.put_stored(&stored).await {
        tracing::warn!(target: "habilis_network::gossip", %error, "a fetched value was not kept in the chunk store");
    }
    keep_held(state).await;
    surface(state, context, channel, &author);
    if channel == Channel::Meta {
        app.on_meta_applied(&author, state, context);
    }
}

/// What came of the bytes that a fetch gave.
enum Resolution {
    /// The slice holds the value whole now.
    Kept,
    /// A newer version replaced the pointer while the chunks were on their way, so the value is of no use.
    Superseded,
    /// The bytes are not a value that this node takes: they do not open, are not an object, or hold the reserved key.
    Refused(&'static str),
}

/// Opens `stored`, reads the value, and keeps it with the slice of `author` if the slice still holds `pointer`.
fn resolve(
    state: &mut EventLoopState,
    (channel, author): (Channel, &AuthorKey),
    pointer: ChunkPointer,
    stored: &[u8],
) -> Resolution {
    let Ok(plain) = state.chunks.open_value(stored) else {
        return Resolution::Refused("the bytes do not open with the key of the mesh");
    };
    let parsed: Result<serde_json::Value, serde_json::Error> = serde_json::from_slice(&plain);
    let Ok(value) = parsed else {
        return Resolution::Refused("the bytes are not JSON");
    };
    match state.docs.resolve_pointer(channel, author, pointer, value) {
        Ok(true) => Resolution::Kept,
        Ok(false) => Resolution::Superseded,
        Err(_) => Resolution::Refused("the value is not an object, or holds the reserved key"),
    }
}

/// Shows the change of `author` on `channel`: the signed slice that names the value, and the document with the whole
/// value in it. A slice from before the join horizon is not shown, as it is not shown when it arrives.
fn surface(state: &EventLoopState, context: &HandlerCtx<'_>, channel: Channel, author: &AuthorKey) {
    let Some(frame) = state.docs.held_frame(channel, author) else {
        return;
    };
    if !state.is_surfaceable(frame.timestamp) {
        return;
    }
    let event = gossip::surface_view(frame, state.docs.plain_body(channel, author));
    context.sink.emit(NodeEvent::StateChanged {
        channel,
        event: Box::new(event),
        document: state.docs.to_json(channel),
        is_self: false,
    });
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use habilis_network_chunks::{CHUNK_BYTES_USIZE, Root};
    use habilis_network_doc::ChunkPointer;
    use habilis_network_util::clock::Instant;
    use habilis_network_util::tuning::{
        CHUNK_FETCH_REFUSED_RETRY, CHUNK_FETCH_RETRY, CHUNK_FETCHES_MAX, CHUNK_SOURCES_MAX,
    };
    use iroh::endpoint::presets;
    use iroh::{EndpointAddr, EndpointId};
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;
    use tokio::sync::mpsc;

    use super::{FetchDone, Fetches};
    use crate::chunk_fetch::{FetchError, fixtures};
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::{EventLoopState, MeshChunks};
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::{NodeEvent, NodeSink};
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::Authored;
    use crate::protocol::{AuthorKey, Channel, MeshId, Nickname, SymmetricKey};
    use crate::testing;
    use crate::transport::MeshSender;

    /// A sink that keeps what the node shows.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<NodeEvent>>);

    impl Recorder {
        fn state_changes(&self) -> Vec<NodeEvent> {
            let events = self.0.lock().expect("the record lock");
            events
                .iter()
                .filter(|event| matches!(event, NodeEvent::StateChanged { .. }))
                .cloned()
                .collect()
        }
    }

    impl NodeSink for Recorder {
        fn emit(&self, event: NodeEvent) {
            self.0.lock().expect("the record lock").push(event);
        }
    }

    /// An app that does nothing.
    struct Inert;

    #[async_trait::async_trait]
    impl NodeApp for Inert {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::NONE
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _context: &HandlerCtx<'_>,
        ) -> bool {
            false
        }
    }

    /// One node on a peerless topic, with everything that a `HandlerCtx` borrows.
    struct Harness {
        endpoint: iroh::Endpoint,
        _gossip: Gossip,
        sender: MeshSender,
        mesh: MeshId,
        identity: Identity,
        our_pubkey: AuthorKey,
        author: Nickname,
        sink: Recorder,
    }

    impl Harness {
        async fn spawn() -> Self {
            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(proto::TopicId::from_bytes([4u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            Self {
                endpoint,
                _gossip: gossip,
                sender: MeshSender::new(gossip_sender),
                mesh: MeshId::from("test"),
                identity,
                our_pubkey,
                author: testing::nick("holder"),
                sink: Recorder::default(),
            }
        }

        fn context(&self) -> HandlerCtx<'_> {
            HandlerCtx {
                sender: &self.sender,
                endpoint: &self.endpoint,
                mesh: &self.mesh,
                author: &self.author,
                identity: &self.identity,
                our_pubkey: self.our_pubkey,
                max_peers: 16,
                rendezvous_id: testing::endpoint_id(9),
                external_msg_tx: None,
                sink: &self.sink,
            }
        }
    }

    /// The pointer and the stored bytes of a value, as an author that holds the chunks gives them. The value is a
    /// JSON object of about `len` bytes, so it opens and parses on the other side.
    async fn author_side(
        len: usize,
        key: Option<SymmetricKey>,
    ) -> (ChunkPointer, Vec<u8>, serde_json::Value) {
        let text: String = String::from_utf8(
            fixtures::bytes(len)
                .iter()
                .map(|byte| b'a' + byte % 26)
                .collect(),
        )
        .expect("letters");
        let value = serde_json::json!({ "text": text });
        let plain = serde_json::to_vec(&value).expect("a JSON value");
        let chunks = MeshChunks::open(None).expect("an in-memory store").key(key);
        let root = chunks.put_value(&plain).await.expect("a value");
        let pointer = ChunkPointer::new(root, u64::try_from(plain.len()).expect("a size"));
        (pointer, chunks.stored_bytes(root).await, value)
    }

    /// The state of a node that holds the pointer of `author` as its first version.
    fn state_waiting(author: &Identity, pointer: ChunkPointer) -> EventLoopState {
        let mut state = testing::fresh_state();
        fixtures::name_root(&mut state, author, pointer, 1);
        state
    }

    fn fetches() -> (Fetches, mpsc::UnboundedReceiver<FetchDone>) {
        let (done, received) = mpsc::unbounded_channel();
        (Fetches::new(done), received)
    }

    #[tokio::test]
    async fn a_fetched_value_is_shown_once_whole_and_its_chunks_are_kept() {
        let harness = Harness::spawn().await;
        let context = harness.context();
        let author = Identity::generate();
        let (pointer, stored, value) = author_side(CHUNK_BYTES_USIZE + 4_000, None).await;
        let mut state = state_waiting(&author, pointer);
        assert!(
            harness.sink.state_changes().is_empty(),
            "nothing is shown before the value is fetched"
        );
        let done = FetchDone {
            channel: Channel::State,
            author: author.author_key(),
            pointer,
            result: Ok(stored),
        };
        super::finish(&mut state, &mut Inert, &context, done, Instant::now()).await;
        let changes = harness.sink.state_changes();
        assert_eq!(
            changes.len(),
            1,
            "the change is shown once, when the value is whole"
        );
        let NodeEvent::StateChanged {
            channel,
            document,
            is_self,
            ..
        } = &changes[0]
        else {
            panic!("a state change");
        };
        assert_eq!(*channel, Channel::State, "the channel of the slice");
        assert!(!is_self, "the change is not our own");
        let hex = String::from_utf8_lossy(&author.author_key().hex()).into_owned();
        assert_eq!(
            document.get(&hex),
            Some(&value),
            "the document must hold the whole value of the author"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            2,
            "the chunks are kept, so this node serves them in turn"
        );
        assert!(
            !state
                .docs
                .is_unresolved(Channel::State, &author.author_key()),
            "the pointer is resolved"
        );
        harness.endpoint.close().await;
    }

    #[tokio::test]
    async fn a_value_for_a_pointer_that_a_newer_version_replaced_is_not_shown() {
        let harness = Harness::spawn().await;
        let context = harness.context();
        let author = Identity::generate();
        let (pointer, stored, _) = author_side(CHUNK_BYTES_USIZE + 4_000, None).await;
        let mut state = state_waiting(&author, pointer);
        fixtures::slice_of_peer(
            &mut state,
            &author,
            r#"{"version":2,"value":{"newer":1}}"#,
            2,
        );
        let done = FetchDone {
            channel: Channel::State,
            author: author.author_key(),
            pointer,
            result: Ok(stored),
        };
        super::finish(&mut state, &mut Inert, &context, done, Instant::now()).await;
        assert!(
            harness.sink.state_changes().is_empty(),
            "the late value of a replaced pointer is not shown"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "the late value of a replaced pointer is not kept"
        );
        harness.endpoint.close().await;
    }

    #[tokio::test]
    async fn a_fetch_that_failed_shows_nothing_and_starts_again_after_the_wait() {
        let harness = Harness::spawn().await;
        let context = harness.context();
        let author = Identity::generate();
        let (pointer, _, _) = author_side(CHUNK_BYTES_USIZE + 4_000, None).await;
        let mut state = state_waiting(&author, pointer);
        let now = Instant::now();
        let waiting = state.docs.unresolved();
        assert_eq!(
            state
                .fetches
                .due(waiting.clone(), now, u64::MAX, ChunkPointer::size)
                .len(),
            1,
            "a pointer that waits is due"
        );
        let done = FetchDone {
            channel: Channel::State,
            author: author.author_key(),
            pointer,
            result: Err(FetchError::NoSource),
        };
        super::finish(&mut state, &mut Inert, &context, done, now).await;
        assert!(
            harness.sink.state_changes().is_empty(),
            "a failure shows nothing"
        );
        assert!(
            state
                .fetches
                .due(waiting.clone(), now, u64::MAX, ChunkPointer::size)
                .is_empty(),
            "a fetch that failed waits before it starts again"
        );
        assert_eq!(
            state
                .fetches
                .due(
                    waiting,
                    now + CHUNK_FETCH_RETRY,
                    u64::MAX,
                    ChunkPointer::size
                )
                .len(),
            1,
            "the fetch starts again when the wait is over"
        );
        harness.endpoint.close().await;
    }

    #[test]
    fn a_value_that_is_not_an_object_is_refused_with_a_long_wait() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::gossip",
                "a fetched value was refused",
            );
            let harness = Harness::spawn().await;
            let context = harness.context();
            let author = Identity::generate();
            let chunks = MeshChunks::open(None).expect("an in-memory store");
            let plain = serde_json::to_vec(&serde_json::json!([1, 2, 3])).expect("JSON");
            let root = chunks.put_value(&plain).await.expect("a value");
            let pointer = ChunkPointer::new(root, u64::try_from(plain.len()).expect("a size"));
            let mut state = state_waiting(&author, pointer);
            let now = Instant::now();
            let done = FetchDone {
                channel: Channel::State,
                author: author.author_key(),
                pointer,
                result: Ok(chunks.stored_bytes(root).await),
            };
            super::finish(&mut state, &mut Inert, &context, done, now).await;
            assert!(
                harness.sink.state_changes().is_empty(),
                "a refused value shows nothing"
            );
            assert!(
                state
                    .docs
                    .is_unresolved(Channel::State, &author.author_key()),
                "a refused value leaves the pointer waiting"
            );
            let waiting = state.docs.unresolved();
            assert!(
                state
                    .fetches
                    .due(
                        waiting.clone(),
                        now + CHUNK_FETCH_RETRY,
                        u64::MAX,
                        ChunkPointer::size
                    )
                    .is_empty(),
                "the author is wrong, so the wait is longer than for a failed fetch"
            );
            assert_eq!(
                state
                    .fetches
                    .due(
                        waiting,
                        now + CHUNK_FETCH_REFUSED_RETRY,
                        u64::MAX,
                        ChunkPointer::size
                    )
                    .len(),
                1,
                "the fetch starts again when the long wait is over"
            );
            harness.endpoint.close().await;
        });
    }

    #[tokio::test]
    async fn on_a_passworded_mesh_the_sealed_bytes_open_with_the_key_of_the_mesh() {
        let harness = Harness::spawn().await;
        let context = harness.context();
        let mesh_key = SymmetricKey::from([5u8; 32]);
        let author = Identity::generate();
        let (pointer, stored, value) =
            author_side(CHUNK_BYTES_USIZE + 4_000, Some(mesh_key.derive(b"chunks"))).await;
        let mut state = testing::fresh_state_with_mesh_key(mesh_key.clone());
        fixtures::name_root_sealed(&mut state, &author, pointer, 1, &mesh_key);
        let done = FetchDone {
            channel: Channel::State,
            author: author.author_key(),
            pointer,
            result: Ok(stored),
        };
        super::finish(&mut state, &mut Inert, &context, done, Instant::now()).await;
        let changes = harness.sink.state_changes();
        assert_eq!(
            changes.len(),
            1,
            "the value of a passworded mesh is shown once"
        );
        let NodeEvent::StateChanged { document, .. } = &changes[0] else {
            panic!("a state change");
        };
        let hex = String::from_utf8_lossy(&author.author_key().hex()).into_owned();
        assert_eq!(
            document.get(&hex),
            Some(&value),
            "the opened value is shown"
        );
        harness.endpoint.close().await;
    }

    #[test]
    fn at_most_the_cap_of_fetches_run_at_once_and_a_running_fetch_is_not_started_twice() {
        let (mut fetches, _received) = fetches();
        let waiting: Vec<(Channel, AuthorKey, ChunkPointer)> = (0..10_u8)
            .map(|number| {
                (
                    Channel::State,
                    testing::test_key(&format!("author{number}")),
                    ChunkPointer::new(Root::from_bytes([number; 32]), 100_000),
                )
            })
            .collect();
        let now = Instant::now();
        let first = fetches.due(waiting.clone(), now, u64::MAX, ChunkPointer::size);
        assert_eq!(
            first.len(),
            CHUNK_FETCHES_MAX,
            "no more than the cap at once"
        );
        for (channel, author, pointer) in &first {
            fetches
                .running
                .insert((*channel, *author, pointer.root()), pointer.size());
        }
        assert!(
            fetches
                .due(waiting.clone(), now, u64::MAX, ChunkPointer::size)
                .is_empty(),
            "while the cap is full, no other fetch starts"
        );
        let (channel, author, pointer) = first[0];
        fetches.running.remove(&(channel, author, pointer.root()));
        assert_eq!(
            fetches
                .due(waiting, now, u64::MAX, ChunkPointer::size)
                .len(),
            1,
            "one place is free, so one fetch starts"
        );
    }

    #[test]
    fn the_author_is_asked_first_and_each_holder_once_and_few() {
        let mut state = testing::fresh_state();
        let author_key = state.name_key("author");
        state.peers.insert(author_key);
        let author_address = EndpointAddr::new(testing::endpoint_id(1));
        state.note_key_endpoint(author_key, author_address.clone());
        for number in 2..12_u8 {
            let key = state.name_key(&format!("member{number}"));
            state.peers.insert(key);
            state.note_key_endpoint(key, EndpointAddr::new(testing::endpoint_id(number)));
        }
        let sources = super::sources_of(&state, &author_key);
        assert_eq!(
            sources.first().map(|address| address.id),
            Some(author_address.id),
            "the author is the first holder"
        );
        assert!(
            sources.len() <= CHUNK_SOURCES_MAX,
            "no more holders than the cap, got {}",
            sources.len()
        );
        let ids: Vec<EndpointId> = sources.iter().map(|address| address.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "each holder once");
    }
    /// `count` pointers of `size` bytes each, of authors that differ.
    fn waiting_of(count: u8, size: u64) -> Vec<(Channel, AuthorKey, ChunkPointer)> {
        (0..count)
            .map(|number| {
                (
                    Channel::State,
                    testing::test_key(&format!("author{number}")),
                    ChunkPointer::new(Root::from_bytes([number; 32]), size),
                )
            })
            .collect()
    }

    #[test]
    fn a_value_that_would_take_the_held_bytes_past_the_budget_is_not_fetched() {
        let (mut fetches, _received) = fetches();
        let now = Instant::now();
        let three = waiting_of(3, 100_000);
        let two_fit = fetches.due(three.clone(), now, 250_000, ChunkPointer::size);
        assert_eq!(
            two_fit.len(),
            2,
            "the room of 250000 bytes takes two values of 100000"
        );
        let none_fit = fetches.due(three, now, 99_999, ChunkPointer::size);
        assert!(
            none_fit.is_empty(),
            "no value fits in a room that is one byte short"
        );
        let mut mixed = waiting_of(2, 100_000);
        mixed.insert(
            0,
            (
                Channel::State,
                testing::test_key("small"),
                ChunkPointer::new(Root::from_bytes([200; 32]), 10),
            ),
        );
        let big_skipped = fetches.due(mixed, now, 100_050, ChunkPointer::size);
        assert_eq!(
            big_skipped.len(),
            2,
            "a value that does not fit is skipped, and the next that fits is fetched"
        );
    }

    #[test]
    fn the_room_is_the_budget_less_the_bytes_held_whole_and_the_bytes_in_flight() {
        let (mut fetches, _received) = fetches();
        assert_eq!(
            fetches.byte_room(0, 1_000),
            1_000,
            "an empty node has the whole budget"
        );
        assert_eq!(
            fetches.byte_room(300, 1_000),
            700,
            "the bytes held whole are not room"
        );
        let name = (
            Channel::State,
            testing::test_key("author"),
            Root::from_bytes([1; 32]),
        );
        fetches.running.insert(name, 200);
        assert_eq!(
            fetches.byte_room(300, 1_000),
            500,
            "the bytes that a running fetch will keep are not room either"
        );
        assert_eq!(
            fetches.byte_room(2_000, 1_000),
            0,
            "a node past its budget has no room"
        );
    }

    #[tokio::test]
    async fn the_held_bytes_are_those_of_the_values_held_whole_of_every_author_and_channel() {
        let mut state = testing::fresh_state();
        let first = Identity::generate();
        let second = Identity::generate();
        let waiting = ChunkPointer::new(Root::from_bytes([3; 32]), 70_000);
        let whole = ChunkPointer::new(Root::from_bytes([4; 32]), 90_000);
        fixtures::name_root(&mut state, &first, waiting, 1);
        fixtures::name_root(&mut state, &second, whole, 1);
        assert_eq!(
            state.held_chunk_bytes(),
            0,
            "a pointer that waits holds nothing"
        );
        state
            .docs
            .resolve_pointer(
                Channel::State,
                &second.author_key(),
                whole,
                serde_json::json!({"a": 1}),
            )
            .expect("an object");
        assert_eq!(
            state.held_chunk_bytes(),
            90_000,
            "the value held whole counts, as the store keeps it"
        );
    }

    #[tokio::test]
    async fn the_sweep_tick_frees_the_chunks_of_a_member_that_left_and_starts_the_wait_that_is_over()
     {
        let harness = Harness::spawn().await;
        let context = harness.context();
        let leaver = Identity::generate();
        let waiting = Identity::generate();
        let (held, stored, _) = author_side(CHUNK_BYTES_USIZE + 4_000, None).await;
        let mut state = state_waiting(&leaver, held);
        assert!(
            state
                .docs
                .resolve_pointer(
                    Channel::State,
                    &leaver.author_key(),
                    held,
                    serde_json::json!({"a": 1})
                )
                .expect("an object"),
            "the value of the member is whole"
        );
        state
            .chunks
            .put_stored(&stored)
            .await
            .expect("the chunks are kept");
        let (other, _, _) = author_side(CHUNK_BYTES_USIZE + 9_000, None).await;
        fixtures::name_root(&mut state, &waiting, other, 1);
        state.docs.forget(&leaver.author_key(), Instant::now());
        super::on_sweep(&mut state, &context, Instant::now()).await;
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "the sweep tick frees the chunks that no slice names any more"
        );
        assert_eq!(
            state.fetches.running(),
            1,
            "the sweep tick starts the fetch of the pointer that waits"
        );
        harness.endpoint.close().await;
    }
}
