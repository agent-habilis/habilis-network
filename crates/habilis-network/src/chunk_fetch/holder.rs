//! The answer of this node to one chunk request: the map or a chunk of a root that a live slice names, to a member
//! of the mesh, within the budget, and the one absent byte in every other case.

use habilis_network_util::clock::Instant;
use iroh::EndpointId;

use super::chunk_answer::{ABSENT, encode_chunk, encode_map};
use super::{ChunkRequest, ChunkServeBudget};
use crate::daemon::state::{ChannelDocs, MeshChunks};
use crate::transport::proven_endpoints::ProvenEndpoints;

/// What this node holds, read to answer a request.
#[derive(Clone, Copy)]
pub(crate) struct Holder<'state> {
    pub(crate) chunks: &'state MeshChunks,
    pub(crate) docs: &'state ChannelDocs,
    pub(crate) proven: &'state ProvenEndpoints,
}

impl Holder<'_> {
    /// The answer to the request in `request`, asked by the connection of `from`. Every case that gives nothing gives
    /// the same absent bytes: a probe cannot tell a root that no slice names from a chunk that is not held, or a
    /// request over the budget from either.
    pub(crate) async fn answer(
        self,
        budget: &mut ChunkServeBudget,
        from: EndpointId,
        request: &[u8],
        now: Instant,
    ) -> Vec<u8> {
        let Ok(request) = ChunkRequest::decode(request) else {
            return ABSENT.to_vec();
        };
        // A stranger comes first, so it cannot use the budget of the members.
        if self.proven.trusted_signer(from).is_none() || !budget.admit(from, now) {
            return ABSENT.to_vec();
        }
        let root = match request {
            ChunkRequest::Map(root) | ChunkRequest::Chunk { root, .. } => root,
        };
        if !self.docs.names_root(root) {
            return ABSENT.to_vec();
        }
        let Ok(Some(map)) = self.chunks.map(root).await else {
            return ABSENT.to_vec();
        };
        match request {
            ChunkRequest::Map(_) => encode_map(&map),
            ChunkRequest::Chunk { index, .. } => {
                let leaf = usize::try_from(index).ok().and_then(|at| map.leaf(at));
                let Some(hash) = leaf else {
                    return ABSENT.to_vec();
                };
                match self.chunks.chunk(hash).await {
                    Ok(Some(bytes)) => encode_chunk(&bytes),
                    Ok(None) | Err(_) => ABSENT.to_vec(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_chunks::{CHUNK_BYTES_USIZE, ChunkMap, Root};
    use habilis_network_doc::{ChunkPointer, SliceIngest};
    use habilis_network_util::clock::Instant;
    use iroh::EndpointId;

    use super::{ABSENT, ChunkServeBudget, Holder};
    use crate::chunk_fetch::ChunkRequest;
    use crate::chunk_fetch::chunk_answer::{decode_chunk, decode_map};
    use crate::daemon::state::EventLoopState;
    use crate::protocol::identity::Identity;
    use crate::protocol::{Channel, MeshId, Message, MessageBody};
    use crate::testing::{endpoint_id, fresh_state, nick, test_key};
    use habilis_network_util::tuning::CHUNK_SERVES_PER_WINDOW;

    /// Bytes that no two chunks of share, `len` long.
    fn bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from((index * 31 + index / 7) % 251).expect("a byte"))
            .collect()
    }

    /// A state that trusts `endpoint_id(1)` as the endpoint of a member.
    fn state_with_member() -> (EventLoopState, EndpointId) {
        let mut state = fresh_state();
        let member = endpoint_id(1);
        state.proven_endpoints.trust(test_key("member"), member);
        (state, member)
    }

    /// Holds `value` as chunks, and a slice of `peer` that names them. Returns the root and the map.
    async fn hold_named_value(
        state: &mut EventLoopState,
        peer: &Identity,
        value: &[u8],
    ) -> (Root, ChunkMap) {
        let root = state.chunks.put_value(value).await.expect("a value");
        let map = state
            .chunks
            .map(root)
            .await
            .expect("a lookup")
            .expect("a map");
        let size = u64::try_from(value.len()).expect("a size");
        name_root(state, peer, ChunkPointer::new(root, size), 1);
        (root, map)
    }

    /// Ingests a slice of a peer, with `version`, that names `pointer`.
    fn name_root(state: &mut EventLoopState, peer: &Identity, pointer: ChunkPointer, version: u64) {
        let body = serde_json::json!({"version": version, "value": pointer.to_value()});
        slice_of_peer(state, peer, &body.to_string(), version);
    }

    /// Ingests a slice of a peer, with the body `text`.
    fn slice_of_peer(state: &mut EventLoopState, peer: &Identity, text: &str, version: u64) {
        let body = MessageBody::try_new(text).expect("a body");
        let frame =
            Message::new_channel_event(&MeshId::from("test"), &nick("peer"), body, Channel::State)
                .sign(peer);
        assert_eq!(
            state
                .docs
                .ingest(Channel::State, &frame, true, Instant::now()),
            SliceIngest::Applied,
            "the slice of version {version} must apply"
        );
    }

    async fn ask(
        state: &EventLoopState,
        budget: &mut ChunkServeBudget,
        from: EndpointId,
        request: &[u8],
    ) -> Vec<u8> {
        let holder = Holder {
            chunks: &state.chunks,
            docs: &state.docs,
            proven: &state.proven_endpoints,
        };
        holder.answer(budget, from, request, Instant::now()).await
    }

    #[tokio::test]
    async fn a_member_gets_the_map_and_each_chunk_of_a_root_that_a_slice_names() {
        let peer = Identity::generate();
        let (mut state, member) = state_with_member();
        let value = bytes(CHUNK_BYTES_USIZE + 100);
        let (root, map) = hold_named_value(&mut state, &peer, &value).await;
        let mut budget = ChunkServeBudget::default();
        let size = u64::try_from(value.len()).expect("a size");

        let map_answer = ask(
            &state,
            &mut budget,
            member,
            &ChunkRequest::Map(root).encode(),
        )
        .await;
        assert_eq!(
            decode_map(&map_answer, root, size),
            Ok(map.clone()),
            "the answer to a map request must be the map"
        );
        for index in 0..map.len() {
            let request = ChunkRequest::Chunk {
                root,
                index: u32::try_from(index).expect("an index"),
            };
            let chunk_answer = ask(&state, &mut budget, member, &request.encode()).await;
            let range = map.range_of(index);
            let expected = &value[usize::try_from(range.start).expect("a start")
                ..usize::try_from(range.end).expect("an end")];
            assert_eq!(
                decode_chunk(&chunk_answer, &map, index),
                Ok(expected.to_vec()),
                "the answer to a request of chunk {index} must be the chunk"
            );
        }
    }

    #[tokio::test]
    async fn a_peer_that_is_not_a_member_gets_the_absent_answer_and_spends_no_budget() {
        let peer = Identity::generate();
        let (mut state, member) = state_with_member();
        let (root, _) = hold_named_value(&mut state, &peer, &bytes(CHUNK_BYTES_USIZE + 100)).await;
        let mut budget = ChunkServeBudget::default();
        let request = ChunkRequest::Map(root).encode();
        for _ in 0..(CHUNK_SERVES_PER_WINDOW + 5) {
            assert_eq!(
                ask(&state, &mut budget, endpoint_id(9), &request).await,
                ABSENT,
                "an endpoint that no member proved must get the absent answer"
            );
        }
        assert_ne!(
            ask(&state, &mut budget, member, &request).await,
            ABSENT,
            "the requests of a stranger must not use the budget of the members"
        );
    }

    #[tokio::test]
    async fn every_case_that_gives_nothing_gives_the_same_bytes() {
        let peer = Identity::generate();
        let (mut state, member) = state_with_member();
        let value = bytes(CHUNK_BYTES_USIZE + 100);
        let (root, _) = hold_named_value(&mut state, &peer, &value).await;
        // The chunks of this value are held, and no slice names its root.
        let unnamed = state
            .chunks
            .put_value(&bytes(CHUNK_BYTES_USIZE * 2 + 5))
            .await
            .expect("an unnamed value");
        // A slice names this root, and the store holds nothing of it.
        let missing = Root::from_bytes([3; 32]);
        name_root(&mut state, &peer, ChunkPointer::new(missing, 10), 2);
        let mut budget = ChunkServeBudget::default();
        let requests = [
            (
                "an unknown root",
                ChunkRequest::Map(Root::from_bytes([9; 32])).encode(),
            ),
            (
                "a held root that no slice names",
                ChunkRequest::Map(unnamed).encode(),
            ),
            (
                "a chunk of a held root that no slice names",
                ChunkRequest::Chunk {
                    root: unnamed,
                    index: 0,
                }
                .encode(),
            ),
            (
                "a root that a slice names and nothing holds",
                ChunkRequest::Map(missing).encode(),
            ),
            (
                "a chunk index past the map",
                ChunkRequest::Chunk { root, index: 2 }.encode(),
            ),
            ("bytes that are no request", vec![0xff, 1, 2]),
            ("an empty request", Vec::new()),
        ];
        for (name, request) in requests {
            assert_eq!(
                ask(&state, &mut budget, member, &request).await,
                ABSENT,
                "{name} must get the absent answer, the same bytes as every other refusal"
            );
        }
    }

    #[tokio::test]
    async fn a_root_that_a_newer_version_no_longer_names_is_not_served() {
        let peer = Identity::generate();
        let (mut state, member) = state_with_member();
        let (root, _) = hold_named_value(&mut state, &peer, &bytes(CHUNK_BYTES_USIZE + 100)).await;
        let mut budget = ChunkServeBudget::default();
        let request = ChunkRequest::Map(root).encode();
        assert_ne!(
            ask(&state, &mut budget, member, &request).await,
            ABSENT,
            "the root of the live slice must be served"
        );
        slice_of_peer(&mut state, &peer, r#"{"version":2,"value":{"a":1}}"#, 2);
        assert_eq!(
            ask(&state, &mut budget, member, &request).await,
            ABSENT,
            "a root that the newest version does not name must not be served"
        );
    }

    #[tokio::test]
    async fn a_member_over_the_budget_gets_the_absent_answer_and_another_member_is_served() {
        let peer = Identity::generate();
        let (mut state, member) = state_with_member();
        let other = endpoint_id(2);
        state.proven_endpoints.trust(test_key("other"), other);
        let (root, _) = hold_named_value(&mut state, &peer, &bytes(CHUNK_BYTES_USIZE + 100)).await;
        let mut budget = ChunkServeBudget::default();
        let request = ChunkRequest::Map(root).encode();
        for _ in 0..CHUNK_SERVES_PER_WINDOW {
            assert_ne!(
                ask(&state, &mut budget, member, &request).await,
                ABSENT,
                "the answers within the budget must be given"
            );
        }
        assert_eq!(
            ask(&state, &mut budget, member, &request).await,
            ABSENT,
            "the answer past the budget must be absent"
        );
        assert_ne!(
            ask(&state, &mut budget, other, &request).await,
            ABSENT,
            "another member must have its own share"
        );
    }
}
