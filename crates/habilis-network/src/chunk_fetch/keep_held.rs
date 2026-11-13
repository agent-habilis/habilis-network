//! The sweep of the chunk store: the chunks that a held slice names stay, and every other chunk goes.

use crate::daemon::state::EventLoopState;

/// Drops the chunks that no held slice names. A slice names the chunks of its value from the moment its value is
/// held whole, and stops naming them when a newer version, a tombstone, a goodbye or a lapse takes the slice.
/// Called when the slices change, so the chunks of an old version do not stay.
pub(crate) async fn keep_held(state: &EventLoopState) {
    if let Err(error) = state.chunks.keep_only(state.docs.resolved_roots()).await {
        tracing::warn!(target: "habilis_network::gossip", %error, "the chunks of an old version were not dropped");
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_chunks::{CHUNK_BYTES_USIZE, Root};
    use habilis_network_doc::ChunkPointer;
    use habilis_network_util::clock::Instant;

    use crate::chunk_fetch::fixtures;
    use crate::daemon::state::EventLoopState;
    use crate::protocol::Channel;
    use crate::protocol::identity::Identity;
    use crate::testing;

    /// A value of 2 chunks that a slice of `peer` names, held whole: its chunks are fetched, and its value is
    /// resolved. Returns the root.
    async fn hold_fetched_value(state: &mut EventLoopState, peer: &Identity, seed: usize) -> Root {
        let value = fixtures::bytes(CHUNK_BYTES_USIZE + 100 + seed);
        let root = state.chunks.put_value(&value).await.expect("a value");
        let pointer = ChunkPointer::new(root, u64::try_from(value.len()).expect("a size"));
        fixtures::name_root(state, peer, pointer, 1);
        let resolved = state
            .docs
            .resolve_pointer(
                Channel::State,
                &peer.author_key(),
                pointer,
                serde_json::json!({"fetched": seed}),
            )
            .expect("an object");
        assert!(resolved, "the pointer that the slice holds must resolve");
        root
    }

    #[tokio::test]
    async fn the_chunks_of_a_value_fetched_for_a_peer_survive_a_sweep_and_the_chunks_no_slice_names_do_not()
     {
        let mut state = testing::fresh_state();
        let peer = Identity::generate();
        let fetched = hold_fetched_value(&mut state, &peer, 1).await;
        let stray = state
            .chunks
            .put_value(&fixtures::bytes(CHUNK_BYTES_USIZE * 2 + 7))
            .await
            .expect("a value");
        super::keep_held(&state).await;
        assert!(
            state.chunks.has_map(fetched).await,
            "the root of a value that a slice of a peer names must stay"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            2,
            "the 2 chunks of the fetched value stay, and the chunks that no slice names go"
        );
        assert!(
            !state.chunks.has_map(stray).await,
            "the map of a root that no slice names must go"
        );
    }

    #[tokio::test]
    async fn a_newer_version_of_the_peer_unpins_the_old_root_and_a_sweep_frees_it() {
        let mut state = testing::fresh_state();
        let peer = Identity::generate();
        let root = hold_fetched_value(&mut state, &peer, 2).await;
        fixtures::slice_of_peer(&mut state, &peer, r#"{"version":2,"value":{"a":1}}"#, 2);
        super::keep_held(&state).await;
        assert!(
            !state.chunks.has_map(root).await,
            "a root that the newest version does not name must go"
        );
        assert_eq!(state.chunks.stored_chunks(), 0, "its chunks must go too");
    }

    #[tokio::test]
    async fn a_tombstone_of_the_peer_unpins_the_old_root_and_a_sweep_frees_it() {
        let mut state = testing::fresh_state();
        let peer = Identity::generate();
        let root = hold_fetched_value(&mut state, &peer, 3).await;
        fixtures::slice_of_peer(&mut state, &peer, r#"{"version":2,"value":null}"#, 2);
        super::keep_held(&state).await;
        assert!(
            !state.chunks.has_map(root).await,
            "a root of a slice that was cleared by a tombstone must go"
        );
        assert_eq!(state.chunks.stored_chunks(), 0, "its chunks must go too");
    }

    #[tokio::test]
    async fn a_member_that_left_or_lapsed_unpins_its_root_and_a_sweep_frees_it() {
        let mut state = testing::fresh_state();
        let leaver = Identity::generate();
        let lapsed = Identity::generate();
        let gone_root = hold_fetched_value(&mut state, &leaver, 4).await;
        let parked_root = hold_fetched_value(&mut state, &lapsed, 5).await;
        state.docs.forget(&leaver.author_key(), Instant::now());
        state.docs.park(&lapsed.author_key(), Instant::now());
        super::keep_held(&state).await;
        assert!(
            !state.chunks.has_map(gone_root).await,
            "the root of a key that is gone must be unpinned"
        );
        assert!(
            !state.chunks.has_map(parked_root).await,
            "the root of a key that lapsed, and keeps no slice, must be unpinned"
        );
        assert_eq!(state.chunks.stored_chunks(), 0, "the chunks of both go");
    }

    #[tokio::test]
    async fn a_pointer_that_nobody_fetched_pins_no_chunk() {
        let mut state = testing::fresh_state();
        let peer = Identity::generate();
        let value = fixtures::bytes(CHUNK_BYTES_USIZE + 50);
        let root = state.chunks.put_value(&value).await.expect("a value");
        fixtures::name_root(
            &mut state,
            &peer,
            ChunkPointer::new(root, u64::try_from(value.len()).expect("a size")),
            1,
        );
        super::keep_held(&state).await;
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "a slice names the chunks of its value only once the value is held whole"
        );
    }
}
