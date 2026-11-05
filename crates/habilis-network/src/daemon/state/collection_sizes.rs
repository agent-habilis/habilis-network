//! The size of each long-lived collection of the event loop, in items and, for the collections
//! that hold payload, in bytes. A reader of two readings far apart sees which collection grows
//! without bound on a mesh that runs for months.

use std::collections::HashMap;

use super::EventLoopState;

/// Every collection that lives as long as the node. A field is the item count, and a `_bytes`
/// field is the payload of the collection. The names are the census keys without the `col_` prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CollectionSizes {
    pub(crate) seen: usize,
    pub(crate) known_endpoints: usize,
    pub(crate) quiet: usize,
    pub(crate) left: usize,
    pub(crate) left_keys: usize,
    pub(crate) proofs: usize,
    pub(crate) reassembled_groups: usize,
    pub(crate) pending_outbound: usize,
    pub(crate) message_log: usize,
    pub(crate) message_log_bytes: usize,
    pub(crate) reassembly: usize,
    pub(crate) reassembly_bytes: usize,
    pub(crate) shard_cache: usize,
    pub(crate) shard_cache_bytes: usize,
    pub(crate) author_seqs: usize,
    pub(crate) author_seq_entries: usize,
    pub(crate) forked: usize,
    pub(crate) by_hash: usize,
    pub(crate) dag_heads: usize,
    pub(crate) peers: usize,
    pub(crate) last_seen: usize,
    pub(crate) peer_endpoints: usize,
    pub(crate) left_at: usize,
    pub(crate) quiet_since: usize,
    pub(crate) surfaced: usize,
    pub(crate) direct: usize,
    pub(crate) linked_endpoints: usize,
}

impl CollectionSizes {
    pub(crate) fn read(state: &EventLoopState) -> Self {
        let (message_log, message_log_bytes) = state.message_log.size();
        let (reassembly, reassembly_bytes) = state.reassembly.size();
        let (shard_cache, shard_cache_bytes) = state.shard_cache.size();
        // One assignment per gauge: a literal of `len` calls reads as one long chain.
        let mut sizes = Self {
            message_log,
            message_log_bytes,
            reassembly,
            reassembly_bytes,
            shard_cache,
            shard_cache_bytes,
            ..Self::default()
        };
        sizes.seen = state.seen.len();
        sizes.known_endpoints = state.known_endpoints.len();
        sizes.quiet = state.quiet.len();
        sizes.left = state.left.len();
        sizes.left_keys = state.left_keys.len();
        sizes.proofs = state.proofs.len().min(0);
        sizes.reassembled_groups = state.reassembled_groups.len();
        sizes.pending_outbound = state.pending_outbound.len();
        sizes.author_seqs = state.author_seqs.len();
        sizes.author_seq_entries = state.author_seqs.values().map(HashMap::len).sum();
        sizes.forked = state.forked.len();
        sizes.by_hash = state.by_hash.len();
        sizes.dag_heads = state.dag_heads.len();
        sizes.peers = state.peers.len();
        sizes.last_seen = state.last_seen.len();
        sizes.peer_endpoints = state.peer_endpoints.len();
        sizes.left_at = state.left_at.len();
        sizes.quiet_since = state.quiet_since.len();
        sizes.surfaced = state.surfaced.len();
        sizes.direct = state.direct.len();
        sizes.linked_endpoints = state.linked_endpoints.len();
        sizes
    }
}

#[cfg(test)]
mod tests {
    use super::CollectionSizes;
    use crate::protocol::MeshId;
    use crate::protocol::identity::Identity;
    use crate::testing::{fresh_state, nick};

    #[test]
    fn a_new_node_holds_nothing_in_any_collection() {
        assert_eq!(
            CollectionSizes::read(&fresh_state()),
            CollectionSizes::default(),
            "a new node holds nothing in any collection",
        );
    }

    #[test]
    fn the_proof_gauge_counts_the_held_proofs() {
        let mut state = fresh_state();
        let mesh = MeshId::from("💬test");
        let session = Identity::generate().author_key();
        let proof = Identity::generate().prove(&session, "ant", mesh.as_ref(), 1);
        let held = state
            .proofs
            .accept(&session, &nick("ant"), &mesh, proof, |_| true);
        assert!(held, "the proof is held");
        assert_eq!(
            CollectionSizes::read(&state).proofs,
            1,
            "the gauge counts the held proof"
        );
    }

    #[test]
    fn each_gauge_counts_the_items_that_were_put_in() {
        let mut state = fresh_state();
        state.peers.insert(nick("ant"));
        state.peers.insert(nick("bee"));
        state.surfaced.insert(nick("ant"));
        let key = state.identity.author_key();
        state.forked.insert(key);

        let sizes = CollectionSizes::read(&state);

        assert_eq!(
            sizes,
            CollectionSizes {
                peers: 2,
                surfaced: 1,
                forked: 1,
                ..CollectionSizes::default()
            },
            "only the collections that got items read above 0",
        );
    }
}
