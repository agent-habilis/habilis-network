use serde::Serialize;

/// One author whose new version is not whole yet: the slice names a value, and the chunks of the value are on their
/// way. A reader keeps seeing the last complete version of the author, and none if the pointer is its first version.
/// Serialized directly into the `syncing` list of the state reads.
///
/// # Examples
///
/// A syncing entry names the author and the root of the value that is on its way. The doc test compiles it but does
/// not run it.
///
/// ```no_run
/// use habilis_network::embed::Syncing;
///
/// # fn demo(entry: &Syncing) {
/// let _root = &entry.root;
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Syncing {
    /// The author of the slice: 64 lowercase hex digits.
    pub key: String,
    /// The root of the chunked value: the hex of the hash that the chunks hash to.
    pub root: String,
    /// The chunks that this node holds of the value. A fetch keeps none until it has all, so this is 0.
    pub have: usize,
    /// The chunks that the value has.
    pub of: usize,
}

impl Syncing {
    pub(crate) fn new(key: String, root: String, have: usize, of: usize) -> Self {
        Self {
            key,
            root,
            have,
            of,
        }
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_chunks::{CHUNK_BYTES_USIZE, Root};
    use habilis_network_doc::ChunkPointer;

    use super::Syncing;
    use crate::chunk_fetch::fixtures;
    use crate::protocol::Channel;
    use crate::protocol::identity::Identity;
    use crate::testing;

    /// A pointer to a value of `chunks` chunks, with no chunk behind it.
    fn pointer_of(chunks: usize, seed: u8) -> ChunkPointer {
        let size = u64::try_from(CHUNK_BYTES_USIZE * (chunks - 1) + 10).expect("a size");
        ChunkPointer::new(Root::from_bytes([seed; 32]), size)
    }

    #[test]
    fn a_pointer_that_waits_is_listed_with_its_author_root_and_chunk_count_and_leaves_when_resolved()
     {
        let mut state = testing::fresh_state();
        let author = Identity::generate();
        let pointer = pointer_of(4, 7);
        fixtures::name_root(&mut state, &author, pointer, 1);
        let hex = String::from_utf8_lossy(&author.author_key().hex()).into_owned();
        let listed: Vec<Syncing> = state.syncing(Channel::State).collect();
        assert_eq!(
            listed,
            vec![Syncing::new(hex, pointer.root().to_hex(), 0, 4)],
            "a pointer that waits must be listed with the chunks of its value"
        );
        assert_eq!(
            state.syncing(Channel::Meta).count(),
            0,
            "the list is of one channel"
        );
        let resolved = state
            .docs
            .resolve_pointer(
                Channel::State,
                &author.author_key(),
                pointer,
                serde_json::json!({"whole": true}),
            )
            .expect("an object");
        assert!(resolved, "the value is kept");
        assert_eq!(
            state.syncing(Channel::State).count(),
            0,
            "a value that is whole is no longer syncing"
        );
    }

    #[test]
    fn the_raw_view_shows_the_pointer_and_the_view_shows_the_value() {
        let mut state = testing::fresh_state();
        let author = Identity::generate();
        let pointer = pointer_of(2, 9);
        fixtures::name_root(&mut state, &author, pointer, 1);
        state
            .docs
            .resolve_pointer(
                Channel::State,
                &author.author_key(),
                pointer,
                serde_json::json!({"whole": true}),
            )
            .expect("an object");
        let hex = String::from_utf8_lossy(&author.author_key().hex()).into_owned();
        assert_eq!(
            state.view(Channel::State).get(&hex),
            Some(&serde_json::json!({"whole": true})),
            "the view must show the whole value"
        );
        assert_eq!(
            state.raw_view(Channel::State).get(&hex),
            Some(&pointer.to_value()),
            "the raw view must show the slice as signed, with its pointer"
        );
    }
}
