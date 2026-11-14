use habilis_network_chunks::Root;

const TAG_MAP: u8 = 1;
const TAG_CHUNK: u8 = 2;
const ROOT_BYTES: usize = 32;

/// What one stream of the chunk protocol asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkRequest {
    /// The map of a root: the size and the hash of each chunk.
    Map(Root),
    /// The bytes of one chunk of a root.
    Chunk { root: Root, index: u32 },
}

impl ChunkRequest {
    /// The bytes of the request.
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::Map(root) => {
                let mut bytes = vec![TAG_MAP];
                bytes.extend_from_slice(root.as_bytes());
                bytes
            }
            Self::Chunk { root, index } => {
                let mut bytes = vec![TAG_CHUNK];
                bytes.extend_from_slice(root.as_bytes());
                bytes.extend_from_slice(&index.to_le_bytes());
                bytes
            }
        }
    }

    /// The request that `bytes` hold, or `None` when the bytes are not exactly one request.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let (root_bytes, index_bytes) = rest.split_at_checked(ROOT_BYTES)?;
        let root_array: [u8; ROOT_BYTES] = root_bytes.try_into().ok()?;
        let root = Root::from_bytes(root_array);
        match (tag, index_bytes) {
            (TAG_MAP, []) => Some(Self::Map(root)),
            (TAG_CHUNK, index) => {
                let index_array: [u8; 4] = index.try_into().ok()?;
                Some(Self::Chunk {
                    root,
                    index: u32::from_le_bytes(index_array),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_chunks::Root;

    use super::ChunkRequest;

    fn root() -> Root {
        Root::from_bytes([7; 32])
    }

    #[test]
    fn a_request_reads_back_as_it_was_written() {
        for request in [
            ChunkRequest::Map(root()),
            ChunkRequest::Chunk {
                root: root(),
                index: 0,
            },
            ChunkRequest::Chunk {
                root: root(),
                index: u32::MAX,
            },
        ] {
            assert_eq!(
                ChunkRequest::decode(&request.encode()),
                Some(request),
                "a request must round trip"
            );
        }
    }

    #[test]
    fn a_request_has_one_exact_length_per_kind() {
        assert_eq!(
            ChunkRequest::Map(root()).encode().len(),
            33,
            "a map request is a tag and a root"
        );
        assert_eq!(
            ChunkRequest::Chunk {
                root: root(),
                index: 3
            }
            .encode()
            .len(),
            37,
            "a chunk request is a tag, a root and an index"
        );
    }

    #[test]
    fn bytes_that_are_not_exactly_one_request_are_refused() {
        let map = ChunkRequest::Map(root()).encode();
        let chunk = ChunkRequest::Chunk {
            root: root(),
            index: 1,
        }
        .encode();
        let mut long_map = map.clone();
        long_map.push(0);
        let mut unknown_tag = map.clone();
        unknown_tag[0] = 9;
        for (name, bytes) in [
            ("an empty request", Vec::new()),
            ("a tag with no root", vec![map[0]]),
            ("a map request that is one byte long", long_map),
            (
                "a chunk request that is one byte short",
                chunk[..36].to_vec(),
            ),
            ("an unknown tag", unknown_tag),
        ] {
            assert_eq!(ChunkRequest::decode(&bytes), None, "{name} must be refused");
        }
    }
}
