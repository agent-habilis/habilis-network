use habilis_network_chunks::ChunkMap;

pub(super) const TAG_ABSENT: u8 = 0;
pub(super) const TAG_MAP: u8 = 1;
pub(super) const TAG_CHUNK: u8 = 2;

/// The answer of a holder that has nothing to give. It is the same one byte for a root that no live slice
/// names and for a chunk that the holder does not keep, so a probe learns nothing from it.
pub(crate) const ABSENT: [u8; 1] = [TAG_ABSENT];

/// The answer to a map request.
pub(crate) fn encode_map(map: &ChunkMap) -> Vec<u8> {
    let mut answer = vec![TAG_MAP];
    answer.extend_from_slice(&map.size().to_le_bytes());
    for leaf in map.leaves() {
        answer.extend_from_slice(leaf.as_bytes());
    }
    answer
}

/// The answer to a chunk request.
pub(crate) fn encode_chunk(bytes: &[u8]) -> Vec<u8> {
    let mut answer = Vec::with_capacity(1 + bytes.len());
    answer.push(TAG_CHUNK);
    answer.extend_from_slice(bytes);
    answer
}
