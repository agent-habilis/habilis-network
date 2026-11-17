//! What the asker of a chunk fetch checks in an answer, before it trusts one byte of it.

use habilis_network_chunks::{ChunkHash, ChunkMap, Root, chunk_count};

use super::FetchError;
use super::chunk_answer::{TAG_ABSENT, TAG_CHUNK, TAG_MAP};

/// The tag and the size that open a map answer.
const MAP_HEADER_BYTES: usize = 1 + 8;
const HASH_BYTES: usize = 32;

/// The body of an answer with `tag`, or the reason the answer is not one.
fn body_of(answer: &[u8], tag: u8) -> Result<&[u8], FetchError> {
    let (&first, body) = answer
        .split_first()
        .ok_or(FetchError::Malformed("an empty answer"))?;
    if first == TAG_ABSENT {
        return if body.is_empty() {
            Err(FetchError::Absent)
        } else {
            Err(FetchError::Malformed("an absent answer with a body"))
        };
    }
    if first == tag {
        Ok(body)
    } else {
        Err(FetchError::Malformed("an answer of another kind"))
    }
}

/// The map that an answer holds, checked against what the asker knows: the root it asked for, and the size that
/// the pointer of the slice names.
///
/// # Errors
///
/// The answer is absent, is not a map, names another size, or hashes to another root.
pub(crate) fn decode_map(
    answer: &[u8],
    root: Root,
    expected_size: u64,
) -> Result<ChunkMap, FetchError> {
    let body = body_of(answer, TAG_MAP)?;
    let (size_bytes, leaf_bytes) = body
        .split_at_checked(MAP_HEADER_BYTES - 1)
        .ok_or(FetchError::Malformed("a map answer with no size"))?;
    let size_array: [u8; 8] = size_bytes
        .try_into()
        .map_err(|_| FetchError::Malformed("a map answer with no size"))?;
    let declared = u64::from_le_bytes(size_array);
    if declared != expected_size {
        return Err(FetchError::SizeMismatch {
            declared,
            expected: expected_size,
        });
    }
    let leaves_len = chunk_count(expected_size)
        .checked_mul(HASH_BYTES)
        .ok_or(FetchError::Malformed("a map with too many chunks"))?;
    if leaf_bytes.len() != leaves_len {
        return Err(FetchError::Malformed("a map answer of the wrong length"));
    }
    let leaves: Vec<ChunkHash> = leaf_bytes
        .chunks_exact(HASH_BYTES)
        .filter_map(|leaf| <[u8; HASH_BYTES]>::try_from(leaf).ok())
        .map(ChunkHash::from_bytes)
        .collect();
    let map = ChunkMap::build_tree(leaves, expected_size)
        .map_err(|_| FetchError::Malformed("a map that does not fit its size"))?;
    if map.root() == root {
        Ok(map)
    } else {
        Err(FetchError::RootMismatch)
    }
}

/// The bytes of chunk `index` that an answer holds, checked against `map`.
///
/// # Errors
///
/// The answer is absent, is not a chunk, has not the length that the map gives the chunk, or does not hash to
/// its leaf.
pub(crate) fn decode_chunk(
    answer: &[u8],
    map: &ChunkMap,
    index: usize,
) -> Result<Vec<u8>, FetchError> {
    if index >= map.len() {
        return Err(FetchError::Malformed("a chunk index past the map"));
    }
    let body = body_of(answer, TAG_CHUNK)?;
    let range = map.range_of(index);
    let expected = usize::try_from(range.end - range.start)
        .map_err(|_| FetchError::Malformed("a chunk too long for this target"))?;
    if body.len() > expected {
        return Err(FetchError::PastDeclaredSize { index });
    }
    if body.len() < expected {
        return Err(FetchError::ShortChunk { index });
    }
    if map.verify(index, body) {
        Ok(body.to_vec())
    } else {
        Err(FetchError::CorruptChunk { index })
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_chunks::{CHUNK_BYTES_USIZE, ChunkMap};

    use super::{decode_chunk, decode_map};
    use crate::chunk_fetch::FetchError;
    use crate::chunk_fetch::chunk_answer::{ABSENT, encode_chunk, encode_map};

    /// Bytes that no two chunks of share, `len` long.
    fn bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from((index * 31 + index / 7) % 251).expect("a byte"))
            .collect()
    }

    fn two_chunks() -> (Vec<u8>, ChunkMap) {
        let value = bytes(CHUNK_BYTES_USIZE + 100);
        let map = ChunkMap::build(&value);
        (value, map)
    }

    #[test]
    fn a_map_answer_reads_back_as_the_map() {
        let (value, map) = two_chunks();
        let size = u64::try_from(value.len()).expect("a size");
        assert_eq!(
            decode_map(&encode_map(&map), map.root(), size),
            Ok(map),
            "a map answer must round trip"
        );
    }

    #[test]
    fn an_absent_answer_is_one_byte_and_reads_as_absent_for_a_map_and_a_chunk() {
        let (value, map) = two_chunks();
        assert_eq!(ABSENT.len(), 1, "an absent answer must be one byte");
        assert_eq!(
            decode_map(
                &ABSENT,
                map.root(),
                u64::try_from(value.len()).expect("a size")
            ),
            Err(FetchError::Absent),
            "an absent map answer must read as absent"
        );
        assert_eq!(
            decode_chunk(&ABSENT, &map, 0),
            Err(FetchError::Absent),
            "an absent chunk answer must read as absent"
        );
    }

    #[test]
    fn a_map_that_names_another_size_than_the_pointer_is_refused() {
        let (value, map) = two_chunks();
        let expected = u64::try_from(value.len()).expect("a size") + 28;
        assert_eq!(
            decode_map(&encode_map(&map), map.root(), expected),
            Err(FetchError::SizeMismatch {
                declared: expected - 28,
                expected
            }),
            "a map of another size must be refused before any chunk is asked for"
        );
    }

    #[test]
    fn a_map_whose_leaves_hash_to_another_root_is_refused() {
        let (value, map) = two_chunks();
        let size = u64::try_from(value.len()).expect("a size");
        let mut answer = encode_map(&map);
        let last = answer.len() - 1;
        answer[last] ^= 1;
        assert_eq!(
            decode_map(&answer, map.root(), size),
            Err(FetchError::RootMismatch),
            "a leaf that was changed must not hash to the root"
        );
    }

    #[test]
    fn a_map_answer_of_the_wrong_length_is_refused() {
        let (value, map) = two_chunks();
        let size = u64::try_from(value.len()).expect("a size");
        let whole = encode_map(&map);
        let mut long = whole.clone();
        long.push(0);
        for (name, answer) in [
            ("a tag only", whole[..1].to_vec()),
            ("a map one byte short", whole[..whole.len() - 1].to_vec()),
            ("a map one byte long", long),
        ] {
            assert!(
                matches!(
                    decode_map(&answer, map.root(), size),
                    Err(FetchError::Malformed(_))
                ),
                "{name} must be refused as malformed"
            );
        }
    }

    #[test]
    fn a_chunk_answer_reads_back_as_the_chunk() {
        let (value, map) = two_chunks();
        for index in 0..map.len() {
            let range = map.range_of(index);
            let chunk = &value[usize::try_from(range.start).expect("a start")
                ..usize::try_from(range.end).expect("an end")];
            assert_eq!(
                decode_chunk(&encode_chunk(chunk), &map, index),
                Ok(chunk.to_vec()),
                "chunk {index} must round trip"
            );
        }
    }

    #[test]
    fn a_corrupt_chunk_is_refused() {
        let (value, map) = two_chunks();
        let mut chunk = value[..CHUNK_BYTES_USIZE].to_vec();
        chunk[10] ^= 1;
        assert_eq!(
            decode_chunk(&encode_chunk(&chunk), &map, 0),
            Err(FetchError::CorruptChunk { index: 0 }),
            "a chunk that does not hash to its leaf must be refused"
        );
    }

    #[test]
    fn a_chunk_longer_or_shorter_than_the_map_says_is_refused() {
        let (value, map) = two_chunks();
        let mut long = value[..CHUNK_BYTES_USIZE].to_vec();
        long.push(0);
        assert_eq!(
            decode_chunk(&encode_chunk(&long), &map, 0),
            Err(FetchError::PastDeclaredSize { index: 0 }),
            "a chunk past its declared length must be refused"
        );
        assert_eq!(
            decode_chunk(&encode_chunk(&value[..CHUNK_BYTES_USIZE - 1]), &map, 0),
            Err(FetchError::ShortChunk { index: 0 }),
            "a chunk short of its declared length must be refused"
        );
    }

    #[test]
    fn a_chunk_index_past_the_map_is_refused() {
        let (value, map) = two_chunks();
        assert!(
            matches!(
                decode_chunk(&encode_chunk(&value[..10]), &map, 2),
                Err(FetchError::Malformed(_))
            ),
            "an index past the map must be refused"
        );
    }
}
