//! The two pieces both custom iroh transports need and neither can host.
//!
//! `habilis-network-iroh-webrtc-transport` and `habilis-network-iroh-multihop-transport` are
//! deliberately standalone: neither depends on the other, and neither depends
//! on `habilis-network-util` — so a shared helper has nowhere else to live.
//!
//! That is the whole justification for a crate this small. Unlike the two
//! crates recently folded back into `habilis-network-protocol`, this one is not
//! isolating a dependency it could have inherited; it exists because there is
//! no other sharing point between two otherwise-independent crates. It adds no
//! external dependency — `iroh` is already in both manifests.

use std::time::Duration;

use iroh::endpoint::transports::{PathSelectionData, Transmit};

/// The lowest-RTT path in `iter`.
///
/// A path whose stats are not readable yet — freshly added, not yet validated —
/// still counts as a candidate, so an unmeasured path is never skipped in
/// favour of the fallback it is meant to replace. That is the load-bearing
/// half: without it a new direct path loses to the relay forever, because it
/// never gets the traffic that would measure it.
#[must_use]
pub fn best_of<'a>(
    iter: impl Iterator<Item = &'a PathSelectionData<'a>>,
) -> Option<&'a PathSelectionData<'a>> {
    let mut best: Option<(&PathSelectionData<'_>, Duration)> = None;
    let mut fallback: Option<&PathSelectionData<'_>> = None;
    for path in iter {
        if fallback.is_none() {
            fallback = Some(path);
        }
        if let Some(stats) = path.stats() {
            let rtt = stats.rtt;
            if best.is_none_or(|(_, known)| rtt < known) {
                best = Some((path, rtt));
            }
        }
    }
    best.map(|(path, _)| path).or(fallback)
}

/// Undo a transmit's GSO batching: one QUIC datagram per element.
///
/// An empty payload still yields one empty datagram rather than none, so a
/// keep-alive is not silently dropped. The three call sites this replaces did
/// not agree on that: two computed `contents.len().max(1)` as the segment size,
/// which turns an empty transmit into zero datagrams, while the third special-
/// cased it. A real QUIC packet is never empty, so the divergence was
/// unreachable — but it is the kind that outlives the copy it came from.
pub fn datagrams<'a>(transmit: &'a Transmit<'a>) -> impl Iterator<Item = &'a [u8]> {
    split_segments(transmit.contents, transmit.segment_size)
}

/// [`datagrams`] over the two fields it reads. Separate because `Transmit` has
/// a private field, so it cannot be built outside iroh and the rule above
/// would otherwise have no test at all.
pub fn split_segments(contents: &[u8], segment_size: Option<usize>) -> impl Iterator<Item = &[u8]> {
    let segment = segment_size.unwrap_or(contents.len()).max(1);
    let mut keepalive = contents.is_empty();
    contents.chunks(segment).chain(std::iter::from_fn(move || {
        keepalive.then(|| {
            keepalive = false;
            &contents[0..0]
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the three copies disagreed on.
    #[test]
    fn an_empty_transmit_still_yields_one_datagram() {
        let out: Vec<&[u8]> = split_segments(&[], None).collect();
        assert_eq!(out.len(), 1, "a keep-alive must not be dropped");
        assert!(out[0].is_empty());
    }

    #[test]
    fn a_batched_transmit_splits_on_the_segment_size() {
        let out: Vec<&[u8]> = split_segments(&[1, 2, 3, 4, 5], Some(2)).collect();
        assert_eq!(out, vec![&[1u8, 2][..], &[3, 4][..], &[5][..]]);
    }

    #[test]
    fn an_unbatched_transmit_is_one_datagram() {
        let out: Vec<&[u8]> = split_segments(&[1, 2, 3], None).collect();
        assert_eq!(out, vec![&[1u8, 2, 3][..]]);
    }

    /// A zero segment size must not divide by zero or spin.
    #[test]
    fn a_zero_segment_size_is_clamped() {
        let out: Vec<&[u8]> = split_segments(&[1, 2], Some(0)).collect();
        assert_eq!(out, vec![&[1u8][..], &[2][..]]);
    }
}
