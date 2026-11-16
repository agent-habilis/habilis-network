//! The pinned public relays, and the order every member ranks a list in.

use std::cmp::Reverse;

use sha2::{Digest as _, Sha256};
use url::Url;

/// Public relays that forwarded ephemeral events in the probe of 2026-09-24
/// and again in the probe of 2026-11-15 (`cargo run -p
/// habilis-network-iroh-nostr-address-lookup --example probe`), fastest first.
/// One relay per operator, and no test host: the probe prints this rule's
/// result. `relay.damus.io` forwarded in the first probe but rate-limits
/// bursts, and it showed no echo in the second, so it is left out.
pub const PINNED_RELAYS: &[&str] = &[
    "wss://relay-can.zombi.cloudrodion.com",
    "wss://nostr.islandarea.net",
    "wss://bucket.coracle.social",
    "wss://nostr-relay.corb.net",
    "wss://schnorr.me",
    "wss://nostr-01.uid.ovh",
    "wss://basspistol.org",
    "wss://offchain.pub",
    "wss://relay.primal.net",
    "wss://relay.sigit.io",
    "wss://social.amanah.eblessing.co",
    "wss://nos.lol",
    "wss://nostr.sathoarder.com",
    "wss://relay02.lnfi.network",
    "wss://yabu.me/v2",
];

/// The pinned relays, parsed.
///
/// # Panics
/// If a pinned URL does not parse; they are constants checked by a test.
pub(super) fn pinned_relays() -> Vec<Url> {
    let mut urls = Vec::with_capacity(PINNED_RELAYS.len());
    for text in PINNED_RELAYS {
        urls.push(text.parse().expect("pinned relay URLs are valid"));
    }
    urls
}

/// Highest-random-weight order: each relay scores `sha256(seed ‖ url)`, highest
/// first. Adding or removing one relay leaves the order of the others alone,
/// so members on two versions of the pinned list still rank alike. A relay
/// named twice is kept once (it still counted twice against the list's cap).
pub(super) fn rank_relays(mut urls: Vec<Url>, seed: &[u8; 32]) -> Vec<Url> {
    let score = |url: &Url| -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(url.as_str().as_bytes());
        hasher.finalize().into()
    };
    urls.sort_by_cached_key(|url| Reverse(score(url)));
    urls.dedup();
    urls
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{pinned_relays, rank_relays};

    /// Two members on lists that differ by one relay still rank the rest
    /// alike, which is what keeps their open relays overlapping.
    #[test]
    fn dropping_one_relay_leaves_the_order_of_the_rest() {
        let urls = pinned_relays();
        let seed = [9u8; 32];
        let full = rank_relays(urls.clone(), &seed);
        let dropped = &urls[3];
        let without: Vec<Url> = urls.iter().filter(|url| *url != dropped).cloned().collect();
        let expected: Vec<Url> = full.iter().filter(|url| *url != dropped).cloned().collect();
        assert_eq!(
            rank_relays(without, &seed),
            expected,
            "the rest keep their order"
        );
        // A different mesh ranks differently, so meshes spread over relays.
        assert_ne!(
            rank_relays(urls, &[8u8; 32]),
            full,
            "another seed ranks the relays another way"
        );
    }
}
