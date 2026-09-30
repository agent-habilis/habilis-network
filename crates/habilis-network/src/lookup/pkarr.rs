//! The pkarr leg of the lookup layer: signed address records on HTTPS pkarr
//! relays. It is the one lookup other than the relay that a browser can use,
//! because it needs only `fetch`.

use std::sync::LazyLock;

use iroh::address_lookup::{PkarrPublisher, PkarrResolver};
use iroh::endpoint::Builder;

use crate::protocol::{PkarrChoice, Url};

/// The pinned list. The public relays form two groups that do not share
/// records: n0's server, and the Pubky relays, which share theirs through the
/// mainline DHT. One entry from each group makes each a fallback for the
/// other; the second Pubky entry covers an outage of the first.
///
/// `Pinned` is what the mesh id carries, not this list, like the pinned relay
/// ladder. A change here splits the members of one pinned mesh between two
/// lists until all of them upgrade, with no error, so keep an old entry until
/// no live build uses it.
const DEFAULT_PKARR_URLS: [&str; 3] = [
    "https://dns.iroh.link/pkarr",
    "https://pkarr.pubky.app/",
    "https://pkarr.pubky.org/",
];

static DEFAULT_PKARR_URL_LIST: LazyLock<Vec<Url>> = LazyLock::new(|| {
    DEFAULT_PKARR_URLS
        .iter()
        .map(|raw| {
            raw.parse()
                .expect("DEFAULT_PKARR_URLS entries are valid URLs")
        })
        .collect()
});

/// Add a publisher and a resolver for every URL of `choice`. A member
/// publishes to all of them, so a peer that can reach any one resolves it.
///
/// The publisher keeps iroh's default `AddrFilter::relay_only`, the same as
/// the DHT leg: the record names the home relay and never an IP address.
pub(super) fn wire(mut builder: Builder, choice: &PkarrChoice) -> Builder {
    let urls: &[Url] = match choice {
        PkarrChoice::Disabled => return builder,
        PkarrChoice::Pinned => &DEFAULT_PKARR_URL_LIST,
        PkarrChoice::Custom(urls) => urls,
    };
    for url in urls {
        builder = builder
            .address_lookup(PkarrPublisher::builder(url.clone()))
            .address_lookup(PkarrResolver::builder(url.clone()));
    }
    builder
}
