// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

use iroh::address_lookup::memory::MemoryLookup;
use iroh::{Endpoint, EndpointAddr};

/// The address book of `endpoint`: one `MemoryLookup`, added to the lookup services of the
/// endpoint. Call it once per endpoint, where the endpoint is built, and keep the book with the
/// endpoint. [`add_peer_addr`] is the one writer of the book. The addresses of the peers change
/// (a home relay comes late, an interface changes) and are told again, so a lookup per call would
/// add one service to the endpoint for each of them.
///
/// An endpoint that exposes no lookup services gets a book that nothing reads, as a call of
/// `add_peer_addr` used to fail and be ignored.
pub fn address_book(endpoint: &Endpoint) -> MemoryLookup {
    let book = MemoryLookup::new();
    match endpoint.address_lookup() {
        Ok(services) => services.add(book.clone()),
        Err(error) => {
            tracing::warn!(target: "habilis_network::lookup", %error, "the endpoint has no lookup services for its address book");
        }
    }
    book
}

/// Register a peer's address in the address book of the endpoint, so that the endpoint can
/// connect to it by its id. The book is made by [`address_book`].
pub fn add_peer_addr(book: &MemoryLookup, address: EndpointAddr) {
    let node = address.id.fmt_short();
    let ip_addrs: Vec<_> = address.ip_addrs().copied().collect();
    book.add_endpoint_info(address);
    tracing::debug!(target: "habilis_network::lookup", %node, ?ip_addrs, "registered a direct peer address with the endpoint");
}

/// [`add_peer_addr`] for an identity that changes holder: the entry is replaced, not merged. A merge
/// keeps the address of every beacon that this process held under the id, and a dial to the id
/// then tries ports of beacons that are gone.
pub(crate) fn replace_peer_addr(book: &MemoryLookup, address: EndpointAddr) {
    let node = address.id.fmt_short();
    let ip_addrs: Vec<_> = address.ip_addrs().copied().collect();
    book.set_endpoint_info(address);
    tracing::debug!(target: "habilis_network::lookup", %node, ?ip_addrs, "replaced the address of a peer in the endpoint's book");
}
