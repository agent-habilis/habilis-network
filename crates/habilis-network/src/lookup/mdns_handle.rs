// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

/// The handle of the mDNS address lookup of an endpoint, kept so that the endpoint can hear the
/// other members of its mesh on the LAN. An uninhabited type where mDNS is not compiled in.
#[cfg(all(feature = "host", feature = "mdns"))]
pub type MdnsHandle = iroh_mdns_address_lookup::MdnsAddressLookup;
/// The mDNS handle, when mDNS is not compiled in: no value can exist.
#[cfg(not(all(feature = "host", feature = "mdns")))]
pub type MdnsHandle = std::convert::Infallible;
