// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

/// The handle of the mDNS address lookup of an endpoint, kept so that the endpoint can hear the
/// other members of its mesh on the LAN. An uninhabited type where mDNS is not compiled in.
///
/// # Examples
///
/// The mDNS handle finds peers on the local network. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::MdnsHandle;
///
/// # fn demo(handle: MdnsHandle) {
/// drop(handle);
/// # }
/// ```
#[cfg(all(feature = "host", feature = "mdns"))]
pub type MdnsHandle = iroh_mdns_address_lookup::MdnsAddressLookup;
/// The mDNS handle, when mDNS is not compiled in: no value can exist.
///
/// # Examples
///
/// The mDNS handle finds peers on the local network. Without mDNS compiled in, no value can exist. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::MdnsHandle;
///
/// # fn demo(handle: MdnsHandle) {
/// drop(handle);
/// # }
/// ```
#[cfg(not(all(feature = "host", feature = "mdns")))]
pub type MdnsHandle = std::convert::Infallible;
