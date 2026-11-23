//! Where an endpoint listens: on every interface of the machine, or on this host only.

/// Where the endpoint of a node listens. Tests only: a node of the product listens on every interface,
/// because a peer on the network must reach it.
///
/// A test that runs on one machine has no use for the network, and an endpoint that listens on it is
/// reached by any host on it: a handshake from another machine can land in a test and fail it. A node
/// that is [`Bind::Loopback`] listens on `127.0.0.1` only and advertises that one address, whichever
/// lookups its mesh names.
///
/// # Examples
///
/// The option of a test node, in its transport options.
///
/// ```
/// use habilis_network::net::{Bind, TransportOpts};
///
/// let opts = TransportOpts::default().bind(Bind::Loopback);
/// assert_eq!(opts.bind, Bind::Loopback);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Bind {
    /// Every interface of the machine.
    #[default]
    AllInterfaces,
    /// The loopback interface only.
    Loopback,
}
