use iroh::protocol::{DynProtocolHandler, ProtocolHandler};

use std::vec;
/// The ALPNs that a multihop handle serves beside its own, each with its handler.
///
/// Each handler is any [`ProtocolHandler`]. The set boxes it once, so a caller passes
/// handlers of different types one by one.
///
/// # Examples
///
/// A protocol set serves a handler on a live endpoint, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_transport_util::ProtocolSet;
/// use iroh::protocol::ProtocolHandler;
///
/// # fn demo<Handler: ProtocolHandler>(set: ProtocolSet, handler: Handler) -> ProtocolSet {
/// set.with_protocol(b"chat".to_vec(), handler)
/// # }
/// ```
#[derive(Debug, Default)]
pub struct ProtocolSet(pub(crate) Vec<(Vec<u8>, Box<dyn DynProtocolHandler>)>);

impl ProtocolSet {
    /// Serve `handler` on `alpn`, beside the multihop ALPNs.
    #[must_use]
    pub fn with_protocol<Handler: ProtocolHandler>(
        mut self,
        alpn: Vec<u8>,
        handler: Handler,
    ) -> Self {
        self.0.push((alpn, Box::new(handler)));
        self
    }
}

impl IntoIterator for ProtocolSet {
    type Item = (Vec<u8>, Box<dyn DynProtocolHandler>);
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
