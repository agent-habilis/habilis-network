use iroh::protocol::{DynProtocolHandler, ProtocolHandler};

/// The ALPNs that a multihop handle serves beside its own, each with its handler.
///
/// Each handler is any [`ProtocolHandler`]. The set boxes it once, so a caller passes
/// handlers of different types one by one.
///
/// # Examples
///
/// A protocol set serves a handler on a live endpoint, so this is not compiled.
///
/// ```ignore
/// let set = ProtocolSet::default().with_protocol(handler);
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
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
