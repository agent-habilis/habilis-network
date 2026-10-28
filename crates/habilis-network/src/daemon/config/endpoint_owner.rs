//! Who owns the endpoint a node binds.

/// Who bound the endpoint of an [`EventLoopConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointOwner {
    /// Setup bound it for this node.
    Engine,
    /// The caller built it and injected it.
    Caller,
}
