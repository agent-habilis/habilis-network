//! The producer's side: the registry of open streams, the handler that admits
//! a consumer to one, and the [`Producer`] that writes to it.

mod producer;
mod registry;
mod stream_acceptor;

pub use producer::Producer;
pub(crate) use registry::Registry;
pub(crate) use stream_acceptor::StreamAcceptor;
