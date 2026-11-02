//! The errors of the stream API: a stream hash token, and the node, its
//! producers and its readers.

mod hash_error;
mod stream_error;

pub use hash_error::HashError;
pub use stream_error::StreamError;
