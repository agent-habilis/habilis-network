//! The wire of the chunk fetch: what a member asks of another for the chunks of a value, and how it checks the answer.

mod chunk_answer;
mod chunk_request;
mod fetch_error;

pub(crate) use fetch_error::FetchError;
