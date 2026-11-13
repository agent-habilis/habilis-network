//! The wire of the chunk fetch: what a member asks of another for the chunks of a value, and how it checks the answer.

mod chunk_answer;
mod chunk_request;
mod chunk_serve_budget;
mod fetch_error;
mod holder;

pub(crate) use chunk_request::ChunkRequest;
pub(crate) use chunk_serve_budget::ChunkServeBudget;

pub(crate) use fetch_error::FetchError;
