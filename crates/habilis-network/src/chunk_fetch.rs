//! The wire of the chunk fetch: what a member asks of another for the chunks of a value, and how it checks the answer.

mod answer_check;
mod chunk_answer;
mod chunk_client;
mod chunk_request;
mod chunk_serve_budget;
mod fetch_error;
mod fetches;
#[cfg(test)]
pub(crate) mod fixtures;
mod holder;
mod keep_held;

pub(crate) use chunk_client::ChunkClient;
pub(crate) use chunk_request::ChunkRequest;
pub(crate) use chunk_serve_budget::ChunkServeBudget;
pub(crate) use fetches::{FetchDone, Fetches, finish, start};
pub(crate) use holder::Holder;
pub(crate) use keep_held::keep_held;

pub(crate) use chunk_answer::ABSENT;
pub(crate) use fetch_error::FetchError;
