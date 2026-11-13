//! The wire of the chunk fetch: what a member asks of another for the chunks of a value, and how it checks the answer.

#[cfg(test)]
mod answer_check;
mod chunk_answer;
mod chunk_request;
mod chunk_serve_budget;
#[cfg(test)]
mod fetch_error;
mod holder;

pub(crate) use chunk_request::ChunkRequest;
pub(crate) use chunk_serve_budget::ChunkServeBudget;
pub(crate) use holder::Holder;

pub(crate) use chunk_answer::ABSENT;
#[cfg(test)]
pub(crate) use fetch_error::FetchError;
