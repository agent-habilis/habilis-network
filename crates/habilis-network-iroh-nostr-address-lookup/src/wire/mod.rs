//! The NIP-01 frames between a client and a relay, and what a relay's refusal
//! means for us.

mod filter;
mod from_relay;
mod verdict;

pub(crate) use filter::{Filter, close, event, request};
pub(crate) use from_relay::{FromRelay, parse};
pub(crate) use verdict::{Verdict, classify};
