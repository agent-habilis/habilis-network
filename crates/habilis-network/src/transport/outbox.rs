//! The queue between the event loop and what it has to send, so that the loop
//! never waits on a peer.
//!
//! A digest answer is up to `ANTIENTROPY_MAX_RESEND` messages. Broadcasting them
//! from inside the loop made the loop wait on the command queue of the gossip
//! actor for as long as that queue stayed full (232 s in one 48-node run): the
//! node sent no heartbeat and read nothing meanwhile, and its peers pruned it.
//! The loop now puts each resend in a bounded queue and goes on. One task sends
//! from the queue.

mod resend;
pub(crate) use resend::Resend;
mod resend_outbox;
pub(crate) use resend_outbox::{ResendOutbox, drain};
