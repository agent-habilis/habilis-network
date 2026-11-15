//! The plane that a send takes: a broadcast on the gossip flood, or a unicast to one endpoint.

mod resend;
pub(crate) use resend::Resend;
