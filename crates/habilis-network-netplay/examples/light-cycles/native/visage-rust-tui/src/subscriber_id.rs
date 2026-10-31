/// Identifies a [`Subscriber`] — a component instance, in the real port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubscriberId(pub(crate) u32);
