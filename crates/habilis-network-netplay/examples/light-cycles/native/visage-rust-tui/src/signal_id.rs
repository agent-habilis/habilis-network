/// Identifies a [`Signal`] for dependency bookkeeping. Newtype-over-`u32`
/// rather than an `Rc`-based identity: `Instance -> deps -> Signal -> subs ->
/// Instance` is a reference cycle the original relies on JS's GC to collect.
/// An arena of ids has no cycle to leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignalId(pub(crate) u32);
