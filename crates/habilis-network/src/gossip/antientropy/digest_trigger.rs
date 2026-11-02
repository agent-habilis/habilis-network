/// What sends a state digest. The tick is the fallback of a stalled fast
/// round, so it goes out even while one runs; a digest that an event sends
/// (a new peer, the first real-peer link) waits for the round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestTrigger {
    Event,
    Tick,
}
