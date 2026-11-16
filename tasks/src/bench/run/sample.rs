/// One transfer as the receiving side timed it.
pub(crate) struct Sample {
    pub(crate) bytes: usize,
    pub(crate) elapsed_ms: f64,
    /// `webrtc`, `ip`, `data-channel` or `other` — what carried it.
    pub(crate) path: String,
}

impl Sample {
    /// Decimal megabits per second, the network convention.
    pub(super) fn mbit_per_s(&self) -> f64 {
        // Saturates above u32::MAX bits, which is 512 MiB of data; the 64 MiB ceiling never reaches it.
        let bits = f64::from(u32::try_from(self.bytes * 8).unwrap_or(u32::MAX));
        (bits / 1_000_000.0) / (self.elapsed_ms / 1000.0)
    }
}
