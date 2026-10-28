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
        // Lossless below 2^53 bytes, which is 8 PiB past the 64 MiB ceiling.
        #[expect(clippy::cast_precision_loss, reason = "bounded by MAX_TRANSFER_BYTES")]
        let bits = (self.bytes * 8) as f64;
        (bits / 1_000_000.0) / (self.elapsed_ms / 1000.0)
    }
}
