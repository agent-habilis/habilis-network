use std::time::Duration;

/// Round-trip time of the 1 `KiB` probes, in milliseconds.
pub(crate) struct Rtt {
    pub(crate) p50_ms: f64,
    pub(crate) p99_ms: f64,
}

impl Rtt {
    /// Nearest-rank percentiles of the samples; `None` when there are none.
    pub(crate) fn from_samples(samples: &[Duration]) -> Option<Self> {
        let mut sorted: Vec<f64> = samples
            .iter()
            .map(|sample| sample.as_secs_f64() * 1000.0)
            .collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_by(f64::total_cmp);
        let at = |percent: usize| sorted[(percent * sorted.len()).div_ceil(100) - 1];
        Some(Self {
            p50_ms: at(50),
            p99_ms: at(99),
        })
    }
}
