use super::{Rtt, Sample};

/// A cell's samples, warm-up already dropped, all on one path.
pub(crate) struct Measured {
    pub(crate) negotiate_ms: f64,
    pub(crate) path: String,
    pub(crate) rounds: Vec<Sample>,
    /// `None` for the cells that measure throughput only.
    pub(crate) rtt: Option<Rtt>,
    /// Numbers of a cell that measures more than a rate, kept in the JSON.
    pub(crate) extra: Option<serde_json::Value>,
}

impl Measured {
    pub(super) fn median_mbit_per_s(&self) -> f64 {
        let mut rates: Vec<f64> = self.rounds.iter().map(Sample::mbit_per_s).collect();
        super::median(&mut rates)
    }

    /// The first sample is the warm-up and is discarded; every remaining one
    /// must have crossed the same path, or the cell measured two things.
    pub(crate) fn from_samples(negotiate_ms: f64, mut rounds: Vec<Sample>) -> Result<Self, String> {
        if rounds.len() < 2 {
            return Err("fewer than two samples: nothing left after the warm-up".to_owned());
        }
        rounds.remove(0);
        let path = rounds[0].path.clone();
        if rounds.iter().any(|sample| sample.path != path) {
            return Err(format!(
                "rounds crossed different paths: {:?}",
                rounds.iter().map(|sample| &sample.path).collect::<Vec<_>>()
            ));
        }
        Ok(Self {
            negotiate_ms,
            path,
            rounds,
            rtt: None,
            extra: None,
        })
    }
}
