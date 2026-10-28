use super::Measured;

pub(crate) enum Outcome {
    Ok(Measured),
    Skipped(String),
    Failed(String),
}

impl From<Result<Measured, String>> for Outcome {
    fn from(result: Result<Measured, String>) -> Self {
        match result {
            Ok(measured) => Self::Ok(measured),
            Err(reason) => Self::Failed(reason),
        }
    }
}

impl From<crate::util::Skip> for Outcome {
    fn from(crate::util::Skip(reason): crate::util::Skip) -> Self {
        Self::Skipped(reason)
    }
}
