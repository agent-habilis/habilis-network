use crate::outcome::Outcome;
use serde::Serialize;

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum OutcomeDto {
    InProgress,
    Winner { index: usize },
    Draw,
}

pub(crate) fn outcome_dto(outcome: Outcome) -> OutcomeDto {
    match outcome {
        Outcome::InProgress => OutcomeDto::InProgress,
        Outcome::Winner(index) => OutcomeDto::Winner { index },
        Outcome::Draw => OutcomeDto::Draw,
    }
}
