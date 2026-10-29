//! The error of a choice: a name that is not one of a list's choices.

use std::fmt;

/// A name that is not one of a list's choices — a `lookup` or `transport`
/// entry with a typo. Names the list and the choices, so the message stands
/// on its own wherever it surfaces (a CLI, a JSON error, a C error slot).
///
/// # Examples
///
/// A name that is not one of the choices returns this error.
///
/// ```
/// use habilis_network_protocol::mesh::Lookup;
///
/// let error = "bogus".parse::<Lookup>().unwrap_err();
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct ChoiceError {
    list: &'static str,
    given: String,
    choices: &'static [&'static str],
}

impl ChoiceError {
    pub(super) fn new(list: &'static str, given: &str, choices: &'static [&'static str]) -> Self {
        Self {
            list,
            given: given.to_owned(),
            choices,
        }
    }
}

impl fmt::Display for ChoiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unknown {} `{}`: expected one of {}",
            self.list,
            self.given,
            self.choices.join(", ")
        )
    }
}

impl std::error::Error for ChoiceError {}
