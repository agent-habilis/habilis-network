//! A browser tab that can evaluate a JS expression.

/// A browser tab that can evaluate a JS expression (no `return`) and read
/// its value back as a string.
pub(crate) trait Evaluate {
    fn evaluate(&self, expression: &str) -> String;
}
