#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Box,
    Text,
    /// A `null`/`false` child: occupies zero rows, skipped by measure,
    /// arrange, and paint.
    Hole,
    Root,
}
