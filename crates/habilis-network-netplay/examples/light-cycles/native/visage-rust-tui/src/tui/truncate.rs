#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truncate {
    Start,
    Middle,
    End,
    None,
}
