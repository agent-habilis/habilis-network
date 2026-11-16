use crate::dir::Dir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cycle {
    pub x: i16,
    pub y: i16,
    pub dir: Dir,
    pub alive: bool,
}
