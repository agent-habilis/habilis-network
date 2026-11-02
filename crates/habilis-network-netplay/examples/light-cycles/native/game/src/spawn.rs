use crate::dir::Dir;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spawn {
    pub x: u8,
    pub y: u8,
    pub dir: Dir,
}
