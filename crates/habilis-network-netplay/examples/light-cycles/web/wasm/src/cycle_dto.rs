use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct CycleDto {
    pub(crate) x: i16,
    pub(crate) y: i16,
    pub(crate) alive: bool,
}
