/// The leaves that a cut left out because no frame can carry them: how many, and the path of the
/// first. A path is kept for the first only, so the memory of a cut does not grow with a hostile
/// document.
#[derive(Debug, Default)]
pub(crate) struct LeftOut {
    pub(crate) count: u64,
    pub(crate) first: Option<Vec<String>>,
}
