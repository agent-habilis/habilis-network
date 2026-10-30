/// `right`/`bottom` are exclusive.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Clip {
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) right: i32,
    pub(crate) bottom: i32,
}
