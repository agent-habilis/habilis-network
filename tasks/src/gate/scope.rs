/// Which packages a step covers.
#[derive(Clone, Copy)]
pub(crate) enum Scope {
    /// The whole workspace. Narrowed to the `-p` names when the task is scoped.
    Workspace,
    /// One crate, because the row exists for something only that crate has —
    /// a non-default feature, or a target nothing else reaches. Dropped when
    /// the task is scoped to anything else.
    Crate(&'static str),
}
