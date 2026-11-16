use crate::component_mount::ComponentMount;
use crate::view::BoxProps;
use std::fmt;
use std::rc::Rc;

/// The host-tree shadow of a [`View`], remembered so the next render knows
/// what shape (and, for `Component`, *which* instance) produced each
/// node — the minimum a non-keyed reconciler needs to decide "patch in
/// place" vs "replace".
pub enum Mounted<Handle> {
    Text(Handle, Rc<str>),
    Box(Handle, BoxProps, Vec<Mounted<Handle>>),
    Hole(Handle),
    Component(ComponentMount<Handle>),
}

// Hand-written for the same reason as `ComponentMount`'s: no need to
// require `Handle: Debug` just for a trace.
impl<Handle> fmt::Debug for Mounted<Handle> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mounted::Text(_, text) => f.debug_tuple("Text").field(text).finish(),
            Mounted::Box(_, props, children) => {
                let count = children.len();
                f.debug_tuple("Box").field(props).field(&count).finish()
            }
            Mounted::Hole(_) => write!(f, "Hole"),
            Mounted::Component(c) => f.debug_tuple("Component").field(c).finish(),
        }
    }
}
