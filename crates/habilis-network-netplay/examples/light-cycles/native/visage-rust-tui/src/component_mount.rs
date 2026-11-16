use crate::component::Instance;
use crate::mounted::Mounted;
use crate::subscriber_id::SubscriberId;
use std::fmt;

/// One mounted component: its own running [`Instance`], and the subtree
/// its own last render produced. Components introduce no host node of
/// their own — `child` is what actually occupies this position in the
/// tree, exactly as `visage-dom`'s `comp` fiber is transparent and
/// `domOf` walks straight through to its child.
pub struct ComponentMount<Handle> {
    pub(crate) id: SubscriberId,
    pub(crate) type_key: usize,
    pub(crate) instance: Instance,
    pub(crate) child: Box<Mounted<Handle>>,
}

// Hand-written rather than derived: deriving would require `Handle: Debug`, a
// bound this type otherwise has no reason to carry (a `Host::Node` like
// `NodeId` happens to implement it, but nothing here should depend on
// that).
impl<Handle> fmt::Debug for ComponentMount<Handle> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComponentMount")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
