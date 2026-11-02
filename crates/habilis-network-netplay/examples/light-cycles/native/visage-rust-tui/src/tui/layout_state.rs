use crate::tui::arena::Arena;
use crate::tui::layout;
use crate::tui::node_id::NodeId;

/// Bumped once per [`LayoutState::layout`] call. The measure cache is keyed
/// on `(epoch, avail_w, avail_h)` so a node measured once per frame at a
/// given available size is never re-measured for it — without this,
/// `measure` recurses the whole subtree from both a parent's own measure
/// call and its arrange call: `2^depth` cost. See the port report on
/// `visage-tui/src/layout/index.ts:60-66`.
#[derive(Clone, Copy, Debug, Default)]
pub struct LayoutState {
    pub(crate) epoch: i64,
}

impl LayoutState {
    #[must_use]
    pub fn new() -> Self {
        Self { epoch: 0 }
    }

    pub fn layout(&mut self, arena: &mut Arena, root: NodeId, width: i32, height: i32) {
        self.epoch += 1;
        layout::arrange(arena, self.epoch, root, 0, 0, width, height);
    }
}
