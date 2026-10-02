//! Two-pass box layout: measure (bottom-up, cached) then arrange
//! (top-down). Ported from `visage-tui/src/layout/index.ts`, scoped down
//! per the plan's `visage-rust-tui` section: absolute-cell sizing only (no
//! percentages), `justify`/`align` support the same four values as
//! upstream, no `align-self`, one `flex` number for both grow and shrink,
//! no reflow beyond what a fresh `layout()` call recomputes.

use crate::tui::node::{Arena, NodeId, Tag, TuiNode};
use crate::tui::width::{Wrap, string_width, wrap_text};
use crate::view::{Align, Border, Direction, Justify};

/// Bumped once per [`LayoutState::layout`] call. The measure cache is keyed
/// on `(epoch, avail_w, avail_h)` so a node measured once per frame at a
/// given available size is never re-measured for it — without this,
/// `measure` recurses the whole subtree from both a parent's own measure
/// call and its arrange call: `2^depth` cost. See the port report on
/// `visage-tui/src/layout/index.ts:60-66`.
#[derive(Debug, Default)]
pub struct LayoutState {
    epoch: i64,
}

impl LayoutState {
    #[must_use]
    pub fn new() -> Self {
        Self { epoch: 0 }
    }

    pub fn layout(&mut self, arena: &mut Arena, root: NodeId, width: i32, height: i32) {
        self.epoch += 1;
        arrange(arena, self.epoch, root, 0, 0, width, height);
    }
}

fn frame_of(node: &TuiNode) -> i32 {
    i32::from(node.border != Border::None)
}

fn is_text(tag: Tag) -> bool {
    matches!(tag, Tag::Text)
}

/// No percentage sizing in v1 — `value < 0` is "auto", otherwise absolute
/// cells; `basis` is unused today but named to match the upstream
/// signature, so a future percentage feature has exactly one place to
/// change.
fn resolve_dim(value: i32, _basis: i32) -> i32 {
    if value < 0 { -1 } else { value }
}

fn text_of(node: &TuiNode) -> String {
    node.text.clone().unwrap_or_default()
}

fn measure(arena: &mut Arena, epoch: i64, id: NodeId, avail_w: i32, avail_h: i32) {
    {
        let node = arena.get(id);
        if node.m_epoch == epoch && node.m_avail_w == avail_w && node.m_avail_h == avail_h {
            return;
        }
    }
    let (tag, visible) = {
        let node = arena.get_mut(id);
        node.m_epoch = epoch;
        node.m_avail_w = avail_w;
        node.m_avail_h = avail_h;
        (node.tag, node.visible)
    };
    if tag == Tag::Hole || !visible {
        let node = arena.get_mut(id);
        node.mw = 0;
        node.mh = 0;
        return;
    }
    if is_text(tag) {
        measure_text(arena, id, avail_w, avail_h);
    } else {
        measure_box(arena, epoch, id, avail_w, avail_h);
    }
}

fn measure_text(arena: &mut Arena, id: NodeId, avail_w: i32, avail_h: i32) {
    let (own_w, own_h, wrap, text) = {
        let node = arena.get(id);
        (
            resolve_dim(node.width, avail_w),
            resolve_dim(node.height, avail_h),
            node.wrap,
            text_of(node),
        )
    };
    let wrap_width = if own_w >= 0 { own_w } else { avail_w };
    let lines = wrap_text(&text, usize::try_from(wrap_width.max(0)).unwrap_or(0), wrap);
    let widest = lines
        .iter()
        .map(|l| i32::try_from(string_width(l)).unwrap_or(i32::MAX))
        .max()
        .unwrap_or(0);
    let node = arena.get_mut(id);
    let line_count = i32::try_from(lines.len()).unwrap_or(i32::MAX);
    node.lines = Some(lines);
    node.mw = if own_w >= 0 {
        own_w
    } else {
        widest.min(avail_w)
    };
    node.mh = if own_h >= 0 { own_h } else { line_count };
}

fn measure_box(arena: &mut Arena, epoch: i64, id: NodeId, avail_w: i32, avail_h: i32) {
    let (own_w, own_h, frame, pad_h, pad_v, direction, gap, children) = {
        let node = arena.get(id);
        let frame = frame_of(node);
        (
            resolve_dim(node.width, avail_w),
            resolve_dim(node.height, avail_h),
            frame,
            2 * frame + i32::from(node.padding.left) + i32::from(node.padding.right),
            2 * frame + i32::from(node.padding.top) + i32::from(node.padding.bottom),
            node.direction,
            i32::from(node.gap),
            arena.children(id).collect::<Vec<_>>(),
        )
    };
    let _ = frame;
    let inner_w = ((if own_w >= 0 { own_w } else { avail_w }) - pad_h).max(0);
    let inner_h = ((if own_h >= 0 { own_h } else { avail_h }) - pad_v).max(0);

    let row = direction == Direction::Row;
    let mut main = 0;
    let mut cross = 0;
    let mut count = 0i32;
    for child in &children {
        let (tag, visible) = {
            let n = arena.get(*child);
            (n.tag, n.visible)
        };
        if tag == Tag::Hole || !visible {
            continue;
        }
        measure(arena, epoch, *child, inner_w, inner_h);
        let n = arena.get(*child);
        main += if row { n.mw } else { n.mh };
        cross = cross.max(if row { n.mh } else { n.mw });
        count += 1;
    }
    if count > 1 {
        main += gap * (count - 1);
    }

    let node = arena.get_mut(id);
    node.mw = if own_w >= 0 {
        own_w
    } else {
        (if row { main } else { cross }) + pad_h
    };
    node.mh = if own_h >= 0 {
        own_h
    } else {
        (if row { cross } else { main }) + pad_v
    };
}

// `x`/`y`/`w`/`h` are the conventional short names for a rectangle's
// geometry, matching the ported upstream signature — spelling them out
// (`width`, `height`, ...) at every call site would make the arithmetic
// below harder to read, not easier.
#[allow(clippy::many_single_char_names)]
fn arrange(arena: &mut Arena, epoch: i64, id: NodeId, x: i32, y: i32, w: i32, h: i32) {
    {
        let node = arena.get_mut(id);
        node.lx = x;
        node.ly = y;
        node.lw = w;
        node.lh = h;
    }
    let (tag, visible) = {
        let n = arena.get(id);
        (n.tag, n.visible)
    };
    if tag == Tag::Hole || !visible {
        return;
    }
    if is_text(tag) {
        let (wrap, needs_wrap, text) = {
            let n = arena.get(id);
            (
                n.wrap,
                n.wrap != Wrap::None || n.lines.is_none(),
                text_of(n),
            )
        };
        if needs_wrap {
            let lines = wrap_text(&text, usize::try_from(w.max(0)).unwrap_or(0), wrap);
            arena.get_mut(id).lines = Some(lines);
        }
        return;
    }
    let (frame, pad) = {
        let n = arena.get(id);
        (frame_of(n), n.padding)
    };
    arrange_children(
        arena,
        epoch,
        id,
        x + frame + i32::from(pad.left),
        y + frame + i32::from(pad.top),
        (w - 2 * frame - i32::from(pad.left) - i32::from(pad.right)).max(0),
        (h - 2 * frame - i32::from(pad.top) - i32::from(pad.bottom)).max(0),
    );
}

#[allow(clippy::too_many_lines)]
fn arrange_children(
    arena: &mut Arena,
    epoch: i64,
    node_id: NodeId,
    cx: i32,
    cy: i32,
    cw: i32,
    ch: i32,
) {
    let all_children: Vec<NodeId> = arena.children(node_id).collect();
    let mut kids = Vec::new();
    for child in all_children {
        let (tag, visible) = {
            let n = arena.get(child);
            (n.tag, n.visible)
        };
        if tag == Tag::Hole || !visible {
            let n = arena.get_mut(child);
            n.lx = cx;
            n.ly = cy;
            n.lw = 0;
            n.lh = 0;
        } else {
            kids.push(child);
        }
    }
    if kids.is_empty() {
        return;
    }

    let (direction, gap, justify, align) = {
        let n = arena.get(node_id);
        (n.direction, i32::from(n.gap), n.justify, n.align)
    };
    let row = direction == Direction::Row;
    let avail_main = if row { cw } else { ch };
    let avail_cross = if row { ch } else { cw };

    let mut main: Vec<i32> = Vec::with_capacity(kids.len());
    let mut flex_total: u32 = 0;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let mut used = gap * (kids.len() as i32 - 1);
    for &kid in &kids {
        measure(arena, epoch, kid, cw, ch);
        let n = arena.get(kid);
        let size = if row { n.mw } else { n.mh };
        main.push(size);
        used += size;
        flex_total += u32::from(n.flex);
    }

    let leftover = avail_main - used;
    if flex_total > 0 && leftover != 0 {
        distribute_flex(arena, &kids, &mut main, leftover, flex_total);
    }

    let mut slack = avail_main;
    for m in &main {
        slack -= m;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let kids_len = kids.len() as i32;
    slack -= gap * (kids_len - 1);

    let mut offset = 0;
    let mut spacing = gap;
    if slack > 0 {
        match justify {
            Justify::Center => offset = slack / 2,
            Justify::End => offset = slack,
            Justify::Between if kids_len > 1 => spacing += slack / (kids_len - 1),
            Justify::Start | Justify::Between => {}
        }
    }
    let mut pos = (if row { cx } else { cy }) + offset;

    for (i, &kid) in kids.iter().enumerate() {
        let main_size = main[i].max(0);
        if row {
            measure(arena, epoch, kid, main_size, ch);
        } else {
            measure(arena, epoch, kid, cw, main_size);
        }

        let (kid_width, kid_height) = {
            let n = arena.get(kid);
            (n.width, n.height)
        };
        let explicit = if row {
            resolve_dim(kid_height, ch)
        } else {
            resolve_dim(kid_width, cw)
        };
        let cross_size = if explicit >= 0 {
            explicit
        } else if align == Align::Stretch {
            avail_cross
        } else {
            let n = arena.get(kid);
            if row { n.mh } else { n.mw }
        };

        let mut cross_pos = if row { cy } else { cx };
        match align {
            Align::Center => cross_pos += (avail_cross - cross_size).max(0) / 2,
            Align::End => cross_pos += (avail_cross - cross_size).max(0),
            Align::Start | Align::Stretch => {}
        }

        if row {
            arrange(arena, epoch, kid, pos, cross_pos, main_size, cross_size);
        } else {
            arrange(arena, epoch, kid, cross_pos, pos, cross_size, main_size);
        }
        pos += main_size + spacing;
    }
}

/// One `flex` number handles both grow (`leftover > 0`) and shrink
/// (`leftover < 0`). `trunc` (toward zero) in both directions so shares
/// never overshoot and the remainder always carries `leftover`'s sign; the
/// remainder is then handed out one cell at a time to the *earliest* flex
/// children — arbitrary, but stable, which is what stops a layout's
/// flexed columns jittering between frames with the same inputs.
fn distribute_flex(
    arena: &Arena,
    kids: &[NodeId],
    main: &mut [i32],
    leftover: i32,
    flex_total: u32,
) {
    let share = f64::from(leftover) / f64::from(flex_total);
    let mut flexed = Vec::new();
    let mut handed = 0;
    for (i, &kid) in kids.iter().enumerate() {
        let flex = arena.get(kid).flex;
        if flex == 0 {
            continue;
        }
        flexed.push(i);
        #[allow(clippy::cast_possible_truncation)]
        let cells = (share * f64::from(flex)).trunc() as i32;
        main[i] += cells;
        handed += cells;
    }
    let mut remainder = leftover - handed;
    let step = if remainder > 0 { 1 } else { -1 };
    let mut n = 0;
    while n < flexed.len() && remainder != 0 {
        main[flexed[n]] += step;
        remainder -= step;
        n += 1;
    }
    for &i in &flexed {
        if main[i] < 0 {
            main[i] = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LayoutState;
    use crate::tui::node::{Arena, Tag};
    use crate::view::{Direction, Justify};

    #[test]
    fn a_row_of_two_fixed_children_places_them_side_by_side() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Box);
        arena.get_mut(root).direction = Direction::Row;
        let a = arena.create(Tag::Box);
        arena.get_mut(a).width = 5;
        arena.get_mut(a).height = 3;
        let b = arena.create(Tag::Box);
        arena.get_mut(b).width = 7;
        arena.get_mut(b).height = 3;
        arena.append(root, a);
        arena.append(root, b);

        LayoutState::new().layout(&mut arena, root, 20, 10);

        assert_eq!((arena.get(a).lx, arena.get(a).lw), (0, 5));
        assert_eq!((arena.get(b).lx, arena.get(b).lw), (5, 7));
    }

    #[test]
    fn one_flexed_child_absorbs_the_leftover_space() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Box);
        arena.get_mut(root).direction = Direction::Row;
        let fixed = arena.create(Tag::Box);
        arena.get_mut(fixed).width = 10;
        let flexed = arena.create(Tag::Box);
        arena.get_mut(flexed).flex = 1;
        arena.append(root, fixed);
        arena.append(root, flexed);

        LayoutState::new().layout(&mut arena, root, 30, 5);

        assert_eq!(arena.get(fixed).lw, 10);
        assert_eq!(arena.get(flexed).lw, 20);
    }

    #[test]
    fn justify_end_pushes_children_to_the_far_edge() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Box);
        {
            let n = arena.get_mut(root);
            n.direction = Direction::Row;
            n.justify = Justify::End;
        }
        let a = arena.create(Tag::Box);
        arena.get_mut(a).width = 4;
        arena.append(root, a);

        LayoutState::new().layout(&mut arena, root, 10, 3);

        assert_eq!(arena.get(a).lx, 6);
    }

    #[test]
    fn padding_and_border_shrink_the_content_box() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Box);
        {
            let n = arena.get_mut(root);
            n.border = crate::view::Border::Single;
            n.padding = crate::view::Padding::all(1);
        }
        let child = arena.create(Tag::Box);
        arena.get_mut(child).flex = 1;
        arena.append(root, child);

        LayoutState::new().layout(&mut arena, root, 10, 10);

        // 1 cell of border + 1 cell of padding on each side.
        assert_eq!((arena.get(child).lx, arena.get(child).ly), (2, 2));
        assert_eq!((arena.get(child).lw, arena.get(child).lh), (6, 6));
    }

    #[test]
    fn a_hole_child_is_skipped_and_occupies_nothing() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Box);
        arena.get_mut(root).direction = Direction::Row;
        let hole = arena.create(Tag::Hole);
        let a = arena.create(Tag::Box);
        arena.get_mut(a).width = 5;
        arena.append(root, hole);
        arena.append(root, a);

        LayoutState::new().layout(&mut arena, root, 20, 5);

        assert_eq!(arena.get(a).lx, 0); // the hole claimed no space before it
        assert_eq!((arena.get(hole).lw, arena.get(hole).lh), (0, 0));
    }
}
