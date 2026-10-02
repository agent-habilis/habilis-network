//! The terminal framebuffer and the paint walk that fills it, ported from
//! `visage-tui/src/paint/index.ts`. `paint` always does a total repaint of
//! the buffer — minimality lives entirely in [`super::diff`].
//!
//! One deliberate v1 scoping-down: there is no `overflow: visible`. Every
//! box clips its children to its content box (upstream's default anyway),
//! which is what the plan's `visage-rust-tui` section means by "enough
//! widgets for a grid + HUD" rather than full parity.

use crate::tui::color::DEFAULT_COLOR;
use crate::tui::node::{Arena, NodeId, Tag, TextAlign, TuiNode};
use crate::tui::width::{Truncate, char_width, graphemes, string_width, truncate as truncate_text};
use crate::view::Border;

/// One grapheme cluster per cell — never a `char`, since a cell can hold a
/// multi-code-point cluster (ZWJ emoji, combining marks). An empty string
/// marks the second half of a wide glyph (the continuation cell).
#[derive(Debug, Clone)]
pub struct ScreenBuffer {
    pub width: i32,
    pub height: i32,
    pub chars: Vec<String>,
    pub fg: Vec<i32>,
    pub bg: Vec<i32>,
    pub attrs: Vec<u8>,
}

impl ScreenBuffer {
    #[must_use]
    pub fn new(width: i32, height: i32) -> Self {
        let size = usize::try_from(width.max(0) * height.max(0)).unwrap_or(0);
        Self {
            width,
            height,
            chars: vec![" ".to_string(); size],
            fg: vec![DEFAULT_COLOR; size],
            bg: vec![DEFAULT_COLOR; size],
            attrs: vec![0; size],
        }
    }

    pub fn clear(&mut self) {
        for cell in &mut self.chars {
            cell.clear();
            cell.push(' ');
        }
        self.fg.fill(DEFAULT_COLOR);
        self.bg.fill(DEFAULT_COLOR);
        self.attrs.fill(0);
    }
}

/// Order is top-left, top-right, bottom-left, bottom-right, horizontal,
/// vertical.
const BORDER_SINGLE: [char; 6] = ['┌', '┐', '└', '┘', '─', '│'];
const BORDER_ROUND: [char; 6] = ['╭', '╮', '╰', '╯', '─', '│'];
const BORDER_DOUBLE: [char; 6] = ['╔', '╗', '╚', '╝', '═', '║'];
const BORDER_BOLD: [char; 6] = ['┏', '┓', '┗', '┛', '━', '┃'];
const BORDER_ASCII: [char; 6] = ['+', '+', '+', '+', '-', '|'];

fn border_chars(style: Border) -> Option<[char; 6]> {
    match style {
        Border::None => None,
        Border::Single => Some(BORDER_SINGLE),
        Border::Round => Some(BORDER_ROUND),
        Border::Double => Some(BORDER_DOUBLE),
        Border::Bold => Some(BORDER_BOLD),
        Border::Ascii => Some(BORDER_ASCII),
    }
}

/// `right`/`bottom` are exclusive.
#[derive(Debug, Clone, Copy)]
struct Clip {
    x: i32,
    y: i32,
    right: i32,
    bottom: i32,
}

fn intersect(a: Clip, b: Clip) -> Clip {
    Clip {
        x: a.x.max(b.x),
        y: a.y.max(b.y),
        right: a.right.min(b.right),
        bottom: a.bottom.min(b.bottom),
    }
}

#[derive(Debug, Clone, Copy)]
struct Style {
    fg: i32,
    bg: i32,
    attrs: u8,
}

const ROOT_STYLE: Style = Style {
    fg: DEFAULT_COLOR,
    bg: DEFAULT_COLOR,
    attrs: 0,
};

pub fn paint(buffer: &mut ScreenBuffer, arena: &Arena, root: NodeId) {
    buffer.clear();
    let clip = Clip {
        x: 0,
        y: 0,
        right: buffer.width,
        bottom: buffer.height,
    };
    paint_node(buffer, arena, root, clip, ROOT_STYLE);
}

fn paint_node(buffer: &mut ScreenBuffer, arena: &Arena, id: NodeId, clip: Clip, inherited: Style) {
    let node = arena.get(id);
    if !node.visible || node.tag == Tag::Hole {
        return;
    }
    if node.lw <= 0 || node.lh <= 0 {
        return;
    }

    // Inheritance: fg/bg inherit exactly when the node's own value is
    // DEFAULT_COLOR — there is deliberately no way to reset back to the
    // terminal default under an ancestor that set a color. `attrs` is a
    // bitwise OR up the tree, so there is no way to un-set a parent's bit.
    let style = Style {
        fg: if node.fg == DEFAULT_COLOR {
            inherited.fg
        } else {
            node.fg
        },
        bg: if node.bg == DEFAULT_COLOR {
            inherited.bg
        } else {
            node.bg
        },
        attrs: inherited.attrs | node.attrs,
    };

    // The background covers the node's whole border box, text included —
    // a stretched `text` node is a full-width highlighted row.
    if style.bg != DEFAULT_COLOR {
        fill(buffer, clip, node.lx, node.ly, node.lw, node.lh, style);
    }

    if node.tag == Tag::Text {
        paint_text(buffer, node, clip, style);
        return;
    }
    if node.border != Border::None {
        paint_border(buffer, node, clip, style);
    }

    let frame = i32::from(node.border != Border::None);
    let child_clip = intersect(
        clip,
        Clip {
            x: node.lx + frame + i32::from(node.padding.left),
            y: node.ly + frame + i32::from(node.padding.top),
            right: node.lx + node.lw - frame - i32::from(node.padding.right),
            bottom: node.ly + node.lh - frame - i32::from(node.padding.bottom),
        },
    );
    for child in arena.children(id) {
        paint_node(buffer, arena, child, child_clip, style);
    }
}

fn paint_text(buffer: &mut ScreenBuffer, node: &TuiNode, clip: Clip, style: Style) {
    let empty = Vec::new();
    let lines = node.lines.as_ref().unwrap_or(&empty);
    for (i, raw_line) in lines.iter().enumerate() {
        let Ok(row) = i32::try_from(i) else { break };
        if row >= node.lh {
            break; // lines beyond node.lh are dropped, never clipped
        }
        let width = i32::try_from(string_width(raw_line)).unwrap_or(i32::MAX);
        let line = if width > node.lw && node.truncate != Truncate::None {
            truncate_text(
                raw_line,
                usize::try_from(node.lw.max(0)).unwrap_or(0),
                node.truncate,
            )
        } else {
            raw_line.clone()
        };
        let mut x = node.lx;
        if node.text_align != TextAlign::Left {
            let slack = node.lw - i32::try_from(string_width(&line)).unwrap_or(0);
            if slack > 0 {
                x += if node.text_align == TextAlign::Center {
                    slack / 2
                } else {
                    slack
                };
            }
        }
        write(buffer, clip, x, node.ly + row, &line, style);
    }
}

fn paint_border(buffer: &mut ScreenBuffer, node: &TuiNode, clip: Clip, style: Style) {
    let Some(chars) = border_chars(node.border) else {
        return;
    };
    let edge = if node.border_fg == DEFAULT_COLOR {
        style
    } else {
        Style {
            fg: node.border_fg,
            ..style
        }
    };
    let left = node.lx;
    let top = node.ly;
    let right = node.lx + node.lw - 1;
    let bottom = node.ly + node.lh - 1;

    let mut buf = [0u8; 4];
    for x in (left + 1)..right {
        put(
            buffer,
            clip,
            x,
            top,
            chars[4].encode_utf8(&mut buf),
            edge,
            1,
        );
        put(
            buffer,
            clip,
            x,
            bottom,
            chars[4].encode_utf8(&mut buf),
            edge,
            1,
        );
    }
    for y in (top + 1)..bottom {
        put(
            buffer,
            clip,
            left,
            y,
            chars[5].encode_utf8(&mut buf),
            edge,
            1,
        );
        put(
            buffer,
            clip,
            right,
            y,
            chars[5].encode_utf8(&mut buf),
            edge,
            1,
        );
    }
    put(
        buffer,
        clip,
        left,
        top,
        chars[0].encode_utf8(&mut buf),
        edge,
        1,
    );
    put(
        buffer,
        clip,
        right,
        top,
        chars[1].encode_utf8(&mut buf),
        edge,
        1,
    );
    put(
        buffer,
        clip,
        left,
        bottom,
        chars[2].encode_utf8(&mut buf),
        edge,
        1,
    );
    put(
        buffer,
        clip,
        right,
        bottom,
        chars[3].encode_utf8(&mut buf),
        edge,
        1,
    );

    // Uses `style`, not `edge` — the title takes the node's own fg, not the
    // border's.
    if let Some(title) = &node.title
        && node.lw > 4
    {
        let inset = format!(
            " {} ",
            truncate_text(
                title,
                usize::try_from((node.lw - 6).max(0)).unwrap_or(0),
                Truncate::End
            )
        );
        write(buffer, clip, left + 2, top, &inset, style);
    }
}

// See `layout::arrange`'s doc comment on why `x`/`y`/`w`/`h` stay short.
#[allow(clippy::many_single_char_names)]
fn fill(buffer: &mut ScreenBuffer, clip: Clip, x: i32, y: i32, w: i32, h: i32, style: Style) {
    let x0 = clip.x.max(x).max(0);
    let x1 = clip.right.min(x + w).min(buffer.width);
    let y0 = clip.y.max(y).max(0);
    let y1 = clip.bottom.min(y + h).min(buffer.height);
    for row in y0..y1 {
        for col in x0..x1 {
            let i = index(buffer, row, col);
            buffer.chars[i].clear();
            buffer.chars[i].push(' ');
            buffer.fg[i] = style.fg;
            buffer.bg[i] = style.bg;
            buffer.attrs[i] = style.attrs;
        }
    }
}

/// The wide-character handling: writes one grapheme cluster, and — for a
/// two-cell-wide one — a continuation cell (`''`) carrying the *same*
/// style, which matters for the diff's cell-equality test. A wide glyph
/// clipped at the right edge downgrades its lead cell to a space, matching
/// what a terminal itself does.
fn put(
    buffer: &mut ScreenBuffer,
    clip: Clip,
    x: i32,
    y: i32,
    cluster: &str,
    style: Style,
    width: usize,
) {
    if y < clip.y || y >= clip.bottom || y < 0 || y >= buffer.height {
        return;
    }
    if x < clip.x || x >= clip.right || x < 0 || x >= buffer.width {
        return;
    }
    let i = index(buffer, y, x);
    buffer.chars[i] = cluster.to_string();
    buffer.fg[i] = style.fg;
    buffer.bg[i] = style.bg;
    buffer.attrs[i] = style.attrs;
    if width != 2 {
        return;
    }
    let next = x + 1;
    if next >= clip.right || next >= buffer.width {
        buffer.chars[i] = " ".to_string();
        return;
    }
    let j = index(buffer, y, next);
    buffer.chars[j].clear(); // '' continuation marker
    buffer.fg[j] = style.fg;
    buffer.bg[j] = style.bg;
    buffer.attrs[j] = style.attrs;
}

/// Clusters left of `clip.x` are dropped by `put` but still advance
/// `column` — correct for a horizontally-scrolled/clipped line.
fn write(buffer: &mut ScreenBuffer, clip: Clip, x: i32, y: i32, text: &str, style: Style) {
    if y < clip.y || y >= clip.bottom {
        return;
    }
    let mut column = x;
    for cluster in graphemes(text) {
        let width = char_width(cluster);
        if width == 0 {
            continue; // never advances the column
        }
        if column >= clip.right {
            break;
        }
        put(buffer, clip, column, y, cluster, style, width);
        column += i32::try_from(width).unwrap_or(0);
    }
}

fn index(buffer: &ScreenBuffer, row: i32, col: i32) -> usize {
    usize::try_from(row * buffer.width + col).expect("caller has already bounds-checked row/col")
}

#[cfg(test)]
mod tests {
    use super::{ScreenBuffer, paint};
    use crate::tui::node::{Arena, Tag};
    use crate::tui::width::string_width;

    #[test]
    fn a_text_node_writes_its_content_into_the_buffer() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Text);
        {
            let n = arena.get_mut(root);
            n.text = Some("hi".to_string());
            n.lx = 0;
            n.ly = 0;
            n.lw = 5;
            n.lh = 1;
            n.lines = Some(vec!["hi".to_string()]);
        }
        let mut buffer = ScreenBuffer::new(5, 1);
        paint(&mut buffer, &arena, root);
        assert_eq!(buffer.chars[0], "h");
        assert_eq!(buffer.chars[1], "i");
        assert_eq!(buffer.chars[2], " ");
    }

    #[test]
    fn a_background_color_fills_the_whole_border_box() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Box);
        {
            let n = arena.get_mut(root);
            n.bg = crate::tui::color::palette(1);
            n.lx = 0;
            n.ly = 0;
            n.lw = 3;
            n.lh = 2;
        }
        let mut buffer = ScreenBuffer::new(3, 2);
        paint(&mut buffer, &arena, root);
        for bg in &buffer.bg {
            assert_eq!(*bg, crate::tui::color::palette(1));
        }
    }

    #[test]
    fn a_wide_glyph_writes_a_continuation_cell() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Text);
        {
            let n = arena.get_mut(root);
            n.text = Some("字a".to_string());
            n.lx = 0;
            n.ly = 0;
            n.lw = 5;
            n.lh = 1;
            n.lines = Some(vec!["字a".to_string()]);
        }
        let mut buffer = ScreenBuffer::new(5, 1);
        paint(&mut buffer, &arena, root);
        assert_eq!(string_width(&buffer.chars[0]), 2);
        assert_eq!(buffer.chars[1], ""); // continuation
        assert_eq!(buffer.chars[2], "a");
    }

    #[test]
    fn text_clipped_at_the_right_edge_still_advances_by_full_width() {
        let mut arena = Arena::new();
        let root = arena.create(Tag::Text);
        {
            let n = arena.get_mut(root);
            n.text = Some("toolong".to_string());
            n.lx = 0;
            n.ly = 0;
            n.lw = 3;
            n.lh = 1;
            n.truncate = crate::tui::width::Truncate::None;
            n.lines = Some(vec!["toolong".to_string()]);
        }
        let mut buffer = ScreenBuffer::new(3, 1);
        paint(&mut buffer, &arena, root);
        assert_eq!(buffer.chars, vec!["t", "o", "o"]);
    }
}
