//! Two [`ScreenBuffer`]s in, the smallest ANSI that gets from one to the
//! other out. Ported from `visage-tui/src/diff/index.ts`.
//!
//! Kept from the original: row-granular skip (an unchanged row emits
//! nothing), prefix/suffix span rewrite within a changed row, erase rather
//! than overwrite for a blank tail, zero bytes when nothing changed.
//! Reversed from `ansi-diff` (the reference the original itself reverses
//! four decisions from): **absolute** cursor positioning
//! (`ESC[row;colH`), not relative — relative positioning desyncs
//! permanently on the first external write or an unexpected wrap, and
//! there is no way to notice or recover. A resize is a full repaint. SGR
//! state is tracked (the "pen"), so a run of same-styled cells costs one
//! escape sequence, not one per cell.

use crate::tui::color::{DEFAULT_COLOR, push_attrs, push_bg, push_fg};
use crate::tui::paint::ScreenBuffer;

const ESC: &str = "\u{1b}[";
const CLEAR_LINE: &str = "\u{1b}[0K";
/// Every attribute and color back to the terminal's own defaults.
pub const RESET: &str = "\u{1b}[0m";

fn move_to(x: i32, y: i32) -> String {
    format!("{ESC}{};{}H", y + 1, x + 1)
}

fn clear_screen() -> String {
    format!("{ESC}H{ESC}2J")
}

#[derive(Debug, Clone, Copy)]
struct Pen {
    fg: i32,
    bg: i32,
    attrs: u8,
}

const DEFAULT_PEN: Pen = Pen {
    fg: DEFAULT_COLOR,
    bg: DEFAULT_COLOR,
    attrs: 0,
};

fn is_default(pen: Pen) -> bool {
    pen.fg == DEFAULT_COLOR && pen.bg == DEFAULT_COLOR && pen.attrs == 0
}

/// Diffs `prev` (`None` on the very first frame) against `next`, returning
/// the ANSI bytes that repaint the terminal from one to the other. Empty
/// when nothing changed.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn diff(prev: Option<&ScreenBuffer>, next: &ScreenBuffer) -> String {
    let full = prev.is_none_or(|p| p.width != next.width || p.height != next.height);
    let mut out = String::new();
    let mut pen = DEFAULT_PEN;
    if full {
        out.push_str(RESET);
        out.push_str(&clear_screen());
    }

    let width = next.width;
    for y in 0..next.height {
        let base = usize::try_from(y * width).unwrap_or(0);

        let mut left = 0i32;
        let mut right = width - 1;
        while left <= right
            && unchanged(prev, next, base + usize::try_from(left).unwrap_or(0), full)
        {
            left += 1;
        }
        if left > right {
            continue; // whole row unchanged: emit nothing
        }
        while right > left
            && unchanged(prev, next, base + usize::try_from(right).unwrap_or(0), full)
        {
            right -= 1;
        }

        // Wide-glyph boundary expansion: a continuation cell at either edge
        // of the changed span pulls the edge onto its lead cell.
        while left > 0 && next.chars[base + usize::try_from(left).unwrap_or(0)].is_empty() {
            left -= 1;
        }
        while right + 1 < width
            && next.chars[base + usize::try_from(right + 1).unwrap_or(0)].is_empty()
        {
            right += 1;
        }

        // Trailing-blank scan, over `next` only, in absolute terms — not
        // relative to the changed span, since the span has already been
        // trimmed past blanks that were also blank before.
        let mut tail = width;
        while tail > 0 && blank(next, base + usize::try_from(tail - 1).unwrap_or(0)) {
            tail -= 1;
        }

        let erase = tail <= right;
        let emit_to = if erase { left.max(tail) - 1 } else { right };

        out.push_str(&move_to(left, y));
        let mut x = left;
        while x <= emit_to {
            let i = base + usize::try_from(x).unwrap_or(0);
            if !next.chars[i].is_empty() {
                style(&mut out, &mut pen, next.fg[i], next.bg[i], next.attrs[i]);
                out.push_str(&next.chars[i]);
            }
            x += 1;
        }

        if erase {
            // EL0 erases with the *current* background on most terminals,
            // so the pen must be reset first or the tail paints in the
            // last-written cell's background.
            if !is_default(pen) {
                out.push_str(RESET);
                pen = DEFAULT_PEN;
            }
            out.push_str(CLEAR_LINE);
        }
    }

    if out.is_empty() {
        return out; // the empty check runs before the trailing RESET below,
        // so a no-change frame is genuinely zero bytes
    }
    if !is_default(pen) {
        out.push_str(RESET);
    }
    out
}

fn unchanged(prev: Option<&ScreenBuffer>, next: &ScreenBuffer, i: usize, full: bool) -> bool {
    let Some(prev) = (if full { None } else { prev }) else {
        // On a full repaint the screen has just been erased, so "unchanged"
        // collapses to "is blank in the default colors" — this is what
        // unifies the first frame with every other one instead of giving
        // it its own code path.
        return blank(next, i);
    };
    prev.chars[i] == next.chars[i]
        && prev.fg[i] == next.fg[i]
        && prev.bg[i] == next.bg[i]
        && prev.attrs[i] == next.attrs[i]
}

fn blank(buffer: &ScreenBuffer, i: usize) -> bool {
    // A continuation cell ("") is NOT blank, so the tail scan stops at one.
    buffer.chars[i] == " "
        && buffer.fg[i] == DEFAULT_COLOR
        && buffer.bg[i] == DEFAULT_COLOR
        && buffer.attrs[i] == 0
}

/// One `ESC[...m` per cell-style change, carrying every changed parameter.
/// `push_attrs` returning `true` means it emitted SGR `0`, which resets
/// colors too — so the pen's color beliefs are invalidated before the
/// fg/bg comparisons, forcing them to be re-emitted.
fn style(out: &mut String, pen: &mut Pen, fg: i32, bg: i32, attrs: u8) {
    if pen.fg == fg && pen.bg == bg && pen.attrs == attrs {
        return;
    }
    let mut params = Vec::new();
    if push_attrs(&mut params, pen.attrs, attrs) {
        pen.fg = DEFAULT_COLOR;
        pen.bg = DEFAULT_COLOR;
    }
    if pen.fg != fg {
        push_fg(&mut params, fg);
    }
    if pen.bg != bg {
        push_bg(&mut params, bg);
    }
    if !params.is_empty() {
        out.push_str(ESC);
        out.push_str(&params.join(";"));
        out.push('m');
    }
    pen.fg = fg;
    pen.bg = bg;
    pen.attrs = attrs;
}

#[cfg(test)]
mod tests {
    use super::{CLEAR_LINE, RESET, diff};
    use crate::tui::color::palette;
    use crate::tui::paint::ScreenBuffer;

    fn set(buffer: &mut ScreenBuffer, x: i32, y: i32, s: &str) {
        let i =
            usize::try_from(y * buffer.width + x).expect("test fixture indices are non-negative");
        buffer.chars[i] = s.to_string();
    }

    #[test]
    fn a_blank_first_frame_is_just_reset_plus_clear_screen() {
        let buffer = ScreenBuffer::new(10, 3);
        let out = diff(None, &buffer);
        assert_eq!(out, format!("{RESET}{ESC}H{ESC}2J", ESC = "\u{1b}["));
    }

    #[test]
    fn two_identical_frames_produce_zero_bytes() {
        let mut a = ScreenBuffer::new(5, 1);
        set(&mut a, 0, 0, "x");
        let b = a.clone();
        assert_eq!(diff(Some(&a), &b), "");
    }

    #[test]
    fn a_changed_row_moves_the_cursor_absolutely_then_writes_the_span() {
        let a = ScreenBuffer::new(5, 1);
        let mut b = ScreenBuffer::new(5, 1);
        set(&mut b, 2, 0, "x");
        let out = diff(Some(&a), &b);
        assert!(out.starts_with("\u{1b}[1;3H")); // row 1, col 3 (1-based)
        assert!(out.contains('x'));
    }

    #[test]
    fn a_shortened_line_erases_the_tail_instead_of_overwriting_with_spaces() {
        let mut a = ScreenBuffer::new(5, 1);
        set(&mut a, 0, 0, "h");
        set(&mut a, 1, 0, "e");
        set(&mut a, 2, 0, "l");
        set(&mut a, 3, 0, "l");
        set(&mut a, 4, 0, "o");
        let mut b = ScreenBuffer::new(5, 1);
        set(&mut b, 0, 0, "x");
        set(&mut b, 1, 0, "y");
        // Cells 2..5 are blank in `b`: the tail scan should cover them
        // with one `EL0` instead of three literal space-overwrites.
        let out = diff(Some(&a), &b);
        assert!(out.contains("xy"));
        assert!(out.contains(CLEAR_LINE));
        assert!(!out.contains('l')); // never emitted as a replacement write
    }

    #[test]
    fn an_unchanged_prefix_is_not_re_emitted_even_when_the_row_changes() {
        // Only the character at column 1 differs; column 0 already reads
        // "h" on screen and must not be rewritten — this is the whole
        // reason the algorithm scans in from both ends instead of
        // rewriting from the first difference to the end of the row.
        let mut a = ScreenBuffer::new(2, 1);
        set(&mut a, 0, 0, "h");
        set(&mut a, 1, 0, "i");
        let mut b = ScreenBuffer::new(2, 1);
        set(&mut b, 0, 0, "h");
        set(&mut b, 1, 0, "o");
        let out = diff(Some(&a), &b);
        assert!(out.contains('o'));
        assert!(!out.contains('h')); // unchanged cell, never rewritten
    }

    #[test]
    fn a_run_of_same_styled_cells_emits_one_sgr_sequence() {
        let a = ScreenBuffer::new(3, 1);
        let mut b = ScreenBuffer::new(3, 1);
        for i in 0..3 {
            b.chars[i] = "x".to_string();
            b.fg[i] = palette(1);
        }
        let out = diff(Some(&a), &b);
        // Exactly one `38...m`-shaped SGR sequence, i.e. one occurrence of
        // the palette-1 foreground code, even though three cells changed.
        assert_eq!(out.matches("31m").count(), 1);
        assert_eq!(out.matches('x').count(), 3);
    }

    #[test]
    fn a_resize_forces_a_full_repaint_even_if_content_matches() {
        let a = ScreenBuffer::new(5, 1);
        let b = ScreenBuffer::new(6, 1); // wider — same logical content, different size
        let out = diff(Some(&a), &b);
        assert!(out.starts_with(&format!("{RESET}\u{1b}[H\u{1b}[2J")));
    }
}
