//! Grapheme segmentation and cell-width measurement, the rule being that
//! cells and Unicode scalar/code-unit indices are never mixed.
//!
//! v1 defers `visage-tui`'s hand-rolled WIDE/ZERO Unicode range tables (see
//! the plan's `visage-rust-tui` section: "ASCII-safe assumption is fine to
//! start; full Unicode width parity is not this crate's job to solve
//! first") in favor of the well-tested `unicode-width` crate — not
//! byte-identical to `visage-tui`'s tables, but correct for the common
//! cases (CJK, most emoji) a game HUD would ever show.

use crate::tui::truncate::Truncate;
use crate::tui::wrap::Wrap;
use std::mem;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// Splits `text` into extended grapheme clusters (UAX #29) — a ZWJ emoji
/// family, a flag, a base+combining-mark sequence, each one unit.
pub fn graphemes(text: &str) -> impl Iterator<Item = &str> {
    text.graphemes(true)
}

/// The terminal cell width of one grapheme cluster: 0, 1, or 2.
#[must_use]
pub fn char_width(cluster: &str) -> usize {
    UnicodeWidthStr::width(cluster)
}

/// The total cell width of `text`. Does not special-case `\n` — callers
/// with multi-line text measure each line themselves.
#[must_use]
pub fn string_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/// Shortens `text` to fit `cells`, replacing the cut with `…`. A wide
/// grapheme that would straddle the boundary is dropped whole rather than
/// split, so the result can be narrower than `cells` by one cell —
/// matching what a terminal does at the right margin.
#[must_use]
pub fn truncate(text: &str, cells: usize, mode: Truncate) -> String {
    if cells == 0 {
        return String::new();
    }
    if string_width(text) <= cells {
        return text.to_string();
    }
    if cells == 1 {
        return "…".to_string();
    }
    let parts: Vec<&str> = graphemes(text).collect();
    match mode {
        Truncate::End | Truncate::None => format!("{}…", take(&parts, cells - 1, true)),
        Truncate::Start => format!("…{}", take(&parts, cells - 1, false)),
        Truncate::Middle => {
            let left = (cells - 1) / 2;
            let right = cells - 1 - left;
            format!(
                "{}…{}",
                take(&parts, left, true),
                take(&parts, right, false)
            )
        }
    }
}

/// Accumulates clusters from the front (`from_front`) or back, stopping —
/// not splitting — as soon as one more cluster would exceed `cells`.
pub(crate) fn take(parts: &[&str], cells: usize, from_front: bool) -> String {
    let mut used = 0;
    let mut out: Vec<&str> = Vec::new();
    let ordered: Vec<&&str> = if from_front {
        parts.iter().collect()
    } else {
        parts.iter().rev().collect()
    };
    for part in ordered {
        let width = char_width(part);
        if used + width > cells {
            break;
        }
        out.push(part);
        used += width;
    }
    if !from_front {
        out.reverse();
    }
    out.concat()
}

/// Wraps `text` to `cells`. `\n` is always a hard break in every mode;
/// `mode` only controls implicit breaks within an over-wide line.
pub fn wrap_text(text: &str, cells: usize, mode: Wrap) -> impl Iterator<Item = String> {
    let hard: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::new();
    if mode == Wrap::None || cells == 0 {
        out.extend(hard.into_iter().map(str::to_string));
        return out.into_iter();
    }
    for line in hard {
        if string_width(line) <= cells {
            out.push(line.to_string());
            continue;
        }
        match mode {
            Wrap::Char => out.extend(break_anywhere(line, cells)),
            Wrap::Word => out.extend(break_at_words(line, cells)),
            Wrap::None => unreachable!("handled above"),
        }
    }
    out.into_iter()
}

pub(crate) fn break_anywhere(line: &str, cells: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut used = 0;
    for part in graphemes(line) {
        let width = char_width(part);
        if used + width > cells {
            out.push(mem::take(&mut current));
            used = 0;
        }
        current.push_str(part);
        used += width;
    }
    out.push(current);
    out
}

pub(crate) fn break_at_words(line: &str, cells: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut used = 0;
    for word in line.split(' ') {
        let width = string_width(word);
        let gap = usize::from(!current.is_empty());
        if used + gap + width <= cells {
            if gap == 1 {
                current.push(' ');
            }
            current.push_str(word);
            used += gap + width;
            continue;
        }
        if !current.is_empty() {
            out.push(mem::take(&mut current));
        }
        if width <= cells {
            current = word.to_string();
            used = width;
            continue;
        }
        // One word wider than the box: break it, carry the tail forward.
        let pieces = break_anywhere(word, cells);
        let (last, rest) = pieces
            .split_last()
            .expect("break_anywhere always yields at least one piece");
        out.extend_from_slice(rest);
        current.clone_from(last);
        used = string_width(&current);
    }
    out.push(current);
    out
}

#[cfg(test)]
mod tests {
    use super::{Truncate, Wrap, char_width, graphemes, string_width, truncate, wrap_text};

    #[test]
    fn ascii_graphemes_are_one_cell_each() {
        let _guard = ::habilis_network_test_tracing::init();
        let got: Vec<&str> = graphemes("abc").collect();
        assert_eq!(
            got,
            vec!["a", "b", "c"],
            "ascii graphemes are one cell each"
        );
        assert_eq!(
            string_width("abc"),
            3,
            "an ascii string is three cells wide"
        );
    }

    #[test]
    fn wide_cjk_characters_are_two_cells() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(char_width("字"), 2, "a wide cjk character is two cells");
        assert_eq!(
            string_width("字字"),
            4,
            "two wide cjk characters are four cells"
        );
    }

    #[test]
    fn truncate_end_replaces_the_tail_with_an_ellipsis() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            truncate("hello world", 8, Truncate::End),
            "hello w…",
            "truncate at the end replaces the tail with an ellipsis"
        );
    }

    #[test]
    fn truncate_a_single_cell_is_just_the_ellipsis() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            truncate("hello", 1, Truncate::End),
            "…",
            "a single-cell truncation is just the ellipsis"
        );
    }

    #[test]
    fn truncate_shorter_than_the_budget_is_unchanged() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            truncate("hi", 10, Truncate::End),
            "hi",
            "a string shorter than the budget is unchanged"
        );
    }

    #[test]
    fn word_wrap_breaks_between_words_not_inside_them() {
        let _guard = ::habilis_network_test_tracing::init();
        let got: Vec<String> = wrap_text("the quick brown fox", 10, Wrap::Word).collect();
        assert_eq!(
            got,
            vec!["the quick", "brown fox"],
            "word wrap breaks between words"
        );
    }

    #[test]
    fn char_wrap_breaks_anywhere() {
        let _guard = ::habilis_network_test_tracing::init();
        let got: Vec<String> = wrap_text("abcdefgh", 3, Wrap::Char).collect();
        assert_eq!(got, vec!["abc", "def", "gh"], "char wrap breaks anywhere");
    }

    #[test]
    fn no_wrap_returns_hard_lines_untouched() {
        let _guard = ::habilis_network_test_tracing::init();
        let got: Vec<String> = wrap_text("a very long line indeed", 5, Wrap::None).collect();
        assert_eq!(
            got,
            vec!["a very long line indeed"],
            "no wrap returns hard lines untouched"
        );
    }

    #[test]
    fn newlines_are_always_hard_breaks() {
        let _guard = ::habilis_network_test_tracing::init();
        let got: Vec<String> = wrap_text("first\nsecond", 20, Wrap::Word).collect();
        assert_eq!(
            got,
            vec!["first", "second"],
            "newlines are always hard breaks"
        );
    }
}
