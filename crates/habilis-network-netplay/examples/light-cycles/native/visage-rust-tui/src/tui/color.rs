//! Packed terminal colors and SGR emission, ported from
//! `visage-tui/src/color/index.ts`.

/// Terminal default (SGR 39/49) — `-1` rather than `0` because `0x000000`
/// is a legitimate truecolor black.
pub const DEFAULT_COLOR: i32 = -1;
const PALETTE: i32 = 0x0100_0000;
const TRUECOLOR: i32 = 0x0200_0000;

/// A 256-color palette index, packed for [`push`].
#[must_use]
pub fn palette(index: u8) -> i32 {
    PALETTE | i32::from(index)
}

/// A 24-bit truecolor value (`0xrrggbb`), packed for [`push`].
#[must_use]
pub fn truecolor(rgb: u32) -> i32 {
    TRUECOLOR | (rgb & 0x00ff_ffff).cast_signed()
}

/// Appends the SGR parameter(s) selecting `packed` as a foreground (`base =
/// 30`) or background (`base = 40`) color. Mirrors `push`/`pushFg`/`pushBg`.
pub fn push(out: &mut Vec<String>, packed: i32, base: i32) {
    if packed == DEFAULT_COLOR {
        out.push((base + 9).to_string()); // 39 / 49
        return;
    }
    if packed & TRUECOLOR == TRUECOLOR {
        let rgb = packed & 0x00ff_ffff;
        out.push(format!(
            "{};2;{};{};{}",
            base + 8,
            (rgb >> 16) & 0xff,
            (rgb >> 8) & 0xff,
            rgb & 0xff
        ));
        return;
    }
    let index = packed & 0xff;
    if index < 8 {
        out.push((base + index).to_string()); // 30-37 / 40-47
    } else if index < 16 {
        out.push((base + 60 + (index - 8)).to_string()); // 90-97 / 100-107
    } else {
        out.push(format!("{};5;{index}", base + 8)); // 38;5;n
    }
}

pub fn push_fg(out: &mut Vec<String>, packed: i32) {
    push(out, packed, 30);
}

pub fn push_bg(out: &mut Vec<String>, packed: i32) {
    push(out, packed, 40);
}

pub const BOLD: u8 = 1;
pub const DIM: u8 = 2;
pub const ITALIC: u8 = 4;
pub const UNDERLINE: u8 = 8;
pub const INVERSE: u8 = 16;
pub const STRIKE: u8 = 32;
const SGR_ON: [(u8, u8); 6] = [
    (BOLD, 1),
    (DIM, 2),
    (ITALIC, 3),
    (UNDERLINE, 4),
    (INVERSE, 7),
    (STRIKE, 9),
];

/// Appends SGR codes turning attribute bits on/off to move from `prev` to
/// `next`, returning `true` if it emitted SGR `0` (which also resets
/// colors — the caller must re-emit fg/bg after). Individual "attribute
/// off" codes are avoided entirely: SGR 21 is "double underline" on some
/// terminals and "bold off" on others, and 22 clears bold and dim
/// together, so any bit going off resets everything and re-applies what
/// should stay on.
pub fn push_attrs(out: &mut Vec<String>, prev: u8, next: u8) -> bool {
    if prev == next {
        return false;
    }
    if prev & !next != 0 {
        out.push("0".to_string());
        for (bit, code) in SGR_ON {
            if next & bit != 0 {
                out.push(code.to_string());
            }
        }
        return true;
    }
    for (bit, code) in SGR_ON {
        if next & bit != 0 && prev & bit == 0 {
            out.push(code.to_string());
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_COLOR, INVERSE, UNDERLINE, palette, push_attrs, push_bg, push_fg, truecolor,
    };

    #[test]
    fn default_color_pushes_the_reset_code() {
        let mut out = Vec::new();
        push_fg(&mut out, DEFAULT_COLOR);
        assert_eq!(out, vec!["39"]);
        let mut out = Vec::new();
        push_bg(&mut out, DEFAULT_COLOR);
        assert_eq!(out, vec!["49"]);
    }

    #[test]
    fn low_palette_indices_use_the_classic_codes() {
        let mut out = Vec::new();
        push_fg(&mut out, palette(1)); // red
        assert_eq!(out, vec!["31"]);
    }

    #[test]
    fn bright_palette_indices_use_9x_and_10x() {
        let mut out = Vec::new();
        push_fg(&mut out, palette(9)); // bright red: 30 + 60 + (9-8) = 91
        assert_eq!(out, vec!["91"]);
        let mut out = Vec::new();
        push_bg(&mut out, palette(9)); // 40 + 60 + (9-8) = 101
        assert_eq!(out, vec!["101"]);
    }

    #[test]
    fn high_palette_indices_use_extended_syntax() {
        let mut out = Vec::new();
        push_fg(&mut out, palette(200));
        assert_eq!(out, vec!["38;5;200"]);
    }

    #[test]
    fn truecolor_uses_the_24_bit_syntax() {
        let mut out = Vec::new();
        push_fg(&mut out, truecolor(0x0000_ff80));
        assert_eq!(out, vec!["38;2;0;255;128"]);
    }

    #[test]
    fn identical_attrs_emit_nothing() {
        let mut out = Vec::new();
        assert!(!push_attrs(&mut out, UNDERLINE, UNDERLINE));
        assert!(out.is_empty());
    }

    #[test]
    fn turning_a_bit_on_emits_only_that_code() {
        let mut out = Vec::new();
        assert!(!push_attrs(&mut out, 0, UNDERLINE));
        assert_eq!(out, vec!["4"]);
    }

    #[test]
    fn turning_a_bit_off_resets_everything_and_reapplies_the_rest() {
        let mut out = Vec::new();
        let reset = push_attrs(&mut out, UNDERLINE | INVERSE, INVERSE);
        assert!(reset);
        assert_eq!(out, vec!["0", "7"]); // SGR 0, then re-apply inverse (7)
    }
}
