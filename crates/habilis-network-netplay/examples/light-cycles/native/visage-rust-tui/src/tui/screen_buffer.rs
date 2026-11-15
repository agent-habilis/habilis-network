use crate::tui::color::DEFAULT_COLOR;

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
