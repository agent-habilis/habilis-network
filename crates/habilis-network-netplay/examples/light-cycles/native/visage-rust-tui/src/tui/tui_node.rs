use crate::tui::color::DEFAULT_COLOR;
use crate::tui::node_id::NodeId;
use crate::tui::tag::Tag;
use crate::tui::text_align::TextAlign;
use crate::tui::truncate::Truncate;
use crate::tui::wrap::Wrap;
use crate::view::{Align, Border, Direction, Justify, Padding};

#[derive(Debug, Clone)]
pub struct TuiNode {
    pub tag: Tag,

    // Tree — doubly-linked list of children, arena-indexed.
    pub parent: Option<NodeId>,
    pub previous: Option<NodeId>,
    pub next: Option<NodeId>,
    pub first_child: Option<NodeId>,
    pub last_child: Option<NodeId>,
    pub child_count: u32,

    // Box model.
    pub direction: Direction,
    /// Absolute cells, or -1 for "auto". No percentage sizing in v1.
    pub width: i32,
    pub height: i32,
    pub flex: u16,
    pub padding: Padding,
    pub gap: u16,
    pub justify: Justify,
    pub align: Align,
    pub border: Border,
    pub border_fg: i32,
    pub title: Option<String>,
    pub visible: bool,

    // Style.
    pub fg: i32,
    pub bg: i32,
    pub attrs: u8,

    // Text.
    /// A `text` node's own text prop, or a `#text` leaf's data.
    pub text: Option<String>,
    pub wrap: Wrap,
    pub truncate: Truncate,
    pub text_align: TextAlign,

    // Written by the layout pass — absolute cell coordinates of the
    // BORDER box.
    pub lx: i32,
    pub ly: i32,
    pub lw: i32,
    pub lh: i32,
    pub lines: Option<Vec<String>>,

    // Measure cache.
    pub mw: i32,
    pub mh: i32,
    pub m_epoch: i64,
    pub m_avail_w: i32,
    pub m_avail_h: i32,
}

impl TuiNode {
    pub(crate) fn new(tag: Tag) -> Self {
        Self {
            tag,
            parent: None,
            previous: None,
            next: None,
            first_child: None,
            last_child: None,
            child_count: 0,
            direction: Direction::Column,
            width: -1,
            height: -1,
            flex: 0,
            padding: Padding::default(),
            gap: 0,
            justify: Justify::Start,
            align: Align::Stretch,
            border: Border::None,
            border_fg: DEFAULT_COLOR,
            title: None,
            visible: true,
            fg: DEFAULT_COLOR,
            bg: DEFAULT_COLOR,
            attrs: 0,
            text: None,
            wrap: Wrap::None,
            truncate: Truncate::End,
            text_align: TextAlign::Left,
            lx: 0,
            ly: 0,
            lw: 0,
            lh: 0,
            lines: None,
            mw: 0,
            mh: 0,
            m_epoch: -1,
            m_avail_w: -1,
            m_avail_h: -1,
        }
    }
}
