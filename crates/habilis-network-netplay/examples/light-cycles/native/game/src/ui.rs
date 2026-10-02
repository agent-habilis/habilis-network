//! The terminal UI: a `visage-rust-tui` root component rendering the same
//! screen the browser client does.
//!
//! "The same" is meant literally, not loosely. `web/src/Board.tsx` draws
//! the arena as characters on a `1ch` grid precisely so it can meet this
//! one: both read the same `grid` array, use the same glyphs, rule the
//! same grid every [`GRID_STEP`] cells, and lay the readouts out the same
//! way — players flanking the top, status between them, controls along the
//! bottom. Change the arrangement here and change it there.
//!
//! The one thing that cannot match is the cell aspect: a terminal's
//! character cell is roughly twice as tall as it is wide and is not ours
//! to choose, where the browser pins its cells to a square `1ch`.
//!
//! Colors are named ANSI palette indices (`palette(1..=14)`), never
//! truecolor — a displayed "red" or "blue" follows whatever the user has
//! configured for that name in their own terminal theme, rather than
//! forcing a specific RGB value that might clash with it.

use std::pin::Pin;

use visage_rust_tui::component::{ComponentCoroutine, Yield};
use visage_rust_tui::reactive::Signal;
use visage_rust_tui::tui::color::palette;
use visage_rust_tui::view::{Align, Border, BoxProps, Direction, Justify, Padding, View};

use crate::app::Snapshot;
use crate::grid::{GRID_H, GRID_W};
use crate::sim::Outcome;

/// Named ANSI colors usable as a player color, in assignment order.
/// `0` (black) and the near-background/foreground indices are skipped —
/// indistinguishable from "empty" or the terminal's own default text on
/// plenty of themes.
///
/// **The order and length are a cross-play contract**, not a local
/// choice: `web/src/colors.ts` assigns the same six hues to the same
/// roster indices and wraps at the same point, so a given player is the
/// same color to everyone regardless of which client they are watching.
/// Change one side and you change the other. Past six players the color
/// repeats — identically on both clients, which is the property that
/// matters here.
const PLAYER_PALETTE: [u8; 6] = [4, 1, 5, 2, 3, 6];

/// How many cells apart the arena's ruled grid sits. 8 divides both 64 and
/// 48, so the field is ruled edge to edge with no partial square. Matches
/// `web/src/colors.ts`'s constant of the same name.
const GRID_STEP: u8 = 8;

/// A claimed cell. Full block, so trails read as solid light.
const TRAIL: char = '█';
/// An empty cell on a ruled intersection.
const RULE: char = '·';
const EMPTY: char = ' ';

fn color_for(roster_index: usize) -> i32 {
    palette(PLAYER_PALETTE[roster_index % PLAYER_PALETTE.len()])
}

/// Bright black — dim enough for the ruled grid to read as depth rather
/// than as something in play.
fn dim() -> i32 {
    palette(8)
}

/// The root component: reads `snapshot` every render and produces the
/// whole tree fresh. A game's screen changes almost entirely every tick
/// anyway (the grid, the HUD counters), so one root re-rendering wholesale
/// is the right level of granularity here — not a case for
/// `View::component`'s nested-instance isolation, which pays off when
/// *most* of a tree stays still and only a small part changes.
#[must_use]
pub fn app(snapshot: Signal<Snapshot>) -> Pin<Box<ComponentCoroutine>> {
    Box::pin(
        #[coroutine]
        move || {
            loop {
                let current = snapshot.get();
                yield Yield::View(render(&current));
            }
        },
    )
}

fn render(s: &Snapshot) -> View {
    View::boxed(
        BoxProps {
            direction: Direction::Column,
            ..BoxProps::default()
        },
        vec![players(s), status(s), arena(s), controls(s)],
    )
}

/// The players, flanking the screen — one at each edge with two, spread
/// evenly with more. The readout arrangement the cabinet used.
fn players(s: &Snapshot) -> View {
    let mut children: Vec<View> = s
        .roster
        .iter()
        .enumerate()
        .map(|(i, (pubkey, nick))| {
            let alive = s.world.cycles.get(i).is_some_and(|c| c.alive);
            let mut label = nick.to_uppercase();
            if !alive {
                label.push_str(" (OUT)");
            }
            if *pubkey == s.my_pubkey {
                label.push_str(" YOU");
            }
            View::boxed(
                BoxProps {
                    fg: color_for(i),
                    ..BoxProps::default()
                },
                vec![View::text(label)],
            )
        })
        .collect();
    // Something has to occupy the row or it collapses and the screen jumps
    // when the first match starts.
    if children.is_empty() {
        children.push(View::text(" "));
    }
    View::boxed(
        BoxProps {
            direction: Direction::Row,
            justify: Justify::Between,
            width: Some(u16::from(GRID_W) + 2),
            ..BoxProps::default()
        },
        children,
    )
}

/// The one-line summary of where the match is. Public because the
/// "terminal too small" screen in `main.rs` shows it too — a stuck player
/// is most likely staring at that screen, and two copies of this wording
/// would drift apart.
#[must_use]
pub fn status_line(s: &Snapshot) -> String {
    if s.desynced {
        return "DESYNCED".to_owned();
    }
    // Ahead of the waiting states on purpose: a lobby that *cannot* start
    // must not keep reporting that it is about to.
    if let Some(blocked) = &s.blocked {
        return blocked.to_uppercase();
    }
    if s.waiting {
        return if s.present > 1 {
            format!("{} PLAYERS READY", s.present)
        } else {
            "WAITING".to_owned()
        };
    }
    if s.syncing {
        return "SYNCING".to_owned();
    }
    match crate::sim::outcome(&s.world) {
        Outcome::InProgress => String::new(),
        Outcome::Winner(i) => format!(
            "{} WINS",
            s.roster
                .get(i)
                .map_or("?".to_owned(), |(_, nick)| nick.to_uppercase())
        ),
        Outcome::Draw => "DRAW".to_owned(),
    }
}

fn status(s: &Snapshot) -> View {
    let alarming = s.desynced || s.blocked.is_some();
    let color = if alarming { palette(1) } else { palette(6) };
    View::boxed(
        BoxProps {
            direction: Direction::Row,
            justify: Justify::Center,
            width: Some(u16::from(GRID_W) + 2),
            fg: color,
            ..BoxProps::default()
        },
        vec![View::text(status_line(s))],
    )
}

/// The arena, bordered. While waiting there is nothing in the field worth
/// looking at, so it carries the attract message instead — the browser
/// overlays the same words on the same empty grid.
fn arena(s: &Snapshot) -> View {
    let body = if s.waiting {
        vec![View::boxed(
            BoxProps {
                direction: Direction::Column,
                justify: Justify::Center,
                align: Align::Center,
                flex: 1,
                fg: palette(6),
                ..BoxProps::default()
            },
            vec![
                View::text(attract_headline(s)),
                View::boxed(
                    BoxProps {
                        fg: dim(),
                        ..BoxProps::default()
                    },
                    // Pointless advice when the lobby is blocked — sharing
                    // the code again fixes nothing, and the status line
                    // above is already carrying the actual reason.
                    vec![View::text(if s.blocked.is_some() {
                        ""
                    } else {
                        "SHARE THE ROOM CODE BELOW"
                    })],
                ),
            ],
        )]
    } else {
        (0..GRID_H).map(|y| row_view(s, y)).collect()
    };

    View::boxed(
        BoxProps {
            direction: Direction::Column,
            border: Border::Single,
            fg: palette(6),
            width: Some(u16::from(GRID_W) + 2),
            height: Some(u16::from(GRID_H) + 2),
            ..BoxProps::default()
        },
        body,
    )
}

/// The big line in the middle of an empty arena.
///
/// A blocked lobby must not read as an imminent match: "GET READY" for
/// something that can never start is worse than saying nothing.
fn attract_headline(s: &Snapshot) -> String {
    if s.blocked.is_some() {
        "CANNOT START".to_owned()
    } else if s.present > 1 {
        "GET READY".to_owned()
    } else {
        "WAITING FOR A PLAYER".to_owned()
    }
}

fn controls(s: &Snapshot) -> View {
    View::boxed(
        BoxProps {
            direction: Direction::Row,
            justify: Justify::Between,
            width: Some(u16::from(GRID_W) + 2),
            fg: dim(),
            padding: Padding {
                top: 1,
                ..Padding::default()
            },
            ..BoxProps::default()
        },
        vec![
            View::text("↑↓←→ OR WASD".to_owned()),
            View::text(format!("MATCH {}", s.match_number)),
            View::text(room_label(&s.room)),
        ],
    )
}

/// `ROOM <code>`, with the code **exactly as given**.
///
/// The label is shouted like every other readout; the code is not, and that
/// is load-bearing rather than a style choice. It is the one string on this
/// screen a player retypes into another terminal, and
/// `crypto::topic_seed` hashes the topic byte-for-byte after trimming —
/// deliberately, since case-folding is platform-dependent and would break
/// convergence across machines. Uppercasing the value here therefore
/// handed the player a code that derives a *different* mesh: both sides
/// then wait forever, each looking somewhere the other is not, with
/// nothing on screen to say so.
fn room_label(room: &str) -> String {
    format!("ROOM {room}")
}

/// One grid row, as a run-length-encoded sequence of colored spans — a
/// bare `View::Text` inherits its color from an ancestor `Box`, so a
/// contiguous run of one player's trail is one small `Box{fg}` wrapping
/// one `Text`, not one node per cell. `web/src/Board.tsx`'s `rowRuns` does
/// exactly this with `<span>`s.
fn row_view(s: &Snapshot, y: u8) -> View {
    let width = usize::from(GRID_W);
    let base = usize::from(y) * width;

    let mut spans = Vec::new();
    let mut run_owner: Option<u8> = None;
    let mut run = String::new();

    for x in 0..width {
        let owner = s.world.grid.get(base + x).copied().unwrap_or(0);
        if run_owner != Some(owner) {
            flush_run(run_owner, &mut run, &mut spans);
            run_owner = Some(owner);
        }
        let ruled = x.is_multiple_of(usize::from(GRID_STEP)) && y.is_multiple_of(GRID_STEP);
        run.push(if owner != 0 {
            TRAIL
        } else if ruled {
            RULE
        } else {
            EMPTY
        });
    }
    flush_run(run_owner, &mut run, &mut spans);

    View::boxed(
        BoxProps {
            direction: Direction::Row,
            ..BoxProps::default()
        },
        spans,
    )
}

fn flush_run(owner: Option<u8>, run: &mut String, spans: &mut Vec<View>) {
    if run.is_empty() {
        return;
    }
    let text = View::text(std::mem::take(run));
    spans.push(match owner {
        Some(o) if o > 0 => View::boxed(
            BoxProps {
                fg: color_for(usize::from(o - 1)),
                ..BoxProps::default()
            },
            vec![text],
        ),
        // The ruled grid lives in the empty runs, so they are dimmed
        // rather than left to inherit.
        _ => View::boxed(
            BoxProps {
                fg: dim(),
                ..BoxProps::default()
            },
            vec![text],
        ),
    });
}

#[cfg(test)]
mod tests {
    use super::room_label;

    /// Regression: the room code used to be uppercased for display, but
    /// `crypto::topic_seed` hashes the topic byte-for-byte. A player who
    /// retyped what the screen showed derived a different mesh and waited
    /// forever. The label may shout; the code may not.
    #[test]
    fn the_room_code_is_shown_exactly_as_given() {
        assert_eq!(room_label("Gadget-Plover"), "ROOM Gadget-Plover");
        assert_eq!(room_label("volt-paddle"), "ROOM volt-paddle");
    }
}
