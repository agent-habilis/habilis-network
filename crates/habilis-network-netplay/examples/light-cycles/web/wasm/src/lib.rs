//! The web `light-cycles` client's wasm half: game logic, the
//! `habilis-network-netplay` embedding (`app`), and the deterministic
//! `grid`/`round`/`sim` machinery — all this crate's own copy,
//! independent of `native/game`'s (see the plan's "Workspace layout").
//!
//! This file is the one thing with no native counterpart to mirror: the
//! wasm-bindgen JS API a `requestAnimationFrame` loop drives —
//! [`LightCyclesPeer::join`], [`LightCyclesPeer::turn`],
//! [`LightCyclesPeer::frame`], [`LightCyclesPeer::hud`],
//! [`LightCyclesPeer::drain_events`].
//!
//! `frame()` is also where the simulation is *paced*, and that is
//! load-bearing rather than a convenience. A rollback session advances
//! exactly one simulation tick per `Game::tick`, so driving it straight
//! off rAF would run this client at the display's refresh rate — 60 Hz
//! against the terminal client's 20 — and the two would not be playing
//! the same game. The accumulator below decouples the two: render as
//! often as the browser likes, simulate at [`grid::TICK_MS`].

mod app;
mod grid;
mod round;
mod sim;

use std::cell::RefCell;

use habilis_network::embed::SilentSink;
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, MeshConfig, MeshName, Nickname, TransportPolicy};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, derive_topic_mesh_config, setup_mesh,
};
use habilis_network::util::clock::Instant;
use habilis_network_netplay::RollbackDriver;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use wasm_bindgen::prelude::*;

use app::{Game, LightCycles};
use grid::{Dir, GRID_H, GRID_W, TICK_MS};
use sim::Outcome;

/// The most simulation ticks one `frame()` will run to catch up.
///
/// A browser suspends rAF entirely while a tab is backgrounded, so the
/// first frame after the player comes back can be minutes of owed time.
/// Replaying all of it would freeze the tab and, worse, race far ahead of
/// the other players. Capping it means a returning tab simply resumes and
/// lets the session's own pacing pull it back into line.
const MAX_CATCH_UP_TICKS: u32 = 4;

#[derive(Serialize)]
struct CycleDto {
    x: i16,
    y: i16,
    alive: bool,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutcomeDto {
    InProgress,
    Winner { index: usize },
    Draw,
}

fn outcome_dto(outcome: Outcome) -> OutcomeDto {
    match outcome {
        Outcome::InProgress => OutcomeDto::InProgress,
        Outcome::Winner(index) => OutcomeDto::Winner { index },
        Outcome::Draw => OutcomeDto::Draw,
    }
}

/// A `visage-canvas` scene is built from exactly this every rAF — see the
/// plan's "Rendering approach".
#[derive(Serialize)]
struct FrameDto {
    grid_w: u8,
    grid_h: u8,
    /// Row-major, `grid_w * grid_h`. `0` = empty, else roster index + 1 —
    /// same encoding `sim::World::grid` uses internally.
    grid: Vec<u8>,
    cycles: Vec<CycleDto>,
}

#[derive(Serialize)]
struct RosterEntryDto {
    pubkey: String,
    nick: String,
    alive: bool,
    me: bool,
}

#[derive(Serialize)]
struct HudDto {
    /// Which match this is, counting from 1; `0` before the first.
    match_number: u64,
    /// Peers in the lobby, us included.
    present: usize,
    /// No match in progress — waiting for someone to play against.
    waiting: bool,
    /// A peer's state checksum disagreed with ours. Should never happen;
    /// if it does, the two are no longer playing the same game.
    desynced: bool,
    /// Why the lobby cannot start a match, when waiting will not fix it.
    blocked: Option<String>,
    /// The session is up but still aligning frame numbers with its peers.
    syncing: bool,
    /// The authoritative match outcome, from `sim::outcome`. Sent rather
    /// than left for the frontend to re-derive from `roster`: that is the
    /// game's central rule, and a second definition of it on the
    /// frontend drifted from this one immediately.
    outcome: OutcomeDto,
    roster: Vec<RosterEntryDto>,
}

/// A joined mesh peer — one instance for the tab's whole session. Dropping
/// it leaves the mesh (there is no explicit `leave()`; a page
/// navigation/reload is the only lifecycle this client needs, same as
/// `chat-web`'s).
#[wasm_bindgen]
pub struct LightCyclesPeer {
    // Never read directly — held only so the node's background task isn't
    // dropped.
    _node: Node<RollbackDriver<LightCycles>>,
    /// `RefCell`, not `Arc<Mutex<_>>`: nothing shares this any more. The
    /// engine's event loop reaches the game through the transport's own
    /// mailboxes, so the only borrower is this tab's rAF loop.
    game: RefCell<Game>,
    /// When the last simulation tick ran, and the time owed since.
    last_tick: RefCell<Instant>,
}

#[wasm_bindgen]
impl LightCyclesPeer {
    /// Joins the mesh derived from `room_code`. "Join" and "create" are
    /// the same call for a topic-derived mesh — whichever tab calls this
    /// first has created nothing special, the mesh id is a pure function
    /// of the string (see the plan's "Create / join screen").
    ///
    /// `relay_transport` lets game traffic fall back to the relay; off, the
    /// relay is a meeting point only and every input goes peer to peer. It
    /// is mixed into the mesh id, so both tabs must pass the same value.
    ///
    /// # Errors
    /// An invalid `nick`, or anything that fails while standing up the
    /// mesh (a malformed `room_code`, or the underlying `setup_mesh` call
    /// itself failing) — surfaced as its `Display` string, not a typed
    /// error, since the only consumer is JS.
    pub async fn join(
        room_code: String,
        nick: String,
        relay_transport: bool,
    ) -> Result<LightCyclesPeer, JsValue> {
        console_error_panic_hook::set_once();

        let mesh = derive_topic_mesh_config(
            &room_code,
            MeshConfig {
                lookups: LookupOpts::public_preset(),
                password: None,
                issuer_pubkey: None,
                transport: TransportPolicy {
                    relay_transport,
                    ..TransportPolicy::default()
                },
            },
        )
        .map_err(to_js_error)?;
        let author = Nickname::new(&nick).map_err(to_js_error)?;
        let kind = SetupKind::Topic {
            mesh,
            topic_string: room_code,
        };

        let config = setup_mesh(
            kind,
            SetupParams {
                author,
                max_peers: 16,
                endpoint: None,
                protocols: Vec::new(),
                transports: TransportOpts::default(),
                // No files and no control socket: a browser has neither.
                runtime_base: None,
                state_file: None,
                sink: Arc::new(SilentSink),
                multihop: false,
                per_peer_gate: None,
                cohost: None,
                live_count: None,
            },
        )
        .await
        .map_err(to_js_error)?;

        // `handle_signals: false` — nothing to catch in a browser.
        let (driver, pending) = RollbackDriver::<LightCycles>::new();
        let node: Node<RollbackDriver<LightCycles>> = Node::spawn(config, driver, None, false);
        let game = Game::new(pending.connect(node.sender()), nick);

        Ok(LightCyclesPeer {
            _node: node,
            game: RefCell::new(game),
            last_tick: RefCell::new(Instant::now()),
        })
    }

    /// Steers toward `"up"`, `"down"`, `"left"`, or `"right"`
    /// (case-insensitive).
    ///
    /// Sticky, and applied on the next simulation tick rather than
    /// immediately: the input is held state, not an event, which is what
    /// makes the session's prediction of a missing input correct. A
    /// reversal is refused by the simulation itself, so nothing is
    /// rejected here.
    ///
    /// # Errors
    /// `dir` isn't one of the four recognized direction strings.
    pub fn turn(&self, dir: &str) -> Result<(), JsValue> {
        let dir = parse_dir(dir)?;
        self.game.borrow_mut().steer(dir);
        Ok(())
    }

    /// Advances the simulation by however many ticks are owed, then
    /// returns the current frame as a JSON string. Call this every
    /// `requestAnimationFrame`; see this module's doc on why the pacing
    /// lives here.
    ///
    /// # Errors
    /// The frame fails to serialize — not expected in practice.
    pub fn frame(&self) -> Result<String, JsValue> {
        self.pump();

        let game = self.game.borrow();
        let world = game.snapshot().world;
        let dto = FrameDto {
            grid_w: GRID_W,
            grid_h: GRID_H,
            cycles: world
                .cycles
                .iter()
                .map(|c| CycleDto {
                    x: c.x,
                    y: c.y,
                    alive: c.alive,
                })
                .collect(),
            grid: world.grid,
        };
        serde_json::to_string(&dto).map_err(to_js_error)
    }

    /// Match/roster/connection info as a JSON string — separate from
    /// [`Self::frame`] since a HUD redraws far less often than the canvas
    /// does. A pure read: [`Self::frame`] is what advances anything.
    ///
    /// # Errors
    /// The HUD fails to serialize — not expected in practice.
    pub fn hud(&self) -> Result<String, JsValue> {
        let game = self.game.borrow();
        let snapshot = game.snapshot();
        let roster = snapshot
            .roster
            .iter()
            .enumerate()
            .map(|(i, (pubkey, nick))| RosterEntryDto {
                pubkey: pubkey.clone(),
                nick: nick.clone(),
                alive: snapshot.world.cycles.get(i).is_some_and(|c| c.alive),
                me: *pubkey == snapshot.my_pubkey,
            })
            .collect();
        let dto = HudDto {
            match_number: snapshot.match_number,
            present: snapshot.present,
            waiting: snapshot.waiting,
            desynced: snapshot.desynced,
            blocked: snapshot.blocked.clone(),
            syncing: snapshot.syncing,
            outcome: outcome_dto(game.outcome()),
            roster,
        };
        serde_json::to_string(&dto).map_err(to_js_error)
    }

    /// Lobby joins and departures since the last call, as a JSON array.
    ///
    /// # Errors
    /// The event list fails to serialize — not expected in practice.
    pub fn drain_events(&self) -> Result<String, JsValue> {
        let events = self.game.borrow_mut().drain_events();
        serde_json::to_string(&events).map_err(to_js_error)
    }

    /// Runs the simulation ticks owed since the last call.
    fn pump(&self) {
        let step = Duration::from_millis(u64::from(TICK_MS));
        let mut last = self.last_tick.borrow_mut();
        let mut game = self.game.borrow_mut();
        let mut ran = 0;
        while last.elapsed() >= step && ran < MAX_CATCH_UP_TICKS {
            game.tick();
            *last += step;
            ran += 1;
        }
        if ran == MAX_CATCH_UP_TICKS {
            // Whatever is still owed is unreachable — a backgrounded tab,
            // or a hitch long enough that replaying it would help nobody.
            // Drop it rather than carry a debt that never pays down.
            *last = Instant::now();
        }
    }
}

/// A fresh `word-word` room code, from the same curated wordlist the
/// native CLI's `MeshName::random()` draws on — 1024 words, so ~1M pairs.
/// Exposed here rather than reimplemented on the frontend: a second,
/// shorter word list would give browser-minted codes a far higher chance
/// of colliding with an unrelated room than CLI-minted ones, on a topic
/// string that is the room's whole identity.
#[wasm_bindgen]
#[must_use]
pub fn random_room_code() -> String {
    MeshName::random().to_string()
}

/// A fresh `word-word` nickname, from that same wordlist — what
/// `native/game`'s CLI defaults to.
#[wasm_bindgen]
#[must_use]
pub fn random_nick() -> String {
    Nickname::random().to_string()
}

fn parse_dir(s: &str) -> Result<Dir, JsValue> {
    match s.to_ascii_lowercase().as_str() {
        "up" => Ok(Dir::Up),
        "down" => Ok(Dir::Down),
        "left" => Ok(Dir::Left),
        "right" => Ok(Dir::Right),
        other => Err(to_js_error(format!("unknown direction: {other}"))),
    }
}

fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}
