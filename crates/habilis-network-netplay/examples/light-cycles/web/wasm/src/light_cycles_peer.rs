use crate::cycle_dto::CycleDto;
use crate::frame_dto::FrameDto;
use crate::game::Game;
use crate::grid::{GRID_H, GRID_W, TICK_MS};
use crate::hud_dto::HudDto;
use crate::light_cycles::LightCycles;
use crate::outcome_dto::outcome_dto;
use crate::roster_entry_dto::RosterEntryDto;
use crate::{MAX_CATCH_UP_TICKS, js_error, parse_dir};
use habilis_network::embed::SilentSink;
use habilis_network::protocol::{LookupOpts, MeshConfig, Nickname, TransportPolicy};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_config, setup_mesh,
};
use habilis_network::util::clock::Instant;
use habilis_network_netplay::RollbackDriver;
use std::cell::RefCell;
use std::time::Duration;
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

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
        // Carries every input over the relay transport instead of a direct path.
        relay_transport: bool,
    ) -> Result<LightCyclesPeer, JsValue> {
        console_error_panic_hook::set_once();

        let mesh = derive_topic_mesh_config(
            &room_code,
            MeshConfig::new(
                LookupOpts::public_preset(),
                None,
                None,
                TransportPolicy::default().relay_transport(relay_transport),
            ),
        )
        .map_err(js_error::to_js_error)?;
        let author = Nickname::try_new(&nick).map_err(js_error::to_js_error)?;
        let kind = SetupKind::Topic {
            mesh,
            topic_string: room_code,
        };

        let config = setup_mesh(
            kind,
            SetupParams::new(author.clone(), SilentSink::default()).max_peers(16),
        )
        .await
        .map_err(js_error::to_js_error)?;

        // `handle_signals: false` — nothing to catch in a browser.
        let (driver, pending) = RollbackDriver::<LightCycles>::new();
        let node: Node<RollbackDriver<LightCycles>> =
            Node::spawn(config, driver, None, SignalHandling::Leave);
        let game = Game::new(pending.connect(node.sender()), author);

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
        let dir = parse_dir::parse_dir(dir)?;
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
        serde_json::to_string(&dto).map_err(js_error::to_js_error)
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
        let roster: Vec<RosterEntryDto> = snapshot
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
        serde_json::to_string(&dto).map_err(js_error::to_js_error)
    }

    /// Lobby joins and departures since the last call, as a JSON array.
    ///
    /// # Errors
    /// The event list fails to serialize — not expected in practice.
    pub fn drain_events(&self) -> Result<String, JsValue> {
        let events: Vec<_> = self.game.borrow_mut().drain_events().collect();
        serde_json::to_string(&events).map_err(js_error::to_js_error)
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
