//! The native `light-cycles` client: a thin CLI shell around the
//! `light_cycles_native` library (see `lib.rs`), which is where the actual
//! game logic and networking embedding live. This file owns the two
//! things a real terminal process needs that a library can't: argument
//! parsing, and the crossterm-driven render/input loop over
//! `visage-rust-tui`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute, terminal};
use tokio::time::MissedTickBehavior;

use habilis_network::embed::SilentSink;
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, MeshConfig, MeshName, Nickname, TransportPolicy};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, derive_topic_mesh_config, setup_mesh,
};

use habilis_network_netplay::RollbackDriver;

use light_cycles_native::app::Snapshot;
use light_cycles_native::app::{Game, LightCycles};
use light_cycles_native::grid::{Dir, GRID_H, GRID_W, TICK_MS};
use light_cycles_native::ui;

use visage_rust_tui::reactive::Signal;
use visage_rust_tui::runtime::{Runtime, render_frame};
use visage_rust_tui::tui::layout::LayoutState;

#[derive(Parser)]
#[command(
    name = "light-cycles",
    about = "A real-time multiplayer light-cycles game over habilis-network"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Write engine logs to this file, filtered by `RUST_LOG`
    /// (e.g. `RUST_LOG=habilis_network=debug`).
    ///
    /// A file rather than stderr because the alternate screen owns the
    /// terminal for the whole game: anything written there is painted over
    /// immediately. Without this a client that will not connect has no way
    /// to tell you why.
    #[arg(long, global = true, value_name = "PATH")]
    log_file: Option<PathBuf>,
    /// Find the other player on this machine only, over loopback.
    ///
    /// Without it the room is bootstrapped over the public network
    /// (relay/DHT), which is what lets someone across the internet join —
    /// and which takes 20-30s to converge even when both players are on
    /// this same machine. For two terminals side by side, this is instant
    /// and needs no internet at all. Both sides must pass it: the flag
    /// changes how the mesh is derived, so a `--local` peer and a public
    /// one are looking for each other in different places.
    #[arg(long, global = true)]
    local: bool,
    /// Let game traffic fall back to the relay when no direct path opens.
    ///
    /// Without it the relay is a meeting point only and every input goes
    /// peer to peer. Both sides must pass it: it is mixed into the mesh id.
    /// Meaningless with `--local`, which has no relay.
    #[arg(long, global = true, conflicts_with = "local")]
    relay_transport: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Mint a fresh room code, print it, and join it.
    Create {
        #[arg(long)]
        nick: Option<String>,
    },
    /// Join a room a friend already created.
    Join {
        room: String,
        #[arg(long)]
        nick: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let (room, nick) = match cli.command {
        Some(Command::Create { nick }) => (create_room(), nick),
        Some(Command::Join { room, nick }) => (room, nick),
        None => prompt_for_room()?,
    };
    let nick = nick.unwrap_or_else(|| Nickname::random().to_string());
    // Before the mesh comes up, so the setup path is logged too.
    if let Some(path) = cli.log_file {
        start_logging(&path)?;
    }

    run(&room, &nick, cli.local, cli.relay_transport).await
}

/// Point `tracing` at `path`, filtered by `RUST_LOG`.
///
/// `Arc<File>` is the writer because `&File` implements `Write`, which is
/// all `MakeWriter` asks for — no logging side-crate needed. `with_ansi`
/// off: this is a file, and colour codes in it only make it harder to read.
fn start_logging(path: &Path) -> Result<()> {
    let file = std::fs::File::create(path)?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(Arc::new(file))
        .with_ansi(false)
        .init();
    Ok(())
}

/// A fresh `word-word` room code — the same generator nicknames use, just
/// repurposed here as a memorable topic string a player reads aloud.
fn create_room() -> String {
    let room = MeshName::random().to_string();
    println!("room code: {room}");
    room
}

/// No subcommand given: ask on stdin instead of requiring flags, so the
/// human-playable client doesn't strictly need to know the CLI surface.
fn prompt_for_room() -> Result<(String, Option<String>)> {
    print!("nickname (blank for random): ");
    io::stdout().flush()?;
    let mut nick = String::new();
    io::stdin().read_line(&mut nick)?;
    let nick = nick.trim();
    let nick = if nick.is_empty() {
        None
    } else {
        Some(nick.to_string())
    };

    print!("create or join a game? [c/j]: ");
    io::stdout().flush()?;
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;

    if choice.trim().eq_ignore_ascii_case("j") {
        print!("room code: ");
        io::stdout().flush()?;
        let mut room = String::new();
        io::stdin().read_line(&mut room)?;
        Ok((room.trim().to_string(), nick))
    } else {
        Ok((create_room(), nick))
    }
}

async fn run(room: &str, nick: &str, local: bool, relay_transport: bool) -> Result<()> {
    let lookups = if local {
        // Zero external network calls: peers find each other on a
        // seed-derived loopback port ladder. The same setting the
        // integration tests use, which is why they converge in about a
        // second where the public path needs half a minute.
        LookupOpts::loopback()
    } else {
        LookupOpts::public_preset()
    };
    let mesh = derive_topic_mesh_config(
        room,
        MeshConfig {
            lookups,
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy {
                relay_transport,
                ..TransportPolicy::default()
            },
        },
    )?;
    let author = Nickname::new(nick)?;
    let kind = SetupKind::Topic {
        mesh,
        topic_string: room.to_string(),
    };

    let config = setup_mesh(
        kind,
        SetupParams {
            author,
            max_peers: 16,
            max_direct: 0,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink: Arc::new(SilentSink),
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await?;

    // `handle_signals: false` — see `mesh_peer.rs`'s own note: registering
    // tokio's signal handler suppresses the OS default-terminate for the
    // whole process, permanently. This CLI races its own `ctrl_c()` in
    // `render_loop` instead, and always reaches `node.leave()` below.
    let (driver, pending) = RollbackDriver::<LightCycles>::new();
    let node: Node<RollbackDriver<LightCycles>> = Node::spawn(config, driver, None, false);
    let mut game = Game::new(
        pending.connect(node.sender()),
        room.to_string(),
        nick.to_string(),
    );

    let result = render_loop(&mut game).await;

    node.leave().await?;
    result
}

/// Enables raw mode + the alternate screen for the loop's lifetime,
/// restoring both on drop — including on an early `?` return or an
/// unwinding panic, since nothing else in this crate touches the terminal
/// mode (`visage-rust-tui` deliberately leaves that to the caller).
struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), cursor::Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

/// `crossterm::terminal::size()` reads `0x0` in a handful of real
/// environments that have no controlling terminal to report dimensions for
/// (a detached pty, some CI runners) — falls back to a conventional
/// terminal size rather than laying out into a zero-area viewport.
fn viewport_size() -> Result<(i32, i32)> {
    let (width, height) = terminal::size()?;
    if width == 0 || height == 0 {
        return Ok((80, 24));
    }
    Ok((i32::from(width), i32::from(height)))
}

/// The smallest terminal the whole screen fits in, derived from the arena
/// rather than written down: the field plus its border, and the three
/// readout rows (players, status, controls) with the controls' padding.
///
/// The arena is a fixed 64x48 because that is a cross-play contract with
/// the browser client — shrinking it for a small terminal would change the
/// game, not just the view. So below this the client refuses to draw
/// rather than clipping: a clipped arena hides the room code and the
/// status, which is exactly what a player needs when nothing is
/// happening.
const MIN_COLS: i32 = GRID_W as i32 + 2;
const MIN_ROWS: i32 = GRID_H as i32 + 2 + 4;

fn fits(width: i32, height: i32) -> bool {
    width >= MIN_COLS && height >= MIN_ROWS
}

/// What to show instead of the game when the window is too small.
///
/// Carries the room code and the lobby status, because this is the screen
/// a player who "cannot connect" is most likely looking at, and both are
/// otherwise off the bottom of the terminal.
///
/// `\r\n`, not `\n`: raw mode does no carriage-return translation.
fn too_small_screen(snapshot: &Snapshot, width: i32, height: i32) -> String {
    let status = ui::status_line(snapshot);
    let room = &snapshot.room;
    format!(
        "TERMINAL TOO SMALL\r\n\r\n\
         need   {MIN_COLS} x {MIN_ROWS}\r\n\
         have   {width} x {height}\r\n\r\n\
         ROOM {room}\r\n\
         {status}\r\n\r\n\
         resize to start  ·  q to quit\r\n"
    )
}

async fn render_loop(game: &mut Game) -> Result<()> {
    let _raw = RawModeGuard::enter()?;

    let signal = Signal::new(game.snapshot());
    let mut runtime = Runtime::terminal(ui::app(signal.clone()));
    let mut layout_state = LayoutState::new();
    let mut previous = None;
    // The last "too small" screen written, so an unchanged one is not
    // repainted: it clears the whole terminal, and doing that at the frame
    // rate flickers.
    let mut last_too_small: Option<String> = None;
    // Forces a full repaint on the first pass and on every return from the
    // "too small" screen, which the diffing renderer would otherwise skip:
    // while waiting, two consecutive snapshots are often equal, so nothing
    // is dirty and the stale message would stay on screen after a resize.
    let mut needs_full_redraw = true;

    // One render tick is one simulation frame — see `Game::tick`.
    let mut ticker = tokio::time::interval(Duration::from_millis(u64::from(TICK_MS)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if drain_input(game)? {
                    return Ok(());
                }
                // Ticked whatever the window size: the peer is still ours
                // to keep, and dropping out of the mesh because somebody
                // narrowed a terminal would be its own bug.
                game.tick();
                let snapshot = game.snapshot();
                signal.set(snapshot.clone());

                let (width, height) = viewport_size()?;
                if !fits(width, height) {
                    let screen = too_small_screen(&snapshot, width, height);
                    if last_too_small.as_ref() != Some(&screen) {
                        let mut out = io::stdout();
                        execute!(
                            out,
                            terminal::Clear(terminal::ClearType::All),
                            cursor::MoveTo(0, 0)
                        )?;
                        out.write_all(screen.as_bytes())?;
                        out.flush()?;
                        last_too_small = Some(screen);
                    }
                    previous = None;
                    needs_full_redraw = true;
                    continue;
                }
                last_too_small = None;
                if runtime.tick() || needs_full_redraw {
                    needs_full_redraw = false;
                    let (bytes, buffer) = render_frame(
                        &mut runtime,
                        &mut layout_state,
                        previous.as_ref(),
                        width,
                        height,
                    );
                    io::stdout().write_all(bytes.as_bytes())?;
                    io::stdout().flush()?;
                    previous = Some(buffer);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                return Ok(());
            }
        }
    }
}

/// Drains every pending key event without blocking the frame — a light-
/// cycle only ever needs its *latest* facing before the next tick, so
/// nothing is lost by coalescing a burst of keystrokes down to the last
/// one. Returns whether the player asked to quit.
fn drain_input(game: &mut Game) -> Result<bool> {
    while event::poll(Duration::ZERO)? {
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if is_quit_key(key.code, key.modifiers) {
            return Ok(true);
        }
        if let Some(dir) = dir_for_key(key.code) {
            game.steer(dir);
        }
    }
    Ok(false)
}

fn is_quit_key(code: KeyCode, modifiers: KeyModifiers) -> bool {
    matches!(code, KeyCode::Esc | KeyCode::Char('q' | 'Q'))
        || (modifiers.contains(KeyModifiers::CONTROL) && matches!(code, KeyCode::Char('c' | 'C')))
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "only the arrow/WASD keys steer a light-cycle; crossterm's KeyCode has ~20 other \
              variants (function keys, media keys, ...) irrelevant to this game"
)]
fn dir_for_key(code: KeyCode) -> Option<Dir> {
    match code {
        KeyCode::Up | KeyCode::Char('w' | 'W') => Some(Dir::Up),
        KeyCode::Down | KeyCode::Char('s' | 'S') => Some(Dir::Down),
        KeyCode::Left | KeyCode::Char('a' | 'A') => Some(Dir::Left),
        KeyCode::Right | KeyCode::Char('d' | 'D') => Some(Dir::Right),
        _ => None,
    }
}
