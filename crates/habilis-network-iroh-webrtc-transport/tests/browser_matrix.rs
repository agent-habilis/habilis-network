//! A configuration sweep for the browser↔browser bulk stall.
//!
//! `browser_loopback.rs` is the fast green-or-red regression suite. This is the
//! hunt: the same harness driven across every traffic shape worth trying, one
//! row per cell, and a table at the end whether it passes or not.
//!
//! ## Why a sweep and not more tests
//!
//! A consumer reported that browser↔browser channels pass small traffic and
//! freeze on bulk — a ~9 KB request/response round succeeds, the first 200 KB
//! read never answers — and that it is *intermittent per channel*: once a
//! channel stalls it stalls consistently, once one works it works. The
//! regression suite does not reproduce it. That is worth something, but not
//! much: the suite runs the easiest configuration that exists, and one passing
//! configuration is weak evidence about a bug that only some configurations
//! show.
//!
//! So the axes below are the distance between that easy case and the
//! consumer's. Cells are data rather than `#[wasm_bindgen_test]` functions, and
//! every cell runs even after one fails, because *which* cells fail is the
//! finding — "only at 16 concurrent", "only on upload" and "everywhere" are
//! three different bugs, and a suite that aborts on the first failure cannot
//! tell them apart.
//!
//! `cargo task e2e` runs this file once per browser, build profile and
//! main-thread pressure level; those axes need a fresh process, so they live
//! out there. Pressure is the one this most expects to break: in wasm the QUIC
//! driver and the outbound pump share a single JS task queue, and `poll_send`
//! drops into a 256-slot queue and reports success regardless, so a burst that
//! fills the queue before the pump is scheduled is silent loss.
//!
//! ## Reading the output
//!
//! Each row carries the drop counters split by route
//! (`queue`/`congested`/`refused`), so a cell that stalls says which of the
//! three silent-discard paths did it rather than leaving it to be inferred.
//! The table is written to the console *and* into the DOM, followed by a
//! `#matrix-done` element — `cargo task e2e` keys on that, which is what makes
//! a run scriptable over either CDP or `WebDriver`.

#![cfg(target_arch = "wasm32")]

mod browser_harness;

use std::time::Duration;

use browser_harness::{Direction, Pair};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

/// Payload ceiling in flight at once across a cell's concurrent transfers.
///
/// 8 `MiB` × 16 concurrent is 128 MB of payload plus as much again in read
/// buffers, and an OOM-killed tab is not a transport finding — it is a lost
/// run with no row to show for it. Cells over the budget are **skipped and
/// reported as skipped**, never silently dropped.
const MAX_BYTES_IN_FLIGHT: usize = 32 * MIB;

/// Deadline floor, plus an allowance per `MiB` in flight.
///
/// A fixed deadline cannot serve both a 64 `KiB` cell and an 8 `MiB` cell under
/// contention: tight enough to catch a stall in the first is far too tight for
/// the second, and reporting slowness as a stall would be the harness inventing
/// the bug it was built to find. A stall is *indefinite*, so being generous
/// costs only wall-clock on a cell that was going to fail anyway.
const DEADLINE_FLOOR: Duration = Duration::from_secs(20);
const DEADLINE_PER_MIB_MS: u64 = 4_000;

/// How many competing busy-loop tasks to run for the whole sweep, from the
/// query string (`?pressure=8`).
///
/// This is the *real* version of an axis that was briefly fake. The first
/// attempt drove Chrome's `Emulation.setCPUThrottlingRate` over CDP, which is
/// the right instrument and did nothing: the rate is scoped to the CDP session
/// that set it, the runner sets it with a one-shot call, and the connection
/// closes before the page navigates. Measured with a 200-task chain: 1234 ms
/// unthrottled, 1358 ms at a nominal 20×. Every "throttled" cell had in fact
/// run at full speed, and the summary was about to claim a whole axis of
/// coverage that never happened.
///
/// Contention created *inside* the page cannot lie about itself the same way —
/// and it works on any browser, including the ones with no CDP to reach for.
fn pressure_level() -> u64 {
    let Some(search) = web_sys::window().and_then(|window| window.location().search().ok()) else {
        return 0;
    };
    search
        .trim_start_matches('?')
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "pressure")
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .unwrap_or(0)
}

/// One point in the sweep.
#[derive(Debug, Clone, Copy)]
struct Cell {
    /// Bytes of bulk per transfer.
    size: usize,
    /// Transfers in flight at once, each over its own negotiated pair.
    concurrency: usize,
    direction: Direction,
    /// Exchanges to run over each pair. `1` is a fresh channel per transfer;
    /// more reuses the channel, which is the shape the consumer's mount
    /// protocol actually has.
    rounds: usize,
    /// One extra competing busy-loop task on top of whatever ambient pressure
    /// the run was started with, so a single run can show the effect of
    /// contention without needing a second one.
    pressure: bool,
}

impl Cell {
    const fn new(size: usize, concurrency: usize, direction: Direction) -> Self {
        Self {
            size,
            concurrency,
            direction,
            rounds: 1,
            pressure: false,
        }
    }

    const fn rounds(mut self, rounds: usize) -> Self {
        self.rounds = rounds;
        self
    }

    const fn under_pressure(mut self) -> Self {
        self.pressure = true;
        self
    }

    fn bytes_in_flight(&self) -> usize {
        self.direction.bytes_for(self.size) * self.concurrency
    }

    fn deadline(&self, pressure: u64) -> Duration {
        let mibs = u64::try_from(self.bytes_in_flight() / MIB).unwrap_or(u64::MAX);
        let budget = DEADLINE_FLOOR + Duration::from_millis(mibs * DEADLINE_PER_MIB_MS);
        // Every competing task is another share of the main thread the
        // transfer is not getting, so the budget grows with the crowd. A
        // deadline that ignored it would report the pressure as a stall, which
        // is the harness inventing the bug it was built to find.
        budget * u32::try_from(pressure + 1).unwrap_or(1)
    }

    fn size_label(&self) -> String {
        if self.size >= MIB {
            format!("{}M", self.size / MIB)
        } else {
            format!("{}K", self.size / KIB)
        }
    }
}

/// The sweep, as a fractional design rather than a full cross product.
///
/// 4 sizes × 3 concurrencies × 3 directions × 2 reuse × 2 pressure is 144
/// cells, and most of them would restate a neighbour. Grid A moves the two axes
/// most likely to matter together; Grid B moves one axis at a time off a
/// baseline. That is enough to *name* a failing axis, which is all the table
/// has to do — the follow-up run can go dense around whatever it names.
fn cells(pressure: u64) -> Vec<Cell> {
    let mut cells = Vec::new();

    // Grid A — size × concurrency, at the `OP_READ` shape.
    // 200 KiB is not a round number by accident: it is the exact size of the
    // file whose first read never answered.
    //
    // The 8 `MiB` row is dropped once the page is under pressure, and that is a
    // measurement, not a guess: at pressure 8 the full grid takes ~290 s
    // against ~28 s at rest, and the 8 `MiB` cells are most of the difference —
    // 34 `MiB` in flight, moving at a twentieth of the speed. They have never
    // once failed where 1 `MiB` passed, so what they buy under pressure is five
    // minutes of watching a number get bigger.
    let (sizes, concurrencies): (&[usize], &[usize]) = if pressure == 0 {
        (&[64 * KIB, 200 * KIB, MIB, 8 * MIB], &[1, 4, 16])
    } else {
        (&[200 * KIB, MIB], &[1, 4])
    };
    for &size in sizes {
        for &concurrency in concurrencies {
            cells.push(Cell::new(size, concurrency, Direction::Download));
        }
    }

    // Grid B — one axis at a time off 1 MiB / ×1 / download / fresh / calm.
    // Only at rest: every one of these varies a *shape*, and asking the same
    // shape question again with the main thread starved measures the
    // starvation, not the shape.
    if pressure > 0 {
        return cells;
    }
    cells.push(Cell::new(MIB, 1, Direction::Upload));
    cells.push(Cell::new(MIB, 1, Direction::Both));
    cells.push(Cell::new(MIB, 1, Direction::Download).rounds(10));
    cells.push(Cell::new(MIB, 1, Direction::Download).under_pressure());
    cells.push(Cell::new(MIB, 4, Direction::Download).under_pressure());

    cells
}

/// What one cell did.
#[derive(Debug)]
enum Verdict {
    Ok,
    /// Over budget — see [`MAX_BYTES_IN_FLIGHT`].
    Skipped(String),
    Failed(String),
}

impl Verdict {
    fn tag(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Skipped(_) => "skip",
            Self::Failed(_) => "FAIL",
        }
    }
}

struct Row {
    cell: Cell,
    verdict: Verdict,
    /// Both of these stay `f64` all the way to the format string. They come
    /// from `Date::now` and `getStats`, which are `f64` at the source, and
    /// casting them to an integer to print them would be inventing a precision
    /// claim the browser never made.
    elapsed_ms: f64,
    /// Data-channel bytes that crossed during the cell, summed over its pairs.
    ///
    /// `None` is "the browser never gave us a settled reading", **not** zero.
    /// Rendering an unobserved counter as `0` in a table built to hunt a stall
    /// would put the hunted signature in front of the reader as a sampling
    /// artefact — see `Pair::channel_bytes_settled`.
    received: Option<f64>,
    /// Outbound drops, summed over the cell's pairs, split by route.
    drops: (u64, u64, u64),
}

impl Row {
    fn render(&self) -> String {
        let (queue, congested, refused) = self.drops;
        let received = self
            .received
            .map_or_else(|| "?".to_owned(), |bytes| format!("{bytes:.0}"));
        format!(
            "{:>5} {:>4} {:>5} {:>7} {:>5} | {:<4} {:>7.0}ms {received:>12} rx  drops q={queue} c={congested} r={refused}",
            self.cell.size_label(),
            format!("x{}", self.cell.concurrency),
            self.cell.direction.label(),
            if self.cell.rounds > 1 {
                format!("reuse{}", self.cell.rounds)
            } else {
                "fresh".to_owned()
            },
            if self.cell.pressure { "busy" } else { "-" },
            self.verdict.tag(),
            self.elapsed_ms,
        )
    }
}

/// Block the JS task queue in bursts for as long as the guard is held.
///
/// Not a thread — wasm has one — so this is a self-rescheduling task that burns
/// a slice of wall clock, yields, and repeats. Yielding matters: a loop that
/// never gave the queue back would deadlock the transfer it is meant to
/// pressure, and prove nothing.
struct Pressure {
    stop: std::rc::Rc<std::cell::Cell<bool>>,
}

impl Pressure {
    fn apply() -> Self {
        let stop = std::rc::Rc::new(std::cell::Cell::new(false));
        let flag = std::rc::Rc::clone(&stop);
        wasm_bindgen_futures::spawn_local(async move {
            while !flag.get() {
                let until = js_sys::Date::now() + 12.0;
                while js_sys::Date::now() < until {
                    // Spin. `Date::now` is the only clock a browser hands us
                    // that does not require a feature we have not enabled.
                }
                n0_future::time::sleep(Duration::from_millis(1)).await;
            }
        });
        Self { stop }
    }
}

impl Drop for Pressure {
    fn drop(&mut self) {
        self.stop.set(true);
    }
}

/// Run one cell: negotiate its pairs, run every round, total the counters.
async fn run_cell(cell: Cell, pressure: u64) -> (Verdict, Option<f64>, (u64, u64, u64)) {
    if cell.bytes_in_flight() > MAX_BYTES_IN_FLIGHT {
        return (
            Verdict::Skipped(format!(
                "{} bytes in flight is over the {MAX_BYTES_IN_FLIGHT} budget",
                cell.bytes_in_flight()
            )),
            None,
            (0, 0, 0),
        );
    }

    let mut pairs = Vec::new();
    for index in 0..cell.concurrency {
        match Pair::negotiate().await {
            Ok(pair) => pairs.push(pair),
            Err(error) => {
                return (
                    Verdict::Failed(format!("pair {index} failed to negotiate: {error}")),
                    None,
                    (0, 0, 0),
                );
            }
        }
    }

    // Freshly negotiated pairs have carried nothing, so the baseline is zero by
    // construction. Reading it anyway would only invite the same
    // not-yet-published artefact the settled read exists to avoid, at the wrong
    // end of the subtraction.
    // Held across the transfers, released before the counters are read, so the
    // reads themselves are not fighting the busy loop for the queue. Named
    // apart from the `pressure` parameter, which is the run-wide level this
    // one cell adds to.
    let extra_pressure = cell.pressure.then(Pressure::apply);

    let mut failures = Vec::new();
    for round in 0..cell.rounds {
        let outcomes: Vec<_> = futures::future::join_all(
            pairs
                .iter()
                .map(|pair| pair.exchange(cell.direction, cell.size, cell.deadline(pressure))),
        )
        .await;
        for (index, outcome) in outcomes.iter().enumerate() {
            if let Err(error) = outcome {
                failures.push(format!("round {round} pair {index}: {error}"));
            }
        }
        // A stalled channel stays stalled, per the original report, so the
        // remaining rounds would only restate the failure at the cost of a
        // deadline each.
        if !failures.is_empty() {
            break;
        }
    }

    drop(extra_pressure);

    // `None` from any pair makes the cell's total unobserved rather than
    // partial: a sum missing one pair's contribution is a number that looks
    // authoritative and is not.
    let mut received = Some(0.0);
    let mut drops = (0u64, 0u64, 0u64);
    for pair in &pairs {
        match (received, pair.channel_bytes_settled().await) {
            (Some(total), Some((_, bytes))) => received = Some(total + bytes),
            _ => received = None,
        }
        if let Some(counts) = pair.client_hub.session_counters(&pair.server_id) {
            drops.0 += counts.dropped_queue_full;
            drops.1 += counts.dropped_congested;
            drops.2 += counts.dropped_refused;
        }
    }

    let verdict = if failures.is_empty() {
        Verdict::Ok
    } else {
        Verdict::Failed(failures.join("\n    "))
    };

    for pair in pairs {
        pair.shutdown().await;
    }
    (verdict, received, drops)
}

fn log(line: &str) {
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(line));
}

/// Publish the table to the DOM so a CDP driver can wait on it and read it.
///
/// `cargo task e2e` waits on `#matrix-done` rather than polling `innerText` for
/// a substring, so the signal is unambiguous: the element exists only once
/// every cell has a row.
fn publish(table: &str, failed: usize) {
    let Some(document) = web_sys::window().and_then(|window| window.document()) else {
        return;
    };
    let Some(body) = document.body() else {
        return;
    };
    if let Ok(pre) = document.create_element("pre") {
        pre.set_id("matrix-table");
        pre.set_text_content(Some(table));
        let _ = body.append_child(&pre);
    }
    if let Ok(marker) = document.create_element("div") {
        marker.set_id("matrix-done");
        // The count as an attribute, so a driver can branch on it without
        // parsing the table it just waited for.
        let _ = marker.set_attribute("data-failed", &failed.to_string());
        let _ = body.append_child(&marker);
    }
}

/// The column header, shared by the streamed rows and the final table so the
/// two are obviously the same shape.
fn header_row() -> String {
    format!(
        "{:>5} {:>4} {:>5} {:>7} {:>5} | {:<4} {:>9} {:>15}  {}",
        "size", "conc", "dir", "chan", "press", "res", "elapsed", "received", "drops"
    )
}

#[wasm_bindgen_test]
async fn sweep() {
    let pressure = pressure_level();
    let cells = cells(pressure);
    let mut rows = Vec::new();

    // Held for the whole sweep, so every cell in this run competes with the
    // same crowd. Per-cell pressure (Grid B) adds one more on top.
    let _ambient: Vec<Pressure> = (0..pressure).map(|_| Pressure::apply()).collect();

    log(&format!(
        "[matrix] streaming {} cells against {pressure} competing task(s)",
        cells.len()
    ));
    log(&format!("[matrix] {}", header_row()));
    for cell in cells {
        let started = js_sys::Date::now();
        let (verdict, received, drops) = run_cell(cell, pressure).await;
        let elapsed_ms = js_sys::Date::now() - started;
        let row = Row {
            cell,
            verdict,
            elapsed_ms,
            received,
            drops,
        };
        // Streamed as well as tabulated: a run that dies partway (an OOM, a
        // browser crash) still leaves everything it learned in the console.
        log(&format!("[matrix] {}", row.render()));
        rows.push(row);
    }

    let mut table = vec![header_row()];
    table.extend(rows.iter().map(Row::render));

    let detail: Vec<String> = rows
        .iter()
        .filter_map(|row| match &row.verdict {
            Verdict::Ok => None,
            Verdict::Skipped(why) => Some(format!("  skip {}: {why}", row.cell.size_label())),
            Verdict::Failed(why) => Some(format!(
                "  FAIL {} x{} {}:\n    {why}",
                row.cell.size_label(),
                row.cell.concurrency,
                row.cell.direction.label()
            )),
        })
        .collect();
    if !detail.is_empty() {
        table.push(String::new());
        table.extend(detail);
    }

    let failed = rows
        .iter()
        .filter(|row| matches!(row.verdict, Verdict::Failed(_)))
        .count();
    let skipped = rows
        .iter()
        .filter(|row| matches!(row.verdict, Verdict::Skipped(_)))
        .count();
    table.push(format!(
        "\n{} cells at pressure {pressure}: {} ok, {failed} failed, {skipped} skipped",
        rows.len(),
        rows.len() - failed - skipped,
    ));

    let table = table.join("\n");
    log(&table);
    publish(&table, failed);

    assert_eq!(failed, 0, "\n{table}");
}
