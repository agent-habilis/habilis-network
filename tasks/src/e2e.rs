//! `cargo task e2e` — drive the crate's browser tests against real browsers.
//!
//! The sweep inside the page varies traffic shape; this varies everything that
//! needs a fresh process. It exists because the browser↔browser bulk stall a
//! consumer reported does not reproduce in the one configuration the fast suite
//! runs, and one passing configuration says very little about a bug that only
//! some configurations show.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args as ClapArgs, ValueEnum};

use crate::TaskOutcome;
use crate::util::webdriver::{Driver, SAFARI_TP};
use crate::util::{Skip, json_to_string, output};

pub(crate) mod build;
mod cdp;
#[cfg(feature = "mesh")]
mod chat;
mod loopback;
#[cfg(feature = "mesh")]
mod mesh;
#[cfg(feature = "mesh")]
mod multihop;
#[cfg(feature = "mesh")]
mod page;
mod server;
#[cfg(feature = "mesh")]
mod stream;
mod webdriver;

use server::Harness;

/// A sweep at pressure 8 is ~20× slower than at rest, so this is generous. A
/// stall is *indefinite*, so being generous costs only wall-clock on a cell
/// that was going to fail anyway.
const CELL_TIMEOUT: Duration = Duration::from_mins(30);

/// What the page publishes when every cell has a row, and how to read it back.
///
/// The CDP backend evaluates an expression; `WebDriver` runs a function body and
/// needs an explicit `return`. Same three questions either way.
const DONE_SELECTOR: &str = "#matrix-done";
const DONE_EXPRESSION: &str = r#"return document.getElementById("matrix-done") ? "1" : "0";"#;
const TABLE_EXPRESSION: &str =
    r#"(document.getElementById("matrix-table")||{}).textContent||document.body.innerText"#;
const FAILED_EXPRESSION: &str =
    r#"((document.getElementById("matrix-done")||{}).dataset||{}).failed||"?""#;
const TABLE_SCRIPT: &str = r#"var t=document.getElementById("matrix-table");return t?t.textContent:document.body.innerText;"#;
const FAILED_SCRIPT: &str =
    r#"var m=document.getElementById("matrix-done");return m?m.dataset.failed:"?";"#;

/// Every axis is filterable, and that is not a convenience.
///
/// The full sweep is three axes deep, and the two beyond `--only` are the
/// expensive ones: each profile is its own wasm rebuild, and pressure 8 makes a
/// 25-second sweep take eight minutes. Without `--profile` and `--pressure`,
/// the smallest thing anyone could run while *changing* the runner was one
/// browser × two builds × two pressure levels — about fifteen minutes to find
/// out a flag was misspelled. `--quick` is the same idea with one name.
#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Only browsers whose name contains this (e.g. `cft`, `chrome`, `safari`).
    /// The suites that drive one tab (`stream`, `chat`, `mesh`) take the first
    /// match, so name one browser there: `cft`, `chrome-ci`, `chrome-151`,
    /// `safari`, `safari-tp`. Without it they open `safari-tp`.
    #[arg(long)]
    only: Option<String>,
    /// Only this build profile (`release`, `release-slow`). Each one is a
    /// separate wasm build and a separate sweep.
    #[arg(long)]
    profile: Option<Profile>,
    /// Sweep every build profile, not just `release` — see `DEFAULT_PROFILES`
    /// for why the slow one is not in the default run.
    #[arg(long)]
    all_profiles: bool,
    /// Only this main-thread pressure level (`0`, `2`, `8`). Repeatable.
    #[arg(long)]
    pressure: Vec<u32>,
    /// The shortest useful run: `release`, pressure 0, one browser's worth of
    /// cells. What to reach for when the thing under test is the runner.
    #[arg(long)]
    quick: bool,
    /// List the cells that would run — and the ones that would not, with why —
    /// without building or launching anything.
    #[arg(long)]
    list: bool,
    /// Which suite to drive.
    #[arg(long, value_enum, default_value_t = Suite::Matrix)]
    suite: Suite,
}

impl Args {
    /// The one browser a suite that drives a single tab opens: `--only`, or
    /// Safari Technology Preview, the next `WebKit`, where a browser-only
    /// regression shows first.
    #[cfg(feature = "mesh")]
    fn page_browser(&self) -> &str {
        self.only.as_deref().unwrap_or("safari-tp")
    }

    fn profiles(&self) -> Vec<Profile> {
        if self.quick {
            return vec![Profile::Release];
        }
        if self.all_profiles {
            return PROFILES.to_vec();
        }
        self.profile
            .map_or_else(|| DEFAULT_PROFILES.to_vec(), |profile| vec![profile])
    }

    fn wants_pressure(&self, pressure: u32) -> bool {
        if self.quick {
            return pressure == 0;
        }
        self.pressure.is_empty() || self.pressure.contains(&pressure)
    }
}

/// Both suites need the identical, easily-forgotten preamble, which is most of
/// the reason this runner exists — so both are reachable through it. How they
/// are *driven* differs, because they report differently: see `loopback::run`.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Suite {
    /// The configuration sweep: every traffic shape, one row per cell.
    Matrix,
    /// The fast four-test regression suite, on one browser.
    Loopback,
    /// The native↔browser matrix: a real native peer, a real tab, a local
    /// relay, swept over the relay-transport policy, the native transport
    /// set and the join mode.
    Mesh,
    /// The chat example end to end: the native terminal chat in robot mode
    /// against the browser chat page, over a local relay.
    Chat,
    /// A stream end to end: the `habilis-network-stream` CLI against the stream web
    /// page, over a local relay: bytes in on one side, the same bytes out on
    /// the other, each side as producer once.
    Stream,
    /// A tab reached through a native hop: two native peers and a tab on one mesh with
    /// `multihop`, the tab and one native refused a direct session, so that their messages
    /// have to cross the other native.
    Multihop,
}

/// Which wasm build a cell runs.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Profile {
    Release,
    /// `opt-level=1`. See `build::build` for why this is not the debug build.
    ReleaseSlow,
}

impl fmt::Display for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Release => "release",
            Self::ReleaseSlow => "release-slow",
        })
    }
}

/// What a bare `cargo task e2e` sweeps.
///
/// `release` only, and that is a cut made on evidence: `release-slow` is a
/// second full wasm build and a second full sweep — 37% of the wall clock — and
/// across every run of this matrix it has produced results identical to
/// `release`, cell for cell. An axis that has never once differentiated
/// anything does not belong in the run people actually wait for. It stays
/// reachable with `--profile release-slow` for the day that changes.
const DEFAULT_PROFILES: [Profile; 1] = [Profile::Release];
const PROFILES: [Profile; 2] = [Profile::Release, Profile::ReleaseSlow];

/// How a browser is driven.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Backend {
    Cdp,
    WebDriver,
}

struct Browser {
    name: &'static str,
    backend: Backend,
    /// Checked before anything is built, so a browser that is not installed is
    /// a reported skip rather than a crash halfway through a sweep.
    binary: String,
    /// Main-thread pressure levels: how many competing busy-loop tasks the page
    /// runs against itself for the whole sweep.
    ///
    /// Swept on the control browser only. Sweeping it everywhere would multiply
    /// the run for cells whose value is browser diversity, not load.
    ///
    /// It is *in-page* contention, not Chrome's `Emulation.setCPUThrottlingRate`.
    /// That was tried first and silently did nothing: the rate is scoped to the
    /// CDP session that set it, and the backend then opened a new session per
    /// call, which closed before the page navigated. Measured with a 200-task chain:
    /// 1234 ms unthrottled, 1358 ms at a nominal 20×. Eight cells had reported
    /// a throttle axis they never ran.
    pressures: &'static [u32],
}

fn browsers() -> Vec<Browser> {
    vec![
        Browser {
            name: "chrome-cft",
            backend: Backend::Cdp,
            // Resolved (and downloaded on first use) by `cdp::chrome_for_testing`.
            binary: String::new(),
            pressures: &[0, 2, 8],
        },
        Browser {
            name: "chrome-151",
            backend: Backend::WebDriver,
            binary: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_owned(),
            // Pressure 0 only. This cell's question is "does the Chrome version
            // matter"; "does pressure break it" is already `chrome-cft`'s p8
            // cell on the same engine two versions apart. Asking it twice cost
            // ~110 s and has never yet answered differently.
            pressures: &[0],
        },
        // Any Chrome, driven through chromedriver.
        // `CHROME_BIN` and `CHROMEDRIVER` name the two binaries.
        Browser {
            name: "chrome-ci",
            backend: Backend::WebDriver,
            binary: std::env::var("CHROME_BIN").unwrap_or_default(),
            pressures: &[0],
        },
        Browser {
            name: "safari",
            backend: Backend::WebDriver,
            binary: "/Applications/Safari.app/Contents/MacOS/Safari".to_owned(),
            pressures: &[0],
        },
        // The next WebKit, driven by its own safaridriver, which needs its own
        // `sudo … safaridriver --enable` once.
        Browser {
            name: "safari-tp",
            backend: Backend::WebDriver,
            binary: SAFARI_TP.to_owned(),
            pressures: &[0],
        },
    ]
}

/// What a cell's page published.
struct Harvest {
    /// The rendered results table.
    table: String,
    /// `data-failed` off `#matrix-done`; `None` when it never appeared.
    failed: Option<u32>,
    /// Read back from the browser, never from the name we gave it. The label is
    /// our intent; this is what actually ran, and when they disagree the second
    /// one is the finding.
    version: String,
    /// False when `#matrix-done` never appeared — a timeout, not a verdict.
    published: bool,
}

enum Verdict {
    Ok,
    Skipped,
    /// The count lives in `Row::detail` beside the browser version, where a
    /// reader needs both together; carrying it here too would be a second copy
    /// to keep in step.
    Failed,
    Timeout,
}

struct Row {
    browser: &'static str,
    profile: String,
    pressure: String,
    verdict: Verdict,
    detail: String,
}

impl Row {
    fn label(&self) -> String {
        format!(
            "{:<14} {:<13} {:>5}",
            self.browser, self.profile, self.pressure
        )
    }
}

/// The mesh and chat suites, which need the engine (`--features mesh`).
#[cfg(feature = "mesh")]
fn run_engine_suite(args: &Args) -> TaskOutcome {
    if !args.list {
        build::check_tooling()?;
    }
    match args.suite {
        Suite::Mesh => mesh::run(args),
        Suite::Multihop => multihop::run(args),
        Suite::Stream => stream::run(args),
        Suite::Chat | Suite::Matrix | Suite::Loopback => chat::run(args),
    }
}

/// Without the feature the suites are not compiled in, so re-run this same
/// invocation through cargo with it on. Only this path pays for the engine
/// build; a plain `--workspace` build never sees `iroh-test-utils`.
#[cfg(not(feature = "mesh"))]
fn run_engine_suite(_: &Args) -> TaskOutcome {
    crate::util::reexec_with_feature("mesh", "the engine suites", false)
}

pub(crate) fn run(args: &Args) -> TaskOutcome {
    if matches!(
        args.suite,
        Suite::Mesh | Suite::Chat | Suite::Stream | Suite::Multihop
    ) {
        return run_engine_suite(args);
    }

    let env = if args.list {
        BTreeMap::new()
    } else {
        crate::util::wasm::wasm_env()?
    };
    if !args.list {
        build::check_tooling()?;
    }

    // The fast suite reports per-test through the runner rather than through a
    // published table, so it takes its own path and returns here.
    if args.suite == Suite::Loopback {
        let chrome = crate::util::cdp::chrome_for_testing().map_err(|Skip(why)| why)?;
        return loopback::run(&chrome.to_string_lossy(), &env);
    }

    let mut rows = Vec::new();
    // Resolved once and only when a cell will run: the lookup can download
    // Chrome for Testing, and `--list` must launch and fetch nothing.
    let mut chrome_for_testing: Option<Result<PathBuf, String>> = None;

    for profile in args.profiles() {
        // Built lazily and once per profile: a `--only` that matches nothing in
        // this profile should not pay for a wasm nobody runs.
        let mut wasm: Option<PathBuf> = None;

        for browser in browsers() {
            if args
                .only
                .as_ref()
                .is_some_and(|filter| !browser.name.contains(filter.as_str()))
            {
                continue;
            }

            let missing = match browser.backend {
                Backend::Cdp if args.list => None,
                Backend::Cdp => chrome_for_testing
                    .get_or_insert_with(|| {
                        crate::util::cdp::chrome_for_testing().map_err(|Skip(why)| why)
                    })
                    .clone()
                    .err(),
                Backend::WebDriver => (!PathBuf::from(&browser.binary).exists())
                    .then(|| format!("not installed: {}", browser.binary)),
            };
            if let Some(detail) = missing {
                rows.push(Row {
                    browser: browser.name,
                    profile: profile.to_string(),
                    pressure: "-".to_owned(),
                    verdict: Verdict::Skipped,
                    detail,
                });
                continue;
            }

            for &pressure in browser.pressures {
                if !args.wants_pressure(pressure) {
                    continue;
                }
                let base = (browser.name, profile.to_string(), format!("p{pressure}"));

                if args.list {
                    rows.push(Row {
                        browser: base.0,
                        profile: base.1,
                        pressure: base.2,
                        verdict: Verdict::Ok,
                        detail: "would run".to_owned(),
                    });
                    continue;
                }

                if wasm.is_none() {
                    let built = build::build("browser_matrix", profile, &env)?;
                    build::announce(profile, &built);
                    wasm = Some(built);
                }
                let artifact = wasm.clone().expect("just built above");

                output::status(
                    "Running",
                    &format!("{} / {profile} / pressure {pressure}", browser.name),
                );

                let outcome = run_cell(&browser, &artifact, pressure);
                rows.push(finish(base, outcome));
            }
        }
    }

    summarise(&rows, args.list);

    // A skipped cell is reported, never quietly folded into a pass: a matrix
    // that ran three of eight cells and printed "all green" is worse than no
    // matrix.
    let bad = rows
        .iter()
        .filter(|row| matches!(row.verdict, Verdict::Failed | Verdict::Timeout))
        .count();
    if bad > 0 {
        return Err(format!("{bad} cell(s) did not pass").into());
    }
    Ok(())
}

/// Serve the harness, drive one browser through it, tear both down.
fn run_cell(browser: &Browser, wasm: &Path, pressure: u32) -> Result<Harvest, Skip> {
    // Held for the cell's lifetime and dropped on every exit path, so a failed
    // cell cannot leave :8000 occupied for the next one.
    let _harness = Harness::serve(wasm).map_err(Skip)?;

    match browser.backend {
        Backend::Cdp => cdp::run(pressure, CELL_TIMEOUT),
        Backend::WebDriver => {
            let driver = Driver::start(browser.name)?;
            webdriver::run(
                &driver,
                browser.name,
                &browser.binary,
                pressure,
                CELL_TIMEOUT,
            )
        }
    }
}

fn finish(
    (browser, profile, pressure): (&'static str, String, String),
    outcome: Result<Harvest, Skip>,
) -> Row {
    let harvest = match outcome {
        Ok(harvest) => harvest,
        Err(Skip(reason)) => {
            output::caution("Skipping", &reason);
            return Row {
                browser,
                profile,
                pressure,
                verdict: Verdict::Skipped,
                detail: reason,
            };
        }
    };

    if !harvest.table.is_empty() {
        output::verbatim(&harvest.table);
    }

    let (verdict, detail) = match (harvest.published, harvest.failed) {
        (false, _) => (
            Verdict::Timeout,
            format!("{} — never published {DONE_SELECTOR}", harvest.version),
        ),
        (true, Some(0)) => (Verdict::Ok, harvest.version),
        (true, Some(failed)) => (
            Verdict::Failed,
            format!("{failed} cell(s) — {}", harvest.version),
        ),
        // Published, but the count did not parse — failed, not passed: an
        // unreadable verdict is not a green one.
        (true, None) => (
            Verdict::Failed,
            format!("unreadable failure count — {}", harvest.version),
        ),
    };
    Row {
        browser,
        profile,
        pressure,
        verdict,
        detail,
    }
}

fn summarise(rows: &[Row], listing: bool) {
    output::verbatim("");
    output::status(
        "Summary",
        if listing {
            "cells that would run"
        } else {
            "matrix"
        },
    );
    output::verbatim(&format!(
        "{:<14} {:<13} {:>5}  {}",
        "browser", "profile", "press", "result"
    ));
    for row in rows {
        if listing {
            output::verbatim(&format!("{}  {}", row.label(), row.detail));
            continue;
        }
        let line = format!("{}  {}", row.label(), row.detail);
        match row.verdict {
            Verdict::Ok => output::status("ok", &line),
            Verdict::Skipped => output::caution("skip", &line),
            Verdict::Failed => output::failure("FAILED", &line),
            Verdict::Timeout => output::failure("TIMEOUT", &line),
        }
    }
}

/// `data-failed` as a number, or `None` when the page never published one.
fn normalise_failed(raw: &str) -> Option<u32> {
    raw.trim().parse().ok()
}
