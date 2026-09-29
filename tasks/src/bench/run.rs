//! The run itself: the cells, the rows they produce, the table and the JSON.
//! Behind the `bench` feature with the cells, so a default build of the
//! runner carries only the CLI surface.

use std::time::Duration;

use fofoca_iroh_webrtc_transport::bench;

use crate::TaskOutcome;
use crate::util::wasm;
use crate::util::{output, repo_root};

use super::web::Engine::{Chrome, Safari};
use super::{Args, Cell, Direction, native, serve, wanted, web};

impl Direction {
    pub(crate) fn protocol(self) -> bench::Direction {
        match self {
            Self::Down => bench::Direction::Download,
            Self::Up => bench::Direction::Upload,
            Self::Both => bench::Direction::Both,
        }
    }
}

impl Cell {
    pub(crate) fn expected_path(self) -> &'static str {
        match self {
            Self::FofocaChromeChrome
            | Self::FofocaChromeNative
            | Self::FofocaSafariNative
            | Self::FofocaSafariChrome
            | Self::FofocaNativeNativeWebRtc => "webrtc",
            Self::FofocaNativeNative | Self::IrohNativeNative => "ip",
            Self::RawChromeChrome | Self::RawChromeChromeDatagram => "data-channel",
        }
    }

    pub(crate) fn needs_browser(self) -> bool {
        !matches!(
            self,
            Self::FofocaNativeNative | Self::FofocaNativeNativeWebRtc | Self::IrohNativeNative
        )
    }
}

/// One transfer as the receiving side timed it.
pub(crate) struct Sample {
    pub(crate) bytes: usize,
    pub(crate) elapsed_ms: f64,
    /// `webrtc`, `ip`, `data-channel` or `other` — what carried it.
    pub(crate) path: String,
}

impl Sample {
    /// Decimal megabits per second, the network convention.
    fn mbit_per_s(&self) -> f64 {
        // Lossless below 2^53 bytes, which is 8 PiB past the 64 MiB ceiling.
        #[expect(clippy::cast_precision_loss, reason = "bounded by MAX_TRANSFER_BYTES")]
        let bits = (self.bytes * 8) as f64;
        (bits / 1_000_000.0) / (self.elapsed_ms / 1000.0)
    }
}

/// A cell's samples, warm-up already dropped, all on one path.
pub(crate) struct Measured {
    pub(crate) negotiate_ms: f64,
    pub(crate) path: String,
    pub(crate) rounds: Vec<Sample>,
}

impl Measured {
    fn median_mbit_per_s(&self) -> f64 {
        let mut rates: Vec<f64> = self.rounds.iter().map(Sample::mbit_per_s).collect();
        median(&mut rates)
    }

    /// The first sample is the warm-up and is discarded; every remaining one
    /// must have crossed the same path, or the cell measured two things.
    pub(crate) fn from_samples(negotiate_ms: f64, mut rounds: Vec<Sample>) -> Result<Self, String> {
        if rounds.len() < 2 {
            return Err("fewer than two samples: nothing left after the warm-up".to_owned());
        }
        rounds.remove(0);
        let path = rounds[0].path.clone();
        if rounds.iter().any(|sample| sample.path != path) {
            return Err(format!(
                "rounds crossed different paths: {:?}",
                rounds.iter().map(|sample| &sample.path).collect::<Vec<_>>()
            ));
        }
        Ok(Self {
            negotiate_ms,
            path,
            rounds,
        })
    }
}

pub(crate) enum Outcome {
    Ok(Measured),
    Skipped(String),
    Failed(String),
}

/// A transfer is bounded by this: an 8 `MiB` round at a slow cell's
/// 100 Mbit/s takes seconds, and `both` doubles it. A stall is indefinite,
/// so generous costs only wall clock.
pub(crate) const TRANSFER_TIMEOUT: Duration = Duration::from_mins(2);

impl From<Result<Measured, String>> for Outcome {
    fn from(result: Result<Measured, String>) -> Self {
        match result {
            Ok(measured) => Self::Ok(measured),
            Err(reason) => Self::Failed(reason),
        }
    }
}

impl From<crate::util::Skip> for Outcome {
    fn from(crate::util::Skip(reason): crate::util::Skip) -> Self {
        Self::Skipped(reason)
    }
}

struct Row {
    cell: Cell,
    outcome: Outcome,
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        f64::midpoint(values[mid - 1], values[mid])
    } else {
        values[mid]
    }
}

/// The table's columns, in order. The numeric ones are right-aligned.
const COLUMNS: [(&str, bool); 8] = [
    ("cell", false),
    ("path", false),
    ("Mbit/s", true),
    ("min", true),
    ("max", true),
    ("ms/transfer", true),
    ("JSEP ms", true),
    ("result", false),
];

/// What a row says in each column: the numbers for a measured cell, `-` and
/// the reason for one that was skipped or failed.
struct Cells([String; 8]);

/// The pipe-delimited table, markdown-shaped so it pastes into
/// `docs/perf/benchmark.md` as it is. Widths come from the rows, so the
/// pipes line up whatever the reasons in the last column say.
fn table(rows: &[Row]) -> Vec<String> {
    let cells: Vec<Cells> = rows.iter().map(Row::cells).collect();
    let widths: Vec<usize> = COLUMNS
        .iter()
        .enumerate()
        .map(|(column, (name, _))| {
            cells
                .iter()
                .map(|row| row.0[column].chars().count())
                .chain(std::iter::once(name.chars().count()))
                .max()
                .unwrap_or_default()
        })
        .collect();
    let line = |values: &[String]| -> String {
        let padded: Vec<String> = values
            .iter()
            .zip(&widths)
            .zip(COLUMNS)
            .map(|((value, width), (_, numeric))| {
                if numeric {
                    format!("{value:>width$}")
                } else {
                    format!("{value:<width$}")
                }
            })
            .collect();
        format!("| {} |", padded.join(" | "))
    };
    let separator: Vec<String> = widths
        .iter()
        .zip(COLUMNS)
        .map(|(width, (_, numeric))| {
            // Each cell is padded by one space on either side of the pipes.
            if numeric {
                format!("{}:", "-".repeat(width + 1))
            } else {
                "-".repeat(width + 2)
            }
        })
        .collect();
    let mut lines = vec![
        line(&COLUMNS.map(|(name, _)| name.to_owned())),
        format!("|{}|", separator.join("|")),
    ];
    lines.extend(cells.iter().map(|row| line(&row.0)));
    lines
}

impl Row {
    fn verdict(&self) -> String {
        match &self.outcome {
            Outcome::Ok(_) if self.passed() => "ok".to_owned(),
            Outcome::Ok(measured) => format!(
                "WRONG PATH: {} carried it, expected {}",
                measured.path,
                self.cell.expected_path()
            ),
            Outcome::Skipped(reason) => format!("skipped: {reason}"),
            Outcome::Failed(reason) => format!("FAILED: {reason}"),
        }
    }

    /// The one number the progress list shows.
    fn headline(&self) -> String {
        match &self.outcome {
            Outcome::Ok(measured) if self.passed() => {
                format!("{:.0} Mbit/s", measured.median_mbit_per_s())
            }
            Outcome::Ok(_) | Outcome::Skipped(_) | Outcome::Failed(_) => self.verdict(),
        }
    }

    fn cells(&self) -> Cells {
        let label = self.cell.label().to_owned();
        let Outcome::Ok(measured) = &self.outcome else {
            let dash = || "-".to_owned();
            return Cells([
                label,
                dash(),
                dash(),
                dash(),
                dash(),
                dash(),
                dash(),
                self.verdict(),
            ]);
        };
        let rates: Vec<f64> = measured.rounds.iter().map(Sample::mbit_per_s).collect();
        let mut elapsed: Vec<f64> = measured
            .rounds
            .iter()
            .map(|sample| sample.elapsed_ms)
            .collect();
        let min = rates.iter().copied().fold(f64::INFINITY, f64::min);
        let max = rates.iter().copied().fold(0.0, f64::max);
        Cells([
            label,
            measured.path.clone(),
            format!("{:.0}", measured.median_mbit_per_s()),
            format!("{min:.0}"),
            format!("{max:.0}"),
            format!("{:.0}", median(&mut elapsed)),
            format!("{:.0}", measured.negotiate_ms),
            self.verdict(),
        ])
    }

    fn passed(&self) -> bool {
        match &self.outcome {
            Outcome::Ok(measured) => measured.path == self.cell.expected_path(),
            Outcome::Skipped(_) => true,
            Outcome::Failed(_) => false,
        }
    }

    fn json(&self) -> serde_json::Value {
        let (status, detail, samples, path, negotiate_ms) = match &self.outcome {
            Outcome::Ok(measured) => (
                if self.passed() { "ok" } else { "wrong-path" },
                String::new(),
                measured
                    .rounds
                    .iter()
                    .map(|sample| {
                        serde_json::json!({
                            "bytes": sample.bytes,
                            "elapsed_ms": sample.elapsed_ms,
                            "mbit_per_s": sample.mbit_per_s(),
                        })
                    })
                    .collect(),
                measured.path.clone(),
                Some(measured.negotiate_ms),
            ),
            Outcome::Skipped(reason) => {
                ("skipped", reason.clone(), Vec::new(), String::new(), None)
            }
            Outcome::Failed(reason) => ("failed", reason.clone(), Vec::new(), String::new(), None),
        };
        serde_json::json!({
            "cell": self.cell.label(),
            "expected_path": self.cell.expected_path(),
            "path": path,
            "status": status,
            "detail": detail,
            "negotiate_ms": negotiate_ms,
            "rounds": samples,
        })
    }
}

pub(crate) fn run(args: &Args) -> TaskOutcome {
    let cells = wanted(args);
    if args.bytes > bench::MAX_TRANSFER_BYTES {
        return Err(format!(
            "--bytes {} is past the protocol's {} byte ceiling",
            args.bytes,
            bench::MAX_TRANSFER_BYTES
        )
        .into());
    }

    // The page is built and served once, and only when a browser cell is in
    // the run: `--only native` must not pay for a wasm build nobody loads.
    let server = if cells.iter().any(|cell| cell.needs_browser()) {
        wasm::check_wasm_bindgen()?;
        let env = wasm::wasm_env()?;
        output::status("Building", "the browser side (fofoca-bench-wasm)");
        let wasm_dir = repo_root().join("target/bench-wasm");
        let glue = wasm::build_wasm_cdylib("fofoca-bench-wasm", &env, &wasm_dir)?;
        output::detail(&format!("             {}", glue.display()));
        let www = repo_root().join("crates/fofoca-bench-wasm/www");
        let server = serve::Static::serve(www, wasm_dir)?;
        output::status("Serving", &server.url);
        Some(server)
    } else {
        None
    };

    if cfg!(debug_assertions) {
        output::caution(
            "debug",
            "an unoptimised build of the runner: the native cells measure the dev profile",
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no tokio runtime: {error}"))?;

    output::status(
        "Benchmark",
        &format!(
            "{} bytes × {} rounds (+1 warm-up), {}",
            args.bytes,
            args.rounds,
            args.direction.protocol().label()
        ),
    );
    let mut rows = Vec::new();
    for cell in cells {
        output::status("Running", cell.label());
        let browser = || web::Browser {
            server: server.as_ref().expect("built above"),
            args,
        };
        let outcome = match cell {
            Cell::FofocaChromeChrome => browser().web_web(Chrome, Chrome, "index.html", None),
            Cell::FofocaSafariChrome => browser().web_web(Safari, Chrome, "index.html", None),
            Cell::RawChromeChrome | Cell::RawChromeChromeDatagram
                if args.direction != Direction::Down =>
            {
                Outcome::Skipped("the raw page only streams downloads".to_owned())
            }
            Cell::RawChromeChrome => browser().web_web(Chrome, Chrome, "raw.html", None),
            Cell::RawChromeChromeDatagram => {
                browser().web_web(Chrome, Chrome, "raw.html", Some(1200))
            }
            Cell::FofocaChromeNative => runtime.block_on(browser().web_native(Chrome)),
            Cell::FofocaSafariNative => runtime.block_on(browser().web_native(Safari)),
            Cell::FofocaNativeNative => runtime.block_on(native::fofoca_native_native(args)),
            Cell::FofocaNativeNativeWebRtc => {
                runtime.block_on(native::fofoca_native_native_webrtc(args))
            }
            Cell::IrohNativeNative => runtime.block_on(native::iroh_native_native(args)),
        };
        let row = Row { cell, outcome };
        let line = format!("{}  {}", row.cell.label(), row.headline());
        match &row.outcome {
            Outcome::Ok(_) if row.passed() => output::status("ok", &line),
            Outcome::Ok(_) | Outcome::Failed(_) => output::failure("FAILED", &line),
            Outcome::Skipped(_) => output::caution("skip", &line),
        }
        rows.push(row);
    }

    output::verbatim("");
    output::status(
        "Summary",
        &format!(
            "{} byte {}, {} timed rounds after 1 warm-up, medians over the timed rounds",
            args.bytes,
            args.direction.protocol().label(),
            args.rounds
        ),
    );
    output::verbatim("");
    for line in table(&rows) {
        output::verbatim(&line);
    }
    output::verbatim("");
    output::detail(
        "Mbit/s: median throughput of the timed rounds (decimal megabits). min/max: slowest and fastest round.",
    );
    output::detail(
        "ms/transfer: median wall time of one transfer. JSEP ms: the signaling round, outside the timed window.",
    );
    output::detail("path: what carried the bytes, checked against the cell's expectation.");

    if let Some(path) = &args.json {
        let dump = serde_json::json!({
            "bytes": args.bytes,
            "rounds": args.rounds,
            "direction": args.direction.protocol().label(),
            "rows": rows.iter().map(Row::json).collect::<Vec<_>>(),
        });
        std::fs::write(path, serde_json::to_string_pretty(&dump).expect("json"))
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        output::detail(&format!("json: {}", path.display()));
    }

    let bad = rows.iter().filter(|row| !row.passed()).count();
    if bad > 0 {
        return Err(format!("{bad} cell(s) did not pass").into());
    }
    Ok(())
}
