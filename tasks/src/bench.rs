//! `cargo task benchmark` — bulk throughput over the transports.
//!
//! One question: is the iroh↔WebRTC integration the bottleneck? So the cells
//! are fofoca over WebRTC in every pairing that exists — browser↔browser,
//! browser↔native, native↔native — read against two ceilings: plain iroh on
//! UDP, and a bare data channel with no QUIC in it at all.
//!
//! Every cell moves the same bulk protocol (`fofoca_iroh_webrtc_transport::
//! bench`) over one QUIC bi-stream, times it on the receiving side only, and
//! asserts which path carried it — a cell that claims WebRTC and quietly ran
//! on UDP is a wrong number, not a fast one. The JSEP round is timed
//! separately and kept out of the throughput window.

use std::path::PathBuf;

use clap::{Args as ClapArgs, ValueEnum};

use crate::TaskOutcome;
use crate::util::output;

#[cfg(feature = "bench")]
mod native;
#[cfg(feature = "bench")]
mod run;
#[cfg(feature = "bench")]
mod serve;
#[cfg(feature = "bench")]
mod web;

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Only cells whose label contains this (e.g. `chrome`, `safari`, `native`, `raw`).
    #[arg(long)]
    pub(crate) only: Option<String>,
    /// Bytes per transfer. Capped by the protocol's 64 `MiB` ceiling.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub(crate) bytes: usize,
    /// Timed rounds per cell, after one discarded warm-up round: the first
    /// transfer on a connection pays the congestion-window ramp.
    #[arg(long, default_value_t = 5)]
    pub(crate) rounds: usize,
    /// Which way the bulk flows.
    #[arg(long, value_enum, default_value_t = Direction::Down)]
    pub(crate) direction: Direction,
    /// List the cells that would run, without building or launching anything.
    #[arg(long)]
    pub(crate) list: bool,
    /// Also write every row, with its per-round samples, as JSON here.
    #[arg(long)]
    pub(crate) json: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Direction {
    /// Small request, bulk reply.
    Down,
    /// Bulk request, small reply.
    Up,
    /// Bulk both ways at once.
    Both,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cell {
    /// Two separate Chrome processes, iroh QUIC over the data channel.
    FofocaChromeChrome,
    /// A Chrome client, a str0m server in this process.
    FofocaChromeNative,
    /// A Safari Technology Preview client, a str0m server in this process.
    FofocaSafariNative,
    /// A Safari Technology Preview client, a Chrome server: the two WebRTC
    /// stacks against each other.
    FofocaSafariChrome,
    /// Two native endpoints wired as the engine wires them: the WebRTC
    /// transport registered, direct UDP available and preferred. Expected on
    /// `ip`, so it reads as the engine-shaped twin of the iroh baseline.
    FofocaNativeNative,
    /// Two native endpoints with WebRTC as their only transport — str0m at
    /// both ends, the one cell that isolates the native double encryption.
    FofocaNativeNativeWebRtc,
    /// Plain iroh on loopback UDP, no custom transport: the native ceiling.
    IrohNativeNative,
    /// A bare `RTCDataChannel` between two Chrome processes, no wasm and no
    /// QUIC, in 64 `KiB` messages: the browser ceiling.
    RawChromeChrome,
    /// The same channel in 1200-byte messages — one QUIC datagram's worth,
    /// which is how the transport uses it. The gap to [`Self::RawChromeChrome`]
    /// is the channel's own per-message cost; the gap from here to
    /// [`Self::FofocaChromeChrome`] is the integration's.
    RawChromeChromeDatagram,
}

const CELLS: [Cell; 9] = [
    Cell::FofocaChromeChrome,
    Cell::FofocaChromeNative,
    Cell::FofocaSafariNative,
    Cell::FofocaSafariChrome,
    Cell::FofocaNativeNative,
    Cell::FofocaNativeNativeWebRtc,
    Cell::IrohNativeNative,
    Cell::RawChromeChrome,
    Cell::RawChromeChromeDatagram,
];

impl Cell {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::FofocaChromeChrome => "fofoca chrome-chrome",
            Self::FofocaChromeNative => "fofoca chrome-native",
            Self::FofocaSafariNative => "fofoca safari-native",
            Self::FofocaSafariChrome => "fofoca safari-chrome",
            Self::FofocaNativeNative => "fofoca native-native",
            Self::FofocaNativeNativeWebRtc => "fofoca native-native (webrtc-only)",
            Self::IrohNativeNative => "iroh native-native",
            Self::RawChromeChrome => "webrtc chrome-chrome (raw, 64 KiB msgs)",
            Self::RawChromeChromeDatagram => "webrtc chrome-chrome (raw, 1200 B msgs)",
        }
    }
}

pub(crate) fn wanted(args: &Args) -> Vec<Cell> {
    CELLS
        .into_iter()
        .filter(|cell| {
            args.only
                .as_ref()
                .is_none_or(|filter| cell.label().contains(filter.as_str()))
        })
        .collect()
}

pub(crate) fn run(args: &Args) -> TaskOutcome {
    if args.list {
        for cell in wanted(args) {
            output::verbatim(&format!("{:<36} would run", cell.label()));
        }
        return Ok(());
    }
    #[cfg(feature = "bench")]
    return run::run(args);
    #[cfg(not(feature = "bench"))]
    crate::util::reexec_with_feature("bench", "the benchmark", true)
}
