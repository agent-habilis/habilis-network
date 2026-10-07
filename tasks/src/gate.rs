//! The quality gate, as data.
//!
//! Every clippy, check, and test invocation in `.github/workflows/ci.yml` is
//! one row of [`STEPS`], in the workflow's order. Two things follow from that.
//!
//! One, the gate is readable in a single screen instead of being spread across
//! a hundred lines of YAML and shell continuations, and `cargo task ci` is
//! provably the same list rather than a sincere attempt at the same list.
//!
//! Two, `-p` is a filter over the table rather than a second code path. A task
//! scoped to one crate keeps that crate's rows and drops the rest, so a scoped
//! run can never quietly diverge from the full run — there is only one
//! description of what a crate needs.

/// What a step runs, and how the result is judged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Lint,
    Check,
    Test,
    /// The same two, against `wasm32-unknown-unknown`. Separate kinds rather
    /// than a flag on the host ones because the wasm rows are not the host rows
    /// with a target bolted on: five crates reach that target, each with its
    /// own feature position, and the check list carries one row the clippy list
    /// does not.
    WasmCheck,
    WasmClippy,
}

impl Kind {
    fn subcommand(self) -> &'static str {
        match self {
            Self::Lint | Self::WasmClippy => "clippy",
            Self::Check | Self::WasmCheck => "check",
            Self::Test => "test",
        }
    }

    /// The participle that heads the status line, matching cargo's own.
    pub(crate) fn verb(self) -> &'static str {
        match self {
            Self::Lint | Self::WasmClippy => "Linting",
            Self::Check | Self::WasmCheck => "Checking",
            Self::Test => "Testing",
        }
    }

    /// How to name this group of rows when reporting that it had none.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Lint => "clippy",
            Self::Check => "check",
            Self::Test => "test",
            Self::WasmCheck => "wasm check",
            Self::WasmClippy => "wasm clippy",
        }
    }

    fn is_wasm(self) -> bool {
        matches!(self, Self::WasmCheck | Self::WasmClippy)
    }

    /// Clippy is only a gate if its findings fail the build.
    fn denies_warnings(self) -> bool {
        matches!(self, Self::Lint | Self::WasmClippy)
    }
}

/// Which packages a step covers.
#[derive(Clone, Copy)]
pub(crate) enum Scope {
    /// The whole workspace. Narrowed to the `-p` names when the task is scoped.
    Workspace,
    /// One crate, because the row exists for something only that crate has —
    /// a non-default feature, or a target nothing else reaches. Dropped when
    /// the task is scoped to anything else.
    Crate(&'static str),
}

pub(crate) struct Step {
    pub(crate) kind: Kind,
    pub(crate) scope: Scope,
    /// Everything after the package selection.
    pub(crate) args: &'static [&'static str],
}

/// `.github/workflows/ci.yml`, transcribed. Keep the two in step: if they
/// disagree, this file is the one that is wrong, because CI is what gates the
/// branch.
pub(crate) const STEPS: &[Step] = &[
    Step {
        kind: Kind::Lint,
        scope: Scope::Workspace,
        args: &["--all-targets"],
    },
    // `blob` is off by default (only agent-gossip enables it), so the row above
    // never lints `src/blob/` — ~1,300 lines including its own ALPN server. The
    // `--all-features` check row below only *checks* it.
    Step {
        kind: Kind::Lint,
        scope: Scope::Crate("habilis-network"),
        args: &["--features", "blob", "--all-targets"],
    },
    // `habilis-network-iroh-webrtc-transport` compiles one of two mutually exclusive
    // backends and neither is on by default, so every default-feature row above
    // builds neither. `native` is the str0m one, and it owns the loopback test.
    Step {
        kind: Kind::Lint,
        scope: Scope::Crate("habilis-network-iroh-webrtc-transport"),
        args: &["--features", "native,bench", "--all-targets"],
    },
    // `--all-targets` is what the first row has and the `--all-features` check
    // row lacks, so without this one the `mesh` feature's e2e suites are
    // compiled but never linted — the only Rust in the workspace that isn't.
    Step {
        kind: Kind::Lint,
        scope: Scope::Workspace,
        args: &["--all-targets", "--all-features"],
    },
    Step {
        kind: Kind::Check,
        scope: Scope::Workspace,
        args: &["--all-targets"],
    },
    // The `mdns` and `dht` features exist so a consumer can drop iroh's
    // discovery closure, and `async-io` so `habilis-network-util` can shed tokio.
    // Nothing else proves those combinations still compile.
    Step {
        kind: Kind::Check,
        scope: Scope::Workspace,
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::Check,
        scope: Scope::Workspace,
        args: &["--all-features"],
    },
    // Gate only: the e2e workflow compiles this set, so CI would catch a break
    // late. `tasks/mesh` turns on `iroh-test-utils` for the library and nothing
    // else. No `--all-targets` here, because that builds the dev-dependencies,
    // and they turn on `test-fixtures` of the protocol crate. That feature adds
    // `From<&str>` for `Nickname`, so a library that needs it compiles in every
    // other row and fails only here.
    Step {
        kind: Kind::Check,
        scope: Scope::Crate("habilis-network"),
        args: &["--features", "iroh-test-utils"],
    },
    Step {
        kind: Kind::Check,
        scope: Scope::Crate("habilis-network-iroh-webrtc-transport"),
        args: &["--features", "native,bench", "--all-targets"],
    },
    // Six crates are reachable on wasm32 and between them that is a
    // substantial amount of code nothing else compiles: `habilis-network-chunks`'s
    // IndexedDB backend, the whole `web` backend of the WebRTC transport, the
    // portable half of the engine, `habilis-network-netplay`'s simulation,
    // `habilis-network-stream`'s byte streams, and `habilis-network-wasm`, the browser peer.
    // Without these rows that code rots silently, and the `#[expect(...)]`
    // attributes inside it are never lint-checked either.
    // `wasm-simd` only changes blake3's codegen, so checking with it on costs
    // nothing and keeps the feature from rotting.
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network-chunks"),
        args: &["--all-targets", "--features", "wasm-simd"],
    },
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network-iroh-webrtc-transport"),
        args: &["--features", "web,bench"],
    },
    // The multihop transport forwards through a browser too, so its crate must
    // build for the browser by itself: the engine's own rows do not reach it
    // while `host` is the only thing that turns it on.
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network-iroh-multihop-transport"),
        args: &[],
    },
    // The engine itself must reach the browser, not merely be avoidable from
    // it. `--no-default-features` is the portable half: no `host`, so no IPC
    // listener, no state file, no process helpers.
    //
    // Not `--all-targets`: the unit tests pull proptest and insta, which are
    // host-only dev-deps. The one wasm test target is named on the next row.
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network"),
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network"),
        args: &["--no-default-features", "--test", "wasm_runtime"],
    },
    // `habilis-network-netplay` sits above the engine (rollback netcode for peer-to-peer
    // games, not part of it) but must be just as portable: a browser peer is
    // exactly who needs it, and a match between a browser and a terminal only
    // works if both run a bit-identical simulation.
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network-netplay"),
        args: &["--no-default-features"],
    },
    // `habilis-network-stream` runs unchanged in a tab, where a producer's accept side
    // and a consumer's dial both live; the browser package needs it to build.
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network-stream"),
        args: &[],
    },
    // The browser peer itself — `packages/habilis-network-wasm`'s Rust half. wasm32 is
    // the only target it has: the crate is a `cdylib` over wasm-bindgen, so
    // nothing else builds it as the browser will.
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network-wasm"),
        args: &[],
    },
    // The browser side of `cargo task benchmark`, a cdylib like the peer.
    Step {
        kind: Kind::WasmCheck,
        scope: Scope::Crate("habilis-network-bench-wasm"),
        args: &[],
    },
    // Clippy, not just check. The `web` backend had never been linted before
    // these rows existed and carried 18 findings on its first pass.
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-chunks"),
        args: &["--all-targets", "--features", "wasm-simd"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-iroh-webrtc-transport"),
        args: &["--features", "web,bench"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-iroh-multihop-transport"),
        args: &[],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network"),
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-netplay"),
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-stream"),
        args: &[],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-wasm"),
        args: &[],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-bench-wasm"),
        args: &[],
    },
    Step {
        kind: Kind::Test,
        scope: Scope::Workspace,
        args: &[],
    },
    // Not covered by the workspace row: `blob` is off by default, so its ticket
    // round-trips and the loopback offload→fetch test never run there.
    Step {
        kind: Kind::Test,
        scope: Scope::Crate("habilis-network"),
        args: &["--features", "blob"],
    },
    // Not covered by the workspace row either: the loopback suite is behind
    // `required-features = ["native"]`. It stands up two real endpoints and
    // completes a QUIC handshake over a str0m data channel, offline via
    // `IceConfig::host_only()`.
    Step {
        kind: Kind::Test,
        scope: Scope::Crate("habilis-network-iroh-webrtc-transport"),
        args: &["--features", "native"],
    },
    // Not covered by the workspace row: the runner's page helpers, and their
    // tests, are behind the `mesh` and `bench` features, and `bench` is the
    // lighter of the two.
    Step {
        kind: Kind::Test,
        scope: Scope::Crate("tasks"),
        args: &["--features", "bench"],
    },
    // The workspace row already runs the relay-policy proofs
    // (`tests/relay_lookup_only_*.rs`, `tests/mesh_transport_lists.rs`):
    // habilis-network-stream's dev-dependency on habilis-network
    // (`crates/habilis-network-stream/Cargo.toml`) turns on `iroh-test-utils`, and cargo
    // unifies features across the workspace. This row compiles them without
    // that help, so they cannot rot if habilis-network-stream drops the feature.
    Step {
        kind: Kind::Test,
        scope: Scope::Crate("habilis-network"),
        args: &["--features", "iroh-test-utils", "--all-targets", "--no-run"],
    },
];

/// The rows of `kind` that survive a `-p` filter, in table order.
///
/// An empty `packages` means the unscoped run: every row, workspace rows
/// covering the workspace.
pub(crate) fn select(kind: Kind, packages: &[String]) -> Vec<&'static Step> {
    STEPS
        .iter()
        .filter(|step| step.kind == kind)
        .filter(|step| match step.scope {
            Scope::Workspace => true,
            Scope::Crate(name) => packages.is_empty() || packages.iter().any(|want| want == name),
        })
        .collect()
}

impl Step {
    /// The full argument list, ready to hand to cargo.
    pub(crate) fn command(&self, packages: &[String]) -> Vec<String> {
        let mut argv = vec![self.kind.subcommand().to_owned()];

        if self.kind.is_wasm() {
            argv.push("--target".to_owned());
            argv.push("wasm32-unknown-unknown".to_owned());
        }

        match self.scope {
            // A scoped run replaces the whole workspace with the named crates;
            // an unscoped one keeps `--workspace`.
            Scope::Workspace if packages.is_empty() => argv.push("--workspace".to_owned()),
            Scope::Workspace => argv.extend(
                packages
                    .iter()
                    .flat_map(|name| ["-p".to_owned(), name.clone()]),
            ),
            Scope::Crate(name) => {
                argv.push("-p".to_owned());
                argv.push(name.to_owned());
            }
        }

        argv.extend(self.args.iter().map(|&arg| arg.to_owned()));

        if self.kind.denies_warnings() {
            argv.push("--".to_owned());
            argv.push("-D".to_owned());
            argv.push("warnings".to_owned());
        }

        argv
    }

    /// The status line: the participle cargo would use, then the part of the
    /// invocation that says which slice of the workspace this row is.
    pub(crate) fn describe(&self, packages: &[String]) -> (&'static str, String) {
        let subject = self
            .command(packages)
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ");
        (self.kind.verb(), subject)
    }
}
