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

pub(crate) use kind::Kind;
pub(crate) use scope::Scope;
pub(crate) use step::Step;

mod kind;
mod scope;
mod step;

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
    // Every crate that builds for wasm32 has a row of its own, so the `-D
    // clippy::disallowed_methods` that every row passes reaches it as a primary package: the rows
    // above reach these six only as dependencies of another crate.
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-protocol"),
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-util"),
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-iroh-transport-util"),
        args: &[],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-iroh-gossip-transport"),
        args: &[],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-doc"),
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-logging"),
        args: &["--no-default-features"],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-test-tracing"),
        args: &[],
    },
    Step {
        kind: Kind::WasmClippy,
        scope: Scope::Crate("habilis-network-test-tracing-macros"),
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
    // The two gate cells of the send ladder matrix (`tests/send_ladder_matrix.rs`):
    // the default list with IP blocked, and the pair that goes through a third
    // member. Every cell is `#[ignore]`, so that no plain `cargo test` runs a cell
    // next to another test; this row names the two and runs them one at a time,
    // since each runs three real members. The rest belong to `cargo task matrix`
    // and its nightly.
    Step {
        kind: Kind::Test,
        scope: Scope::Crate("habilis-network"),
        args: &[
            "--features",
            "iroh-test-utils",
            "--test",
            "send_ladder_matrix",
            "--",
            "--include-ignored",
            "--exact",
            "udp_webrtc_multihop_ip_direct",
            "udp_webrtc_multihop_ip_webrtc_via_third",
            "--test-threads=1",
        ],
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

#[cfg(test)]
mod tests {
    use xshell::Shell;

    use super::{Kind, STEPS, Scope};
    use crate::util::metadata;

    /// Workspace members that never build for wasm32, each with its reason. Every other member
    /// needs a wasm32 clippy row of its own: that row is what puts `-D
    /// clippy::disallowed_methods` on the crate, with the feature set the crate needs. A new
    /// crate fails the first test below until it has a row or an entry here.
    const NATIVE_ONLY: &[(&str, &str)] = &[
        ("tasks", "the task runner drives the host"),
        ("chat", "the native chat example"),
        ("habilis-network-ffi", "the C ABI for native hosts"),
        ("habilis-network-stream-cli", "a command-line binary"),
    ];

    /// The names of the workspace members, from `cargo metadata`.
    fn workspace_members() -> Vec<String> {
        let sh = Shell::new().expect("a shell");
        metadata(&sh)
            .expect("cargo metadata runs")
            .packages
            .into_iter()
            .map(|package| package.name)
            .collect()
    }

    /// The crates that have a wasm32 clippy row of their own.
    fn wasm_clippy_crates() -> Vec<&'static str> {
        STEPS
            .iter()
            .filter(|step| step.kind == Kind::WasmClippy)
            .filter_map(|step| match step.scope {
                Scope::Crate(name) => Some(name),
                Scope::Workspace => None,
            })
            .collect()
    }

    #[test]
    fn every_workspace_crate_that_builds_for_wasm32_has_a_wasm_clippy_row() {
        let _guard = ::habilis_network_test_tracing::init();
        let rows = wasm_clippy_crates();
        let missing: Vec<String> = workspace_members()
            .into_iter()
            .filter(|name| !rows.contains(&name.as_str()))
            .filter(|name| !NATIVE_ONLY.iter().any(|(native, _)| native == name))
            .collect();

        assert!(
            missing.is_empty(),
            "no wasm32 clippy row, and not native-only: {missing:?}. Add a `Kind::WasmClippy` \
             step to `STEPS` and a line to `ci.yml`, or list the crate in `NATIVE_ONLY` with a reason"
        );
    }

    #[test]
    fn the_rows_and_the_exemptions_name_workspace_crates_and_do_not_overlap() {
        let _guard = ::habilis_network_test_tracing::init();
        let members = workspace_members();
        let rows = wasm_clippy_crates();
        let unknown: Vec<&str> = rows
            .iter()
            .copied()
            .chain(NATIVE_ONLY.iter().map(|(name, _)| *name))
            .filter(|name| !members.iter().any(|member| member == name))
            .collect();
        let both: Vec<&str> = NATIVE_ONLY
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| rows.contains(name))
            .collect();

        assert!(
            unknown.is_empty(),
            "names that are no workspace crate: {unknown:?}"
        );
        assert!(
            both.is_empty(),
            "native-only crates that have a wasm32 row: {both:?}"
        );
    }
}
