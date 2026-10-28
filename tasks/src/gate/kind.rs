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
    pub(super) fn subcommand(self) -> &'static str {
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

    pub(super) fn is_wasm(self) -> bool {
        matches!(self, Self::WasmCheck | Self::WasmClippy)
    }

    /// Clippy is only a gate if its findings fail the build.
    pub(super) fn denies_warnings(self) -> bool {
        matches!(self, Self::Lint | Self::WasmClippy)
    }
}
