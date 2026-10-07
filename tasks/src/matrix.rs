//! `cargo task matrix` — every cell of the send ladder matrix, then the D11 gate, one test at a time.
//!
//! The matrix is `crates/habilis-network/tests/send_ladder_matrix.rs`: one test per
//! cell of transport list, blocked rungs and path of the third member. The D11 gate is
//! `crates/habilis-network/tests/d11_gate_loopback.rs`: a node at a ceiling of two direct
//! connections, and a lane pair. Every test of both files is `#[ignore]`, because each
//! stands up several real members and must not run next to another test, so a full run
//! takes a while. The gate runs two cells by name (a row of [`crate::gate::STEPS`]). This
//! task runs them all, and the nightly workflow runs this task.
//!
//! One test thread: the cells share the process-wide block tables, and a cell
//! that takes IP away from a node must not meet another cell on the same host.

use xshell::{Shell, cmd};

use crate::TaskOutcome;
use crate::util::output;

/// The test binaries of the run, in order. Each is `#[ignore]` throughout.
const TESTS: [&str; 2] = ["send_ladder_matrix", "d11_gate_loopback"];

pub(crate) fn run(sh: &Shell, list: bool) -> TaskOutcome {
    output::status(
        "Running",
        if list {
            "listing the tests of the matrix and the D11 gate"
        } else {
            "every cell of the send ladder matrix and the D11 gate, one at a time"
        },
    );
    let tests: Vec<String> = TESTS
        .iter()
        .flat_map(|test| ["--test".to_owned(), (*test).to_owned()])
        .collect();
    let only_list: &[&str] = if list { &["--list"] } else { &[] };
    cmd!(
        sh,
        "cargo test -p habilis-network --features iroh-test-utils {tests...} -- --include-ignored --test-threads=1 {only_list...}"
    )
    .quiet()
    .run()?;
    Ok(())
}
