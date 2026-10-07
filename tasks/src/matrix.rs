//! `cargo task matrix` — every cell of the send ladder matrix, one at a time.
//!
//! The matrix is `crates/habilis-network/tests/send_ladder_matrix.rs`: one test per
//! cell of transport list, blocked rungs and path of the third member. Two cells
//! run in the gate (a row of [`crate::gate::STEPS`]); the rest are `#[ignore]`
//! because each stands up three real members, so a full run takes a while. This
//! task runs them all, and the nightly workflow runs this task.
//!
//! One test thread: the cells share the process-wide block tables, and a cell
//! that takes IP away from a node must not meet another cell on the same host.

use xshell::{Shell, cmd};

use crate::TaskOutcome;
use crate::util::output;

pub(crate) fn run(sh: &Shell) -> TaskOutcome {
    output::status(
        "Running",
        "every cell of the send ladder matrix, one at a time",
    );
    cmd!(
        sh,
        "cargo test -p habilis-network --features iroh-test-utils --test send_ladder_matrix -- --include-ignored --test-threads=1"
    )
    .quiet()
    .run()?;
    Ok(())
}
