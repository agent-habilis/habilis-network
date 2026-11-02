//! The public path of the state file error: a caller names it and matches on it.
#![cfg(feature = "host")]

use habilis_network::runtime::state_file::{StateFileError, read_snapshot};

use std::{env, fs};
#[test]
fn a_caller_can_name_and_match_the_state_file_error() {
    let path = env::temp_dir().join("habilis-state-file-error-path.json");
    fs::write(&path, "{ not json").expect("write the fixture");
    let error = read_snapshot(&path).expect_err("unparsable");
    fs::remove_file(&path).ok();
    assert!(
        matches!(error, StateFileError::Unparsable { .. }),
        "{error}"
    );
}
