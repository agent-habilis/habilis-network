//! The public path of the state file error: a caller names it and matches on it.

use habilis_network::runtime::state_file::{StateFileError, read_snapshot};

#[test]
fn a_caller_can_name_and_match_the_state_file_error() {
    let path = std::env::temp_dir().join("habilis-state-file-error-path.json");
    std::fs::write(&path, "{ not json").expect("write the fixture");
    let error = read_snapshot(&path).expect_err("unparsable");
    std::fs::remove_file(&path).ok();
    assert!(
        matches!(error, StateFileError::Unparsable { .. }),
        "{error}"
    );
}
