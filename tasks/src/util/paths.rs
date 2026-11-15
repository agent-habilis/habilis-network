use std::path::{Path, PathBuf};

/// The workspace root — `tasks/..`, resolved from the manifest directory
/// rather than the current one, so `cargo task` behaves the same wherever it is
/// invoked from inside the workspace.
pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the tasks crate always sits directly under the workspace root")
        .to_path_buf()
}
