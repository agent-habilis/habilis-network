//! Host-level helpers a consumer needs alongside the mesh itself: where its
//! runtime files live, the clock, the log sink, process introspection, the
//! build stamp.

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

pub mod bounded_fifo_set;
pub mod bounded_queue;
// Gated with its only caller, the engine's IPC listener: line framing over a
// unix socket / named pipe, which a browser has no equivalent of. `async-io` is
// also the crate's only tokio user.
pub mod clock;
pub mod consts;
pub mod cooldown;
pub mod file_name;
// The retry of a rename or a remove that a reader blocks on Windows: the state
// file and the IPC marker.
#[cfg(feature = "host")]
pub mod file_retry;
#[cfg(feature = "async-io")]
pub mod line_read;
pub mod log_config;
/// Process helpers for the daemon: the parent-process walk that the orphan watch uses.
#[cfg(feature = "host")]
pub mod process;
pub mod unix_secs;
// Portable: the reading itself is `cfg`'d down to `None` off a libc host, so
// the leak gauge compiles everywhere and simply reports 0 in a browser. Keeping
// the module un-gated is what lets `timers` stay free of `cfg` at its call sites.
pub mod process_usage;
pub mod resident_memory;
pub mod tuning;
pub mod version;
// The Windows security calls of the IPC named pipe: the user SID, the pipe
// descriptor, the owner check and the identification-only client open.
#[cfg(all(windows, feature = "host"))]
pub mod win_security;
// A hidden window that gets the end of the session: a logoff, a shutdown and a
// close.
#[cfg(all(windows, feature = "host"))]
pub mod win_session;
// A console event sent to another process, for the tests of the console events
// of a daemon. Only for tests, so the library that ships does not have it.
#[cfg(all(windows, feature = "host", feature = "test-fixtures"))]
pub mod win_console;

// What `check_runtime_base` found at the base, on Unix.
#[cfg(all(unix, feature = "host"))]
mod runtime_base_check;
mod runtime_dir;

#[cfg(all(unix, feature = "host"))]
pub use runtime_base_check::RuntimeBaseCheck;
#[cfg(all(unix, feature = "host"))]
pub use runtime_dir::check_runtime_base;
pub use runtime_dir::mesh_prefix;
#[cfg(feature = "host")]
pub use runtime_dir::{
    ensure_mesh_runtime_dir, ensure_parent_private, ensure_runtime_base, is_under_runtime_base,
    mesh_runtime_dir, runtime_base,
};

#[cfg(test)]
mod tests {
    use super::{is_under_runtime_base, mesh_prefix, runtime_base};
    #[cfg(unix)]
    use std::path::Path;
    #[cfg(windows)]
    use std::{ffi, path};

    #[test]
    fn runtime_base_is_deterministic_and_uid_scoped() {
        let _guard = ::habilis_network_test_tracing::init();
        // Regression guard: for a given product the base must be a fixed function
        // of the uid, not of the environment — a daemon and a later CLI in a
        // different context (cron/sudo/statusline) have to agree, or the CLI can't
        // find the socket.
        assert_eq!(
            runtime_base("demo"),
            runtime_base("demo"),
            "the runtime base is deterministic for one name"
        );
        let shown = runtime_base("demo").to_string_lossy().into_owned();
        #[cfg(unix)]
        assert!(shown.starts_with("/tmp/demo-"), "unexpected base: {shown}");
        // Windows has no uid suffix: the per-user part is the profile, and the
        // base is `<LocalAppData>\demo\run`.
        #[cfg(windows)]
        {
            let base = runtime_base("demo");
            assert_eq!(base.file_name(), Some(ffi::OsStr::new("run")), "{shown}");
            let product = base.parent().and_then(path::Path::file_name);
            assert_eq!(product, Some(ffi::OsStr::new("demo")), "{shown}");
            assert!(
                base.components()
                    .any(|part| part.as_os_str().eq_ignore_ascii_case("AppData")),
                "the base is not in the profile: {shown}"
            );
        }
        // …and two embedders never share a base, so their daemons can never
        // collide on a socket or read each other's state files.
        assert_ne!(
            runtime_base("demo"),
            runtime_base("other"),
            "different names give different runtime bases"
        );
    }

    #[test]
    fn is_under_runtime_base_discriminates() {
        let _guard = ::habilis_network_test_tracing::init();
        let base = runtime_base("demo");
        assert!(
            is_under_runtime_base(&base, &base.join("abcdefghijkmnp/nick.state.json")),
            "a path under the runtime base is discriminated as inside"
        );
        // A path beside the base, built from the base so it is valid on each OS.
        let parent = base.parent().expect("the base has a parent");
        assert!(
            !is_under_runtime_base(&base, &parent.join("elsewhere").join("passwd")),
            "a path beside the runtime base is not under it"
        );
        // A sibling whose name only *starts with* the base name is a different
        // directory, not a child: the test is by component, not by string.
        let name = base.file_name().expect("the base has a name");
        let mut sibling = name.to_os_string();
        sibling.push("x");
        assert!(
            !is_under_runtime_base(&base, &parent.join(sibling).join("sessions").join("x.json")),
            "a sibling that shares the name prefix is not under the runtime base"
        );
        // The un-suffixed sibling is a different directory, not a parent.
        #[cfg(unix)]
        assert!(
            !is_under_runtime_base(&base, Path::new("/tmp/demo/sessions/x.json")),
            "a path under another directory is not under the runtime base"
        );
    }

    #[test]
    fn truncates_to_16_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            mesh_prefix("abcdefghijkmnpqrs").chars().count(),
            16,
            "a long mesh prefix is truncated to 16 characters"
        );
    }

    #[test]
    fn short_input_unchanged() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(mesh_prefix("abcd"), "abcd", "a short input is unchanged");
    }

    #[test]
    fn result_is_a_prefix_of_input() {
        let _guard = ::habilis_network_test_tracing::init();
        let input = "abcdefghijkmnpqrstuvwx";
        assert!(
            input.starts_with(&mesh_prefix(input)),
            "the mesh prefix is a prefix of its input"
        );
    }

    #[test]
    fn stem_is_path_safe_ascii() {
        let _guard = ::habilis_network_test_tracing::init();
        // The stem goes straight into a path, so it must carry no separator
        // and nothing needing escaping. Fed a *real* id (bare Base58), not the
        // short labels the cases above use.
        let stem = mesh_prefix("2UXAThUkdBAbiJNXvCt4YeMGQ9myFg7gJJZSr3pG3MAG");
        assert!(
            stem.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "{stem}"
        );
    }
}
