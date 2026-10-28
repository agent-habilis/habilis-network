//! Host-level helpers a consumer needs alongside the mesh itself: where its
//! runtime files live, the clock, the log sink, process introspection, the
//! build stamp.

pub mod bounded_fifo_set;
pub mod bounded_queue;
// Gated with its only caller, the engine's IPC listener: line framing over a
// unix socket / named pipe, which a browser has no equivalent of. `async-io` is
// also the crate's only tokio user.
pub mod clock;
pub mod consts;
pub mod cooldown;
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
pub mod resident_memory;
pub mod tuning;
pub mod version;

mod runtime_dir;

pub use runtime_dir::mesh_prefix;
#[cfg(feature = "host")]
pub use runtime_dir::{
    ensure_mesh_runtime_dir, ensure_parent_private, ensure_runtime_base, is_under_runtime_base,
    mesh_runtime_dir, runtime_base,
};

#[cfg(test)]
mod tests {
    use super::{is_under_runtime_base, mesh_prefix, runtime_base};
    use habilis_network_test_tracing::test;
    use std::path::Path;

    #[test]
    fn runtime_base_is_deterministic_and_uid_scoped() {
        // Regression guard: for a given product the base must be a fixed function
        // of the uid, not of the environment — a daemon and a later CLI in a
        // different context (cron/sudo/statusline) have to agree, or the CLI can't
        // find the socket.
        assert_eq!(runtime_base("demo"), runtime_base("demo"));
        let shown = runtime_base("demo").to_string_lossy().into_owned();
        assert!(shown.starts_with("/tmp/demo-"), "unexpected base: {shown}");
        // …and two embedders never share a base, so their daemons can never
        // collide on a socket or read each other's state files.
        assert_ne!(runtime_base("demo"), runtime_base("other"));
    }

    #[test]
    fn is_under_runtime_base_discriminates() {
        let base = runtime_base("demo");
        assert!(is_under_runtime_base(
            &base,
            &base.join("abcdefghijkmnp/nick.state.json")
        ));
        assert!(!is_under_runtime_base(&base, Path::new("/etc/passwd")));
        // The un-suffixed sibling is a different directory, not a parent.
        assert!(!is_under_runtime_base(
            &base,
            Path::new("/tmp/demo/sessions/x.json")
        ));
    }

    #[test]
    fn truncates_to_16_chars() {
        assert_eq!(mesh_prefix("abcdefghijkmnpqrs").chars().count(), 16);
    }

    #[test]
    fn short_input_unchanged() {
        assert_eq!(mesh_prefix("abcd"), "abcd");
    }

    #[test]
    fn result_is_a_prefix_of_input() {
        let input = "abcdefghijkmnpqrstuvwx";
        assert!(input.starts_with(&mesh_prefix(input)));
    }

    #[test]
    fn stem_is_path_safe_ascii() {
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
