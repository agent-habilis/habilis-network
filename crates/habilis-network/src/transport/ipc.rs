mod addressed;
pub use addressed::Addressed;
mod bound;
mod client;
pub use client::{active_endpoints, send, send_to_endpoint};
#[cfg(unix)]
pub use client::{active_socket_paths, send_to_path};
#[cfg(windows)]
mod engine_control;
#[cfg(windows)]
pub(crate) use engine_control::EngineControl;
mod foreign_endpoint;
pub use foreign_endpoint::ForeignEndpoint;
mod ipc_error;
pub use ipc_error::IpcError;
#[cfg(windows)]
mod ipc_marker;
#[cfg(windows)]
pub(crate) use ipc_marker::IpcMarker;
mod ipc_name;
pub use ipc_name::IpcName;
mod ipc_name_error;
pub use ipc_name_error::IpcNameError;
mod json_reply;
pub use json_reply::{json_ack, json_error, json_ok_msg};
mod listener;
pub(crate) use listener::{bind, serve};
mod no_daemon;
pub use no_daemon::NoDaemon;
mod quit;
pub use quit::{quit, terminate};
mod quit_error;
pub use quit_error::QuitError;
mod quit_target;
pub use quit_target::QuitTarget;

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{
        Addressed, IpcError, IpcName, QuitError, QuitTarget, active_endpoints, client, json_reply,
        listener, quit, terminate,
    };
    #[cfg(windows)]
    use super::{engine_control, ipc_marker, send_to_endpoint};
    use crate::protocol::{MeshId, Nickname};
    use crate::transport::IpcMessage;
    use tokio::sync::mpsc;

    use crate::gossip::event;
    use crate::util;
    use crate::util::tuning;
    #[cfg(not(unix))]
    use std::env;
    use std::time::Duration;
    use std::{fs, path, process, sync};
    use tokio::time;

    #[cfg(windows)]
    use serde::de;
    #[cfg(windows)]
    use std::mem;
    #[cfg(windows)]
    use tokio::task;
    /// A minimal mesh-addressed command standing in for the app's real
    /// `IpcCommand` (which lives app-side): exercises the engine's generic
    /// socket framing without naming any application type.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "command")]
    enum TestCommand {
        #[serde(rename = "msg")]
        Msg { mesh: MeshId, body: String },
        #[serde(rename = "ping")]
        Ping { mesh: MeshId },
    }

    impl Addressed for TestCommand {
        fn mesh_id(&self) -> Option<&MeshId> {
            match self {
                TestCommand::Msg { mesh, .. } | TestCommand::Ping { mesh } => Some(mesh),
            }
        }
    }

    // ── pure functions ─────────────────────────────────────────────

    #[test]
    fn json_ok_is_valid_json() {
        let _guard = ::habilis_network_test_tracing::init();
        let json = json_reply::json_ok("abc-123");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("the json the ipc reply writes parses");
        assert_eq!(
            parsed["ok"], true,
            "a json ok reply is an object with ok true"
        );
        assert_eq!(parsed["id"], "abc-123", "a json ok reply carries the id");
    }

    #[test]
    fn json_error_is_valid_json() {
        let _guard = ::habilis_network_test_tracing::init();
        let json = json_reply::json_error("something broke");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("the json the ipc reply writes parses");
        assert_eq!(
            parsed["ok"], false,
            "a json error reply is an object with ok false"
        );
        assert_eq!(
            parsed["error"], "something broke",
            "a json error reply carries the error text"
        );
    }

    #[test]
    fn json_ok_escapes_special_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        let json = json_reply::json_ok(r#"id"with"quotes"#);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("the json the ipc reply writes parses");
        assert_eq!(
            parsed["id"], r#"id"with"quotes"#,
            "an id with quotes is escaped in a json ok reply"
        );
    }

    #[test]
    fn json_error_escapes_special_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        let json = json_reply::json_error(r#"error: "bad input""#);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("the json the ipc reply writes parses");
        assert_eq!(
            parsed["error"], r#"error: "bad input""#,
            "an error with quotes is escaped in a json error reply"
        );
    }

    /// A runtime base of one test alone, removed when the test ends, also when
    /// an assert fails. A daemon under a product's base never sees it.
    ///
    /// On Unix it is under `/tmp`, not the temp directory: a socket path must
    /// stay inside the `sun_path` limit (about 104 bytes on macOS), and the macOS
    /// temp directory is long.
    struct TestBase(path::PathBuf);

    impl TestBase {
        fn new(tag: &str) -> Self {
            let name = format!("hn-ipc-{}-{tag}", process::id());
            #[cfg(unix)]
            let path = path::Path::new("/tmp").join(name);
            #[cfg(not(unix))]
            let path = env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &path::Path {
            &self.0
        }
    }

    impl Drop for TestBase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A mesh id whose prefix is this process and `tag`, in the Base58 alphabet.
    fn test_mesh(tag: &str) -> MeshId {
        let pid_b58 = bs58::encode(process::id().to_le_bytes()).into_string();
        MeshId::from(format!("{tag}{pid_b58}").as_str())
    }

    /// A valid pipe name that no endpoint has.
    #[cfg(windows)]
    fn absent_name(tag: &str) -> IpcName {
        let raw = format!(r"\\.\pipe\habilis-absent-{}-{tag}", process::id());
        IpcName::new(raw).expect("a valid name")
    }

    /// The endpoint of a bound test daemon, found as a client finds it: the
    /// socket path on Unix, the marker on Windows.
    fn endpoint_of(base: &path::Path, mesh: &MeshId, nickname: &Nickname) -> IpcName {
        #[cfg(unix)]
        let name =
            IpcName::new(listener::socket_path(base, mesh, nickname)).expect("a socket path");
        #[cfg(windows)]
        let name = ipc_marker::read_marker(&ipc_marker::marker_path(base, mesh, nickname))
            .expect("the marker reads")
            .expect("a marker");
        name
    }

    #[test]
    fn an_ipc_name_is_an_endpoint_of_this_os() {
        let _guard = ::habilis_network_test_tracing::init();
        for bad in [
            "",
            "a\nb",
            "relative/x.sock",
            r"\\?\pipe\x",
            r"\\host\pipe\x",
        ] {
            assert!(IpcName::new(bad.to_owned()).is_err(), "{bad:?}");
        }
        assert!(IpcName::new("/".repeat(513)).is_err(), "too long");
        #[cfg(unix)]
        {
            assert!(
                IpcName::new("/tmp/x/nick.ipc.sock".to_owned()).is_ok(),
                "an absolute socket path is a name"
            );
            assert!(
                IpcName::new(r"\\.\pipe\habilis-00".to_owned()).is_err(),
                "a pipe is no name on Unix"
            );
        }
        #[cfg(windows)]
        {
            assert!(
                IpcName::new(r"\\.\pipe\habilis-00ff".to_owned()).is_ok(),
                "a local pipe is a name"
            );
            assert!(
                IpcName::new(r"\\.\pipe\".to_owned()).is_err(),
                "no pipe name"
            );
            assert!(
                IpcName::new(r"\\.\pipe\a\b".to_owned()).is_err(),
                "a backslash"
            );
            assert!(
                IpcName::new(r"C:\tmp\nick.ipc.sock".to_owned()).is_err(),
                "a file path is no name on Windows"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_format() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("abcdefghijkmnpqr");
        let base = util::runtime_base("habilis-network-ipc-test");
        let path = listener::socket_path(&base, &mesh, &Nickname::from("my-nick"));
        assert!(
            path.starts_with(&*base.to_string_lossy()),
            "the socket path starts in the base directory"
        );
        assert!(
            path.ends_with("/my-nick.ipc.sock"),
            "the socket path ends with the nickname socket name"
        );
        assert!(
            path.contains(&util::mesh_prefix(mesh.as_str())),
            "the socket path carries the mesh prefix"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_marker_holds_one_line_and_reads_back() {
        use std::ffi;

        let _guard = ::habilis_network_test_tracing::init();
        let base = TestBase::new("marker");
        let mesh = test_mesh("marker");
        let nickname = Nickname::from("nick");
        fs::create_dir_all(util::mesh_runtime_dir(base.path(), mesh.as_str()))
            .expect("the mesh folder");
        let path = ipc_marker::marker_path(base.path(), &mesh, &nickname);
        assert_eq!(
            path.file_name(),
            Some(ffi::OsStr::new("nick.ipc")),
            "the marker is named for the nickname"
        );
        let name = absent_name("marker");
        let marker = ipc_marker::IpcMarker::write(path.clone(), name.clone()).expect("write");
        assert_eq!(
            fs::read_to_string(&path).expect("the marker reads"),
            format!("{name}\n"),
            "the marker holds one line"
        );
        assert_eq!(
            ipc_marker::read_marker(&path).expect("the marker reads"),
            Some(name),
            "the marker reads back"
        );
        drop(marker);
        // An invalid line is an error, not "no daemon".
        fs::write(&path, "relative\n").expect("write a bad marker");
        assert!(
            ipc_marker::read_marker(&path).is_err(),
            "an invalid line is an error"
        );
        fs::remove_file(&path).expect("remove the marker");
        assert_eq!(
            ipc_marker::read_marker(&path).expect("no marker reads"),
            None,
            "no marker is no daemon"
        );
    }

    #[test]
    fn send_with_no_daemon_is_no_daemon() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("nomarker");
            let mesh = test_mesh("nomarker");
            let nickname = Nickname::from("nobody");
            let command = TestCommand::Ping { mesh };
            let error = client::send(base.path(), &command, &nickname)
                .await
                .expect_err("no daemon");
            assert!(matches!(error, IpcError::NoDaemon(_)), "{error}");
        });
    }

    #[cfg(windows)]
    #[test]
    fn send_to_a_stale_marker_is_no_daemon() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("stale");
            let mesh = test_mesh("stale");
            let nickname = Nickname::from("ghost");
            fs::create_dir_all(util::mesh_runtime_dir(base.path(), mesh.as_str()))
                .expect("the mesh folder");
            ipc_marker::IpcMarker::write(
                ipc_marker::marker_path(base.path(), &mesh, &nickname),
                absent_name("stale"),
            )
            .expect("write");
            let command = TestCommand::Ping { mesh };
            let error = client::send(base.path(), &command, &nickname)
                .await
                .expect_err("no daemon");
            assert!(matches!(error, IpcError::NoDaemon(_)), "{error}");
        });
    }

    // On Unix discovery lists the sockets, as `active_socket_paths` did before
    // `active_endpoints`. A plain file stands in for a socket: discovery reads
    // names only. A `send_to_path` to a path with no socket is an error.
    #[cfg(unix)]
    #[test]
    fn active_endpoints_lists_the_sockets_sorted() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("discover");
            assert!(
                active_endpoints(base.path()).next().is_none(),
                "an absent base"
            );
            let first = base.path().join("meshaaaaaaaaaaaa");
            let second = base.path().join("meshbbbbbbbbbbbb");
            fs::create_dir_all(&first).expect("the first mesh folder");
            fs::create_dir_all(&second).expect("the second mesh folder");
            fs::write(first.join("zz.ipc.sock"), "").expect("a socket stand-in");
            fs::write(second.join("aa.ipc.sock"), "").expect("a socket stand-in");
            fs::write(first.join("nick.state.json"), "{}").expect("a state file");
            let mut paths: Vec<path::PathBuf> = client::active_socket_paths(base.path()).collect();
            paths.sort();
            assert_eq!(
                paths,
                vec![first.join("zz.ipc.sock"), second.join("aa.ipc.sock")],
                "the sockets are listed"
            );
            let found = active_endpoints(base.path());
            let names: Vec<String> = found.map(|name| name.as_str().to_owned()).collect();
            let texts: Vec<&str> = paths.iter().filter_map(|path| path.to_str()).collect();
            assert_eq!(texts.len(), paths.len(), "every socket path is UTF-8");
            let mut expected: Vec<String> = texts.into_iter().map(str::to_owned).collect();
            expected.sort();
            assert_eq!(names, expected, "the endpoints are the sockets, sorted");
            let command = TestCommand::Ping {
                mesh: test_mesh("discover"),
            };
            assert!(
                client::send_to_path(&paths[0], &command).await.is_err(),
                "no socket"
            );
        });
    }

    #[cfg(windows)]
    #[test]
    fn active_endpoints_reads_the_markers_sorted_and_skips_the_rest() {
        let guard = ::habilis_network_test_tracing::init();
        // The marker with an invalid line is skipped with a warn.
        guard.expect_warn("habilis_network::lifecycle", "IPC: skip a marker");
        let base = TestBase::new("discover");
        assert!(
            active_endpoints(base.path()).next().is_none(),
            "an absent base"
        );
        let first = base.path().join("meshaaaaaaaaaaaa");
        let second = base.path().join("meshbbbbbbbbbbbb");
        fs::create_dir_all(&first).expect("the first mesh folder");
        fs::create_dir_all(&second).expect("the second mesh folder");
        let late = absent_name("zz");
        let early = absent_name("aa");
        ipc_marker::IpcMarker::write(first.join("one.ipc"), late.clone()).expect("write");
        ipc_marker::IpcMarker::write(second.join("two.ipc"), early.clone()).expect("write");
        // Not read: an invalid line, the tmp file of a write, a marker that is
        // a folder, and a marker file at the level of the mesh folders.
        fs::write(first.join("bad.ipc"), "relative\n").expect("a bad marker");
        fs::write(first.join("one.ipc.tmp.123"), format!("{early}\n")).expect("a tmp file");
        fs::create_dir_all(second.join("dir.ipc")).expect("a marker folder");
        fs::write(base.path().join("loose.ipc"), format!("{early}\n")).expect("a loose marker");
        let found: Vec<IpcName> = active_endpoints(base.path()).collect();
        assert_eq!(found, vec![early, late], "the markers are read, sorted");
    }

    // Two names, as two daemons have on Windows, where the pipe name is per
    // process. On Unix the two names would be the same socket path.
    #[cfg(windows)]
    #[test]
    fn a_marker_is_removed_only_by_the_daemon_that_it_names() {
        let _guard = ::habilis_network_test_tracing::init();
        let base = TestBase::new("ours");
        fs::create_dir_all(base.path()).expect("the base");
        let path = base.path().join("nick.ipc");
        let first =
            ipc_marker::IpcMarker::write(path.clone(), absent_name("first")).expect("write");
        // A second daemon with the same nickname writes over the first.
        let second =
            ipc_marker::IpcMarker::write(path.clone(), absent_name("second")).expect("write");
        first.remove_if_ours();
        assert!(path.exists(), "the marker of the live second daemon stays");
        second.remove_if_ours();
        assert!(!path.exists(), "the second daemon removes its own marker");
        second.remove_if_ours();
        assert!(!path.exists(), "no marker: nothing to do");
    }

    // A reader that opens the marker as the `Get-Content` of `PowerShell` does,
    // with no `FILE_SHARE_DELETE`, and closes it after 2 ms: the remove waits
    // for it. The short hold leaves most of the 50 ms deadline to a slow runner.
    #[cfg(windows)]
    #[test]
    fn a_marker_remove_waits_for_a_reader_without_share_delete() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::thread;

        // `FILE_SHARE_READ`, with no `FILE_SHARE_DELETE`. This crate has no
        // `windows-sys`.
        const FILE_SHARE_READ: u32 = 1;

        let _guard = ::habilis_network_test_tracing::init();
        let base = TestBase::new("held");
        fs::create_dir_all(base.path()).expect("the base");
        let path = base.path().join("nick.ipc");
        let marker =
            ipc_marker::IpcMarker::write(path.clone(), absent_name("held")).expect("write");
        let reader: fs::File = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .expect("open the marker");
        let closer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(2));
            drop(reader);
        });
        marker.remove_if_ours();
        closer.join().expect("the closer thread ends");
        assert!(
            !path.exists(),
            "the marker is removed after the reader closes"
        );
    }

    #[test]
    fn a_busy_pipe_is_tried_three_more_times_then_given_up() {
        let _guard = ::habilis_network_test_tracing::init();
        let waits: Vec<_> = (0..5).map(client::pipe_busy_retry).collect();
        let fifty = Some(Duration::from_millis(50));
        assert_eq!(
            waits,
            vec![fifty, fifty, fifty, None, None],
            "three tries of 50 ms, then none"
        );
    }

    /// On Windows the endpoint is a pipe with a random name, no mesh prefix and
    /// no nickname in it, and a DACL of the user alone.
    #[cfg(windows)]
    #[test]
    fn the_windows_endpoint_is_a_random_pipe_of_the_user() {
        use std::os::windows::io::AsHandle as _;

        use crate::util::win_security;

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("pipe");
            let mesh = test_mesh("pipe");
            let nickname = Nickname::from("piper");
            let bound = listener::bind(base.path(), &mesh, &nickname).expect("bind");
            let name = endpoint_of(base.path(), &mesh, &nickname);
            let random = name
                .as_str()
                .strip_prefix(listener::PIPE_PREFIX)
                .expect("the engine prefix");
            assert_eq!(random.len(), 32, "{name}");
            assert!(
                random.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{name}"
            );
            assert!(!name.as_str().contains("piper"), "no nickname in {name}");

            // A second bind gets another name.
            let other = listener::bind(base.path(), &test_mesh("pipe2"), &nickname).expect("bind");
            let other_name = endpoint_of(base.path(), &test_mesh("pipe2"), &nickname);
            assert_ne!(name, other_name, "a second bind gets another name");
            drop(other);

            // The DACL of a client handle of the pipe: one entry, the user. The
            // trustee can read back as an alias (`LA` when the test runs as the
            // built-in Administrator), so the test compares the SID.
            let client = win_security::open_pipe_identification(name.as_str()).expect("open");
            let user = win_security::current_user_sid().expect("the user SID");
            let dacl = win_security::dacl_text(client.as_handle()).expect("the DACL");
            let trustee: &str = dacl
                .strip_prefix("D:P(A;;FA;;;")
                .and_then(|rest| rest.strip_suffix(')'))
                .unwrap_or_else(|| panic!("one entry with all access: {dacl}"));
            assert_eq!(
                win_security::Sid::parse(trustee).expect("a SID or an alias"),
                user,
                "the trustee of the DACL is the user"
            );
            drop(bound);
        });
    }

    // The client refuses a pipe that another account owns, and sends it
    // nothing. One user on CI cannot make such a pipe, so the test expects
    // SYSTEM to own our own pipe, and gets the refusal.
    #[cfg(windows)]
    #[test]
    fn a_pipe_of_another_owner_is_refused_as_foreign() {
        use crate::util::win_security;

        let guard = ::habilis_network_test_tracing::init();
        guard.expect_warn(
            "habilis_network::lifecycle",
            "IPC: the pipe is not owned by this user",
        );
        ::habilis_network_test_tracing::run(guard, async {
            let base = TestBase::new("foreign");
            let mesh = test_mesh("foreign");
            let nickname = Nickname::from("owner");
            let bound = listener::bind(base.path(), &mesh, &nickname).expect("bind");
            let name = endpoint_of(base.path(), &mesh, &nickname);
            let system = win_security::Sid::parse("S-1-5-18").expect("SYSTEM");
            let command = TestCommand::Ping { mesh };
            let error = client::send_to_endpoint_owned_by(&name, &command, &system)
                .await
                .expect_err("a foreign owner");
            let IpcError::ForeignEndpoint(foreign) = error else {
                panic!("a ForeignEndpoint: {error}");
            };
            assert_eq!(foreign.name, name, "the refusal names the endpoint");
            assert_eq!(foreign.nickname, None, "the endpoint was asked by name");
            drop(bound);
        });
    }

    // ── property-based tests ───────────────────────────────────────

    mod prop {
        use crate::util;
        use proptest::collection::vec as arb_vec;
        use proptest::strategy::Strategy;
        use proptest::{prop_assert, prop_assert_eq, proptest};

        use crate::protocol::MeshId;
        use crate::transport::ipc::json_reply;

        use crate::proptest_support;
        fn arb_ascii_body() -> impl Strategy<Value = String> {
            arb_vec(0x20u8..0x7eu8, 0..200).prop_map(|bytes| {
                String::from_utf8(bytes).expect("printable ascii bytes are valid utf-8")
            })
        }

        fn arb_mesh() -> impl Strategy<Value = MeshId> {
            "[1-9A-HJ-NP-Za-km-z]{4,24}".prop_map(|label| MeshId::from(label.as_str()))
        }

        proptest! {
            #![proptest_config(proptest_support::config())]
            // ── JSON response validity ────────────────────────────

            #[test]
            fn prop_json_ok_always_valid(id in arb_ascii_body()) {
                let _guard = ::habilis_network_test_tracing::init();
                let json = json_reply::json_ok(&id);
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("the json the ipc reply writes parses");
                prop_assert!(parsed["ok"] == true);
                prop_assert_eq!(&parsed["id"], &id as &str);
                        }

            #[test]
            fn prop_json_error_always_valid(message in arb_ascii_body()) {
                let _guard = ::habilis_network_test_tracing::init();
                let json = json_reply::json_error(&message);
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("the json the ipc reply writes parses");
                prop_assert!(parsed["ok"] == false);
                prop_assert_eq!(&parsed["error"], &message as &str);
                        }

            // ── Injection safety ──────────────────────────────────

            #[test]
            fn prop_json_ok_injection_safe(id in r#"["\\/\n\r\t]{1,50}"#) {
                let _guard = ::habilis_network_test_tracing::init();
                let json = json_reply::json_ok(&id);
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("the json the ipc reply writes parses");
                prop_assert_eq!(&parsed["id"], &id as &str);
                        }

            #[test]
            fn prop_json_error_injection_safe(message in r#"["\\/\n\r\t]{1,50}"#) {
                let _guard = ::habilis_network_test_tracing::init();
                let json = json_reply::json_error(&message);
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("the json the ipc reply writes parses");
                prop_assert_eq!(&parsed["error"], &message as &str);
                        }

            // ── Socket prefix ─────────────────────────────────────

            #[test]
            fn prop_mesh_prefix_max_16_chars(mesh in arb_mesh()) {
                let _guard = ::habilis_network_test_tracing::init();
                let prefix = util::mesh_prefix(mesh.as_str());
                prop_assert!(prefix.chars().count() <= 16);
                        }

            #[test]
            fn prop_mesh_prefix_is_prefix_of_input(mesh in arb_mesh()) {
                let _guard = ::habilis_network_test_tracing::init();
                let prefix = util::mesh_prefix(mesh.as_str());
                prop_assert!(mesh.as_str().starts_with(&prefix));
                        }
        }
    }

    // ── IPC round-trip via local socket ────────────────────────────

    /// Answer exactly one inbound command, then return. Split out of
    /// `ipc_listen_and_send_msg` so the match arms aren't nested inside the
    /// spawned future's `if let`.
    async fn respond_once(mut rx: mpsc::Receiver<IpcMessage<TestCommand>>) {
        let Some((command, resp_tx)) = rx.recv().await else {
            return;
        };
        match command {
            TestCommand::Msg { body, .. } => {
                let _ = resp_tx.send(json_reply::json_ok(&format!("got: {body}")));
            }
            TestCommand::Ping { .. } => {
                let _ = resp_tx.send(json_reply::json_error("unexpected command"));
            }
        }
    }

    #[test]
    fn ipc_listen_and_send_msg() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("roundtrip");
            let mesh = test_mesh("ipctest");
            let nickname = Nickname::from("test-nick");

            let (tx, rx): (
                mpsc::Sender<IpcMessage<TestCommand>>,
                mpsc::Receiver<IpcMessage<TestCommand>>,
            ) = mpsc::channel(8);

            // Bind synchronously (no sleep needed — the socket is accepting the
            // instant `bind` returns), then spawn the accept loop. The marker
            // exists the moment `bind` returns, too.
            let bound = listener::bind(base.path(), &mesh, &nickname).expect("bind IPC socket");
            #[cfg(windows)]
            assert!(
                ipc_marker::marker_path(base.path(), &mesh, &nickname).is_file(),
                "the marker exists when bind returns"
            );
            #[cfg(windows)]
            let (control, mut quit_rx) = test_control(&mesh);
            let listener_handle = tokio::spawn(listener::serve(
                bound.listener,
                tx,
                #[cfg(windows)]
                control,
                // trait object: the setup takes the silent sink as a shared handle
                sync::Arc::new(event::SilentSink),
            ));

            // Spawn a handler that responds to messages
            let handler = tokio::spawn(respond_once(rx));

            // Send a command
            let command = TestCommand::Msg {
                mesh: mesh.clone(),
                body: "test message".to_owned(),
            };
            let response = client::send(base.path(), &command, &nickname)
                .await
                .expect("the client reaches the local ipc listener");
            let parsed: serde_json::Value =
                serde_json::from_str(&response).expect("the ipc reply is json");
            assert_eq!(
                parsed["ok"], true,
                "a message sent over ipc gets an ok reply"
            );
            assert_eq!(
                parsed["id"], "got: test message",
                "the ipc reply carries the echoed message"
            );
            #[cfg(windows)]
            assert!(quit_rx.try_recv().is_err(), "an app command is no quit");

            handler.await.expect("the ipc handler task finishes");
            listener_handle.abort();
        });
    }

    #[test]
    fn accept_backoff_doubles_to_cap() {
        use crate::util::tuning::{IPC_ACCEPT_BACKOFF_MAX, IPC_ACCEPT_BACKOFF_MIN};

        let _guard = ::habilis_network_test_tracing::init();
        let cap = IPC_ACCEPT_BACKOFF_MAX;
        let mut backoff = IPC_ACCEPT_BACKOFF_MIN;
        let mut previous = backoff;
        for _ in 0..16 {
            backoff = listener::next_accept_backoff(backoff);
            assert!(backoff >= previous, "backoff never shrinks");
            assert!(backoff <= cap, "backoff never exceeds the cap");
            previous = backoff;
        }
        assert_eq!(backoff, cap, "sustained failure settles at the cap");
    }

    /// Answer every inbound command with `"healthy"` until the channel
    /// closes. Split out of `idle_connection_is_closed_at_the_read_deadline`
    /// so the loop body isn't nested inside the spawned future's `while let`.
    async fn respond_healthy_forever(mut rx: mpsc::Receiver<IpcMessage<TestCommand>>) {
        while let Some((_cmd, resp_tx)) = rx.recv().await {
            let _ = resp_tx.send(json_reply::json_ok("healthy"));
        }
    }

    // An idle client (connects, never sends) must be disconnected at the
    // I/O deadline instead of pinning a handler task + fd for the
    // daemon's lifetime, and the listener must keep serving others
    // throughout. Real-time: waits out `IPC_IO_TIMEOUT` (10s).
    #[test]
    fn idle_connection_is_closed_at_the_read_deadline() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use interprocess::local_socket::tokio::Stream;
            use interprocess::local_socket::traits::tokio::Stream as _;
            use tokio::io::AsyncReadExt;

            let base = TestBase::new("idle");
            let mesh = test_mesh("ipcquiet");
            let nickname = Nickname::from("idle-nick");
            let (tx, rx): (
                mpsc::Sender<IpcMessage<TestCommand>>,
                mpsc::Receiver<IpcMessage<TestCommand>>,
            ) = mpsc::channel(8);
            let bound = listener::bind(base.path(), &mesh, &nickname).expect("bind IPC socket");
            #[cfg(windows)]
            let (control, _quit_rx) = test_control(&mesh);
            let listener_handle = tokio::spawn(listener::serve(
                bound.listener,
                tx,
                #[cfg(windows)]
                control,
                // trait object: the setup takes the silent sink as a shared handle
                sync::Arc::new(event::SilentSink),
            ));
            // Echo handler so a healthy command still round-trips while the
            // idle connection is parked.
            let handler = tokio::spawn(respond_healthy_forever(rx));

            // Park a silent connection, found as a client finds it. The parked
            // client uses the plain `interprocess` connect: no SQOS and no owner
            // check. That is fine here: the server is this test's own listener,
            // and the test is about the server's read deadline. The user DACL
            // admits it, because the DACL names who may open, not how.
            let name = endpoint_of(base.path(), &mesh, &nickname);
            let mut idle = Stream::connect(name.to_name().expect("a valid name"))
                .await
                .expect("the idle connection reaches the listener");

            // A healthy command still round-trips while the idle one is parked.
            let command = TestCommand::Ping { mesh: mesh.clone() };
            let response = client::send(base.path(), &command, &nickname)
                .await
                .expect("the healthy command reaches the listener");
            assert!(response.contains("healthy"), "listener stalled: {response}");

            // The parked connection is closed (EOF) at the deadline, with margin.
            let mut sink = Vec::new();
            let read = time::timeout(
                tuning::IPC_IO_TIMEOUT + Duration::from_secs(5),
                idle.read_to_end(&mut sink),
            )
            .await;
            assert!(
                matches!(read, Ok(Ok(0))),
                "idle connection was not closed at the read deadline: {read:?}"
            );

            handler.abort();
            listener_handle.abort();
        });
    }

    // ── the engine's quit, Windows only ────────────────────────────

    // On Unix the IPC quit does not exist, and `terminate` is the signal of
    // before the port: it opens no connection.
    #[cfg(unix)]
    #[test]
    fn on_unix_quit_is_unsupported_and_terminate_sends_sigterm() {
        use rustix::process::Signal;
        use std::os::unix::process::ExitStatusExt as _;

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("termunix");
            let mesh = test_mesh("termunix");
            let nickname = Nickname::from("nobody");
            let target = QuitTarget::new(base.path(), &mesh, &nickname);
            assert!(
                matches!(quit(&target).await, Err(QuitError::Unsupported)),
                "the IPC quit is unsupported on Unix"
            );
            let mut child = process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn a child");
            terminate(&target, child.id()).await.expect("the signal");
            let status = child.wait().expect("wait for the child");
            assert_eq!(status.signal(), Some(Signal::TERM.as_raw()), "{status}");
        });
    }

    /// An engine control for `mesh`, and the receiver of its quit channel. The
    /// channel holds one quit, as the real one does.
    #[cfg(windows)]
    fn test_control(mesh: &MeshId) -> (engine_control::EngineControl, mpsc::Receiver<()>) {
        let (quit_tx, quit_rx) = mpsc::channel(1);
        (
            engine_control::EngineControl {
                mesh: mesh.clone(),
                quit_tx,
            },
            quit_rx,
        )
    }

    /// Whether the quit channel stays empty for a short time.
    #[cfg(windows)]
    async fn no_quit_within(quit_rx: &mut mpsc::Receiver<()>) -> bool {
        time::timeout(Duration::from_millis(200), quit_rx.recv())
            .await
            .is_err()
    }

    /// A bound test daemon whose engine control holds `session`, the mesh of
    /// the session; by default the mesh that it is bound under.
    #[cfg(windows)]
    struct TestServer<Cmd> {
        base: TestBase,
        mesh: MeshId,
        nickname: Nickname,
        app_rx: mpsc::Receiver<IpcMessage<Cmd>>,
        quit_rx: mpsc::Receiver<()>,
        accept: task::JoinHandle<()>,
    }

    #[cfg(windows)]
    impl<Cmd: de::DeserializeOwned + Send + 'static> TestServer<Cmd> {
        fn start(tag: &str, session: Option<&MeshId>) -> Self {
            let base = TestBase::new(tag);
            let mesh = test_mesh(tag);
            let nickname = Nickname::from("quit-nick");
            let (tx, app_rx): (
                mpsc::Sender<IpcMessage<Cmd>>,
                mpsc::Receiver<IpcMessage<Cmd>>,
            ) = mpsc::channel(8);
            let bound = listener::bind(base.path(), &mesh, &nickname).expect("bind IPC socket");
            let (control, quit_rx) = test_control(session.unwrap_or(&mesh));
            let accept = tokio::spawn(listener::serve(
                bound.listener,
                tx,
                control,
                // trait object: the setup takes the silent sink as a shared handle
                sync::Arc::new(event::SilentSink),
            ));
            Self {
                base,
                mesh,
                nickname,
                app_rx,
                quit_rx,
                accept,
            }
        }

        fn target(&self) -> QuitTarget<'_> {
            QuitTarget::new(self.base.path(), &self.mesh, &self.nickname)
        }

        fn name(&self) -> IpcName {
            endpoint_of(self.base.path(), &self.mesh, &self.nickname)
        }
    }

    #[cfg(windows)]
    impl<Cmd> Drop for TestServer<Cmd> {
        fn drop(&mut self) {
            self.accept.abort();
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_quit_command_and_its_answer_have_a_fixed_form() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = test_mesh("golden");
        let line =
            serde_json::to_string(&engine_control::EngineCommand::Quit { mesh: mesh.clone() })
                .expect("the quit serializes");
        assert_eq!(
            line,
            format!(r#"{{"command":"quit","mesh":"{}"}}"#, mesh.as_str()),
            "the quit line has a fixed form"
        );
        assert_eq!(
            json_reply::json_ack(),
            r#"{"ok":true}"#,
            "the ack has a fixed form"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_answer_to_a_quit_reads_as_its_outcome() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            quit::quit_outcome(&json_reply::json_ack()).is_ok(),
            "an ack is a quit"
        );
        assert!(
            matches!(
                quit::quit_outcome(&json_reply::json_error(
                    "parse error: unknown variant `quit`"
                )),
                Err(QuitError::OldDaemon(_))
            ),
            "a parse error is an old daemon"
        );
        assert!(
            matches!(
                quit::quit_outcome(&json_reply::json_error(
                    engine_control::QUIT_OF_ANOTHER_MESH
                )),
                Err(QuitError::Refused(_))
            ),
            "another mesh is a refusal"
        );
        assert!(
            matches!(quit::quit_outcome("not json"), Err(QuitError::Refused(_))),
            "no json is a refusal"
        );
        assert!(
            matches!(quit::quit_outcome(""), Err(QuitError::Unreached(_))),
            "no answer is not heard"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_quit_for_this_mesh_is_answered_then_fed_to_the_quit_channel() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut server: TestServer<TestCommand> = TestServer::start("quit", None);
            quit(&server.target()).await.expect("the quit is accepted");
            let fed = time::timeout(Duration::from_secs(5), server.quit_rx.recv())
                .await
                .expect("the quit channel is fed");
            assert_eq!(fed, Some(()), "the quit channel holds the quit");
            assert!(server.app_rx.try_recv().is_err(), "the app sees no quit");
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_quit_for_another_mesh_is_refused_and_feeds_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut server: TestServer<TestCommand> =
                TestServer::start("quitother", Some(&test_mesh("other")));
            let error = quit(&server.target()).await.expect_err("refused");
            assert!(matches!(error, QuitError::Refused(_)), "{error}");
            assert!(
                no_quit_within(&mut server.quit_rx).await,
                "the quit channel stays empty"
            );
            assert!(server.app_rx.try_recv().is_err(), "the app sees no quit");
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_line_that_is_no_valid_quit_reaches_the_app() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut server: TestServer<serde_json::Value> = TestServer::start("quitapp", None);
            let name = server.name();
            let lines = [
                serde_json::json!({ "command": "quit" }),
                serde_json::json!({ "command": "quit", "mesh": "no mesh id" }),
                serde_json::json!("quit"),
            ];
            let mut app_rx = mem::replace(&mut server.app_rx, mpsc::channel(1).1);
            let count = lines.len();
            let app = tokio::spawn(async move {
                let mut seen = Vec::new();
                while seen.len() < count {
                    let Some((command, response)) = app_rx.recv().await else {
                        break;
                    };
                    let _ = response.send(json_reply::json_ok("app"));
                    seen.push(command);
                }
                seen
            });
            for line in &lines {
                let reply = send_to_endpoint(&name, line)
                    .await
                    .expect("the line reaches the endpoint");
                assert!(reply.contains(r#""id":"app""#), "{line}: {reply}");
            }
            assert_eq!(
                app.await.expect("the app task ends"),
                lines,
                "the app sees every line"
            );
            assert!(
                no_quit_within(&mut server.quit_rx).await,
                "the quit channel stays empty"
            );
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_quit_with_no_daemon_is_not_heard() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("quitnone");
            let mesh = test_mesh("quitnone");
            let nickname = Nickname::from("nobody");
            let target = QuitTarget::new(base.path(), &mesh, &nickname);
            let error = quit(&target).await.expect_err("no daemon");
            assert!(matches!(error, QuitError::Unreached(_)), "{error}");
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_line_that_is_no_json_gets_the_parse_error_and_feeds_nothing() {
        use interprocess::local_socket::tokio::Stream;
        use interprocess::local_socket::traits::tokio::Stream as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut server: TestServer<TestCommand> = TestServer::start("quitraw", None);
            let name = server.name();
            let mut client: Stream = Stream::connect(name.to_name().expect("a valid name"))
                .await
                .expect("connect");
            client.write_all(b"not json\n").await.expect("write");
            let mut reply = String::new();
            time::timeout(Duration::from_secs(5), client.read_to_string(&mut reply))
                .await
                .expect("an answer")
                .expect("the answer reads");
            let reply: serde_json::Value =
                serde_json::from_str(reply.trim()).expect("the answer is json");
            assert!(
                reply["error"]
                    .as_str()
                    .is_some_and(|error| error.starts_with("parse error")),
                "{reply}"
            );
            assert!(
                no_quit_within(&mut server.quit_rx).await,
                "the quit channel stays empty"
            );
        });
    }

    #[cfg(windows)]
    #[test]
    fn an_app_that_cannot_parse_a_quit_reads_as_an_old_daemon() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut server: TestServer<TestCommand> = TestServer::start("quitold", None);
            // Not an engine quit, so the app parses it, as a daemon from before the
            // command does with a real quit.
            let reply = send_to_endpoint(&server.name(), &serde_json::json!({ "command": "quit" }))
                .await
                .expect("the line reaches the endpoint");
            assert!(
                matches!(quit::quit_outcome(&reply), Err(QuitError::OldDaemon(_))),
                "{reply}"
            );
            assert!(
                no_quit_within(&mut server.quit_rx).await,
                "the quit channel stays empty"
            );
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_second_quit_is_answered_and_the_channel_holds_one() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut server: TestServer<TestCommand> = TestServer::start("quittwice", None);
            quit(&server.target()).await.expect("the first quit");
            quit(&server.target()).await.expect("the second quit");
            // The server feeds the channel after its answer, so give both feeds a moment.
            time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                server.quit_rx.try_recv(),
                Ok(()),
                "the channel holds a quit"
            );
            assert!(
                no_quit_within(&mut server.quit_rx).await,
                "the channel holds one quit"
            );
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_quit_feeds_the_channel_also_when_the_client_does_not_read() {
        use interprocess::local_socket::tokio::Stream;
        use interprocess::local_socket::traits::tokio::Stream as _;
        use tokio::io::AsyncWriteExt;

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut server: TestServer<TestCommand> = TestServer::start("quitdeaf", None);
            // The plain `interprocess` connect, as in the idle test: this test is
            // about the server.
            let name = server.name();
            let mut client: Stream = Stream::connect(name.to_name().expect("a valid name"))
                .await
                .expect("connect");
            let line = serde_json::to_string(&engine_control::EngineCommand::Quit {
                mesh: server.mesh.clone(),
            })
            .expect("the quit serializes");
            client
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("write");
            let fed = time::timeout(Duration::from_secs(5), server.quit_rx.recv())
                .await
                .expect("the quit channel is fed while the answer is unread");
            assert_eq!(fed, Some(()), "the quit channel holds the quit");
            drop(client);
        });
    }

    #[cfg(windows)]
    #[test]
    fn on_windows_terminate_is_the_quit_alone() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let base = TestBase::new("termwin");
            let mesh = test_mesh("termwin");
            let nickname = Nickname::from("nobody");
            let target = QuitTarget::new(base.path(), &mesh, &nickname);
            // The pid is not used on Windows, so our own is safe here.
            let error = terminate(&target, process::id())
                .await
                .expect_err("no daemon");
            let quit_error: Option<&QuitError> =
                error.get_ref().and_then(|inner| inner.downcast_ref());
            assert!(
                matches!(quit_error, Some(QuitError::Unreached(_))),
                "{error}"
            );
        });
    }
}

#[cfg(test)]
mod chain_tests {

    use super::IpcError;

    use std::io;
    use std::io::ErrorKind;
    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let io = io::Error::new(ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(IpcError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of IpcError is lost: {text}"
        );
    }
}
