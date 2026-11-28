mod addressed;
pub use addressed::Addressed;
mod client;
pub use client::{active_socket_paths, send, send_to_path};
mod denied;
pub use denied::Denied;
mod ipc_error;
pub use ipc_error::IpcError;
mod json_reply;
pub use json_reply::{json_ack, json_error, json_ok_msg};
mod listener;
pub(crate) use listener::{bind, serve};
mod no_daemon;
pub use no_daemon::NoDaemon;

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{Addressed, client, json_reply, listener};
    use crate::protocol::{MeshId, Nickname};
    use crate::transport::IpcMessage;
    use tokio::sync::mpsc;

    use crate::gossip::event;
    use crate::util;
    use crate::util::tuning;
    use std::time::Duration;
    use std::{path, process, sync};
    use tokio::time;
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

    /// A base of this suite's own, so a test that binds a real socket can never
    /// collide with (or be found by) a daemon running under a product's base.
    fn test_base() -> path::PathBuf {
        util::runtime_base("habilis-network-ipc-test")
    }

    #[test]
    fn socket_path_format() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("abcdefghijkmnpqr");
        let base = test_base();
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
            // Base58-encode the pid so the mesh id passes strict charset validation.
            let pid_b58 = bs58::encode(process::id().to_le_bytes()).into_string();
            let mesh = MeshId::from(format!("ipctest{pid_b58}").as_str());
            let nickname = Nickname::from("test-nick");

            let (tx, rx): (
                mpsc::Sender<IpcMessage<TestCommand>>,
                mpsc::Receiver<IpcMessage<TestCommand>>,
            ) = mpsc::channel(8);

            // Bind synchronously (no sleep needed — the socket is accepting the
            // instant `bind` returns), then spawn the accept loop.
            let listener = listener::bind(&test_base(), &mesh, &nickname).expect("bind IPC socket");
            let listener_handle = tokio::spawn(listener::serve(
                listener,
                tx,
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
            let response = client::send(&test_base(), &command, &nickname)
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

            let pid_b58 = bs58::encode(process::id().to_le_bytes()).into_string();
            let mesh = MeshId::from(format!("ipcquiet{pid_b58}").as_str());
            let nickname = Nickname::from("idle-nick");
            let (tx, rx): (
                mpsc::Sender<IpcMessage<TestCommand>>,
                mpsc::Receiver<IpcMessage<TestCommand>>,
            ) = mpsc::channel(8);
            let listener = listener::bind(&test_base(), &mesh, &nickname).expect("bind IPC socket");
            let listener_handle = tokio::spawn(listener::serve(
                listener,
                tx,
                // trait object: the setup takes the silent sink as a shared handle
                sync::Arc::new(event::SilentSink),
            ));
            // Echo handler so a healthy command still round-trips while the
            // idle connection is parked.
            let handler = tokio::spawn(respond_healthy_forever(rx));

            // Park a silent connection.
            let path = listener::socket_path(&test_base(), &mesh, &nickname);
            let name = listener::to_name(&path).expect("the socket path is a valid file name");
            let mut idle = Stream::connect(name)
                .await
                .expect("the idle connection reaches the listener");

            // A healthy command still round-trips while the idle one is parked.
            let command = TestCommand::Ping { mesh: mesh.clone() };
            let response = client::send(&test_base(), &command, &nickname)
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
}

#[cfg(test)]
mod chain_tests {

    use super::{Denied, IpcError, NoDaemon, client};
    use crate::protocol::Nickname;

    use rustix::io::Errno;
    use std::io::ErrorKind;
    use std::os::unix::net::UnixStream;
    use std::{env, fs, io, process};

    const SOCKET: &str = "/tmp/habilis/mesh/nick.ipc.sock";

    #[test]
    fn a_denied_connect_is_typed_as_denied() {
        let _guard = ::habilis_network_test_tracing::init();
        let error = io::Error::from(ErrorKind::PermissionDenied);
        let nickname = Nickname::from("nick");
        for named in [Some(&nickname), None] {
            let typed = client::connect_error(&error, SOCKET, named);
            assert!(
                matches!(&typed, IpcError::Denied(Denied { socket, .. }) if socket == SOCKET),
                "a PermissionDenied connect is not typed as Denied: {typed:?}"
            );
        }
    }

    #[test]
    fn a_missing_or_refused_socket_is_no_daemon() {
        let _guard = ::habilis_network_test_tracing::init();
        let nickname = Nickname::from("nick");
        for kind in [ErrorKind::NotFound, ErrorKind::ConnectionRefused] {
            let typed = client::connect_error(&io::Error::from(kind), SOCKET, Some(&nickname));
            assert!(
                matches!(&typed, IpcError::NoDaemon(NoDaemon { nickname: named }) if *named == nickname),
                "a {kind:?} connect is not typed as NoDaemon: {typed:?}"
            );
        }
    }

    #[test]
    fn another_connect_error_is_internal_and_keeps_its_text() {
        let _guard = ::habilis_network_test_tracing::init();
        let nickname = Nickname::from("nick");
        for named in [Some(&nickname), None] {
            let typed = client::connect_error(&io::Error::from(ErrorKind::TimedOut), SOCKET, named);
            assert!(
                matches!(&typed, IpcError::Internal(_)) && typed.to_string().contains(SOCKET),
                "a TimedOut connect is not Internal with the socket in its text: {typed:?}"
            );
        }
    }

    #[test]
    fn denied_says_the_operating_system_denied_access() {
        let _guard = ::habilis_network_test_tracing::init();
        let text = IpcError::Denied(Denied {
            socket: SOCKET.to_owned(),
            os_error: Some(1),
        })
        .to_string();
        assert!(
            text.contains("denied access to the daemon socket")
                && text.contains(SOCKET)
                && text.contains("os error 1"),
            "the Denied text does not name the denial, the socket and the OS error: {text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_denied_connect_keeps_the_os_error_number() {
        let _guard = ::habilis_network_test_tracing::init();
        for code in [Errno::PERM, Errno::ACCESS] {
            let error = io::Error::from_raw_os_error(code.raw_os_error());
            let typed = client::connect_error(&error, SOCKET, None);
            assert!(
                matches!(&typed, IpcError::Denied(Denied { os_error, .. }) if *os_error == Some(code.raw_os_error())),
                "a denied connect with {code:?} does not keep its OS error number: {typed:?}"
            );
        }
    }

    // A real connect: a socket path in a folder of mode 000 is denied with EACCES.
    #[cfg(unix)]
    #[test]
    fn a_connect_in_a_folder_of_mode_000_is_denied_with_eacces() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use std::os::unix::fs::PermissionsExt as _;
            let folder = env::temp_dir().join(format!("habilis-ipc-denied-{}", process::id()));
            fs::create_dir_all(&folder).expect("the test folder is made");
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o000))
                .expect("the test folder is closed");
            let blocked = fs::read_dir(&folder).is_err();
            let socket = folder.join("nick.ipc.sock");
            let result =
                client::send_to_path(&socket, &serde_json::json!({"command": "ping"})).await;
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o700))
                .expect("the test folder is opened");
            fs::remove_dir(&folder).expect("the test folder is removed");
            if !blocked {
                return; // root reads a folder of mode 000, so nothing is denied
            }
            let error = result.expect_err("a connect in a closed folder fails");
            assert!(
                matches!(&error, IpcError::Denied(Denied { os_error, .. }) if *os_error == Some(Errno::ACCESS.raw_os_error())),
                "a connect in a folder of mode 000 is not Denied with EACCES: {error:?}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_regular_file_at_the_socket_path_is_no_daemon() {
        let _guard = ::habilis_network_test_tracing::init();
        let file = env::temp_dir().join(format!("habilis-ipc-notsock-{}", process::id()));
        fs::write(&file, b"").expect("the test file is written");
        let real = UnixStream::connect(&file).expect_err("a connect to a regular file fails");
        fs::remove_file(&file).expect("the test file is removed");
        assert_eq!(
            real.raw_os_error(),
            Some(Errno::NOTSOCK.raw_os_error()),
            "a connect to a regular file does not give ENOTSOCK on this platform"
        );
        let nickname = Nickname::from("nick");
        let typed = client::connect_error(&real, SOCKET, Some(&nickname));
        assert!(
            matches!(&typed, IpcError::NoDaemon(_)),
            "a regular file at the socket path is not NoDaemon: {typed:?}"
        );
    }

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
