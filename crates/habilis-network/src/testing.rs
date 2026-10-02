//! Fixtures every unit-test module in this crate was writing for itself.
//!
//! `fresh_state` in particular was copy-pasted into six modules, which is what
//! made [`StateInit`] painful to extend: one new field meant editing six test
//! modules that had no reason to know about it. One home instead.

use std::sync::Arc;

use iroh::{EndpointId, SecretKey};

use crate::daemon::state::{EventLoopState, MeshSecrets, StateInit};
use crate::protocol::Nickname;
use crate::protocol::identity::Identity;
use crate::util::clock::Instant;

/// A bare state with a fresh identity: no state file, no secrets, no per-peer
/// gate. The starting point for a test that only cares about one field.
pub(crate) fn fresh_state() -> EventLoopState {
    EventLoopState::new(
        StateInit {
            state_file: None,
            identity: Arc::new(Identity::generate()),
            secrets: MeshSecrets::default(),
            per_peer_gate: None,
            webrtc_admission: crate::transport::SignalAdmission::new(
                crate::transport::MAX_DIRECT_PEERS,
            ),
            webrtc_ice: crate::transport::IceProfile::default(),
        },
        Instant::now(),
    )
}

/// A nickname, panicking on an invalid one — a test fixture, so a bad literal
/// should fail loudly at the assertion rather than be handled.
pub(crate) fn nick(name: &str) -> Nickname {
    Nickname::new(name.to_owned()).expect("valid test nickname")
}

/// A deterministic endpoint id from `seed`, so a test can name the same peer
/// twice and assert on identity.
pub(crate) fn endpoint_id(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

/// A relay url for a loopback listener that never accepts: the relay
/// handshake hangs, as it does on a rung that is slow to answer. Keep the
/// listener alive for as long as the url is in use.
#[cfg(feature = "host")]
pub(crate) fn silent_relay_rung() -> (std::net::TcpListener, iroh::RelayUrl) {
    let silent = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("a silent loopback listener");
    let rung = format!("http://{}", silent.local_addr().expect("its address"))
        .parse()
        .expect("a relay url");
    (silent, rung)
}

/// Run `body` on a fresh current-thread runtime, drop the runtime as
/// returning from `main` does, and return every ERROR logged meanwhile. That
/// drop is where iroh logs `Endpoint dropped without calling` for an endpoint
/// a task still held open.
#[cfg(feature = "host")]
pub(crate) fn errors_through_runtime_drop(body: impl Future<Output = ()>) -> String {
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let logs = Captured::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::ERROR)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(body);
    drop(runtime);
    let logs = logs.0.lock().expect("log buffer");
    String::from_utf8_lossy(&logs).into_owned()
}
