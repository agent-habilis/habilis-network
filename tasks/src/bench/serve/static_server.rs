use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use crate::util::{reachable, wait_for};

pub(crate) struct StaticServer {
    pub(crate) url: String,
}

impl StaticServer {
    /// Serve `www/` at `/` and `wasm/` at `/wasm/`, and wait until the socket
    /// answers.
    pub(crate) fn serve(www: PathBuf, wasm: PathBuf) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("could not bind the page server: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("the page server has no address: {error}"))?
            .port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = super::respond(stream, &www, &wasm);
            }
        });
        let url = format!("http://127.0.0.1:{port}");
        let up = wait_for(Duration::from_secs(5), Duration::from_millis(100), || {
            reachable(&url).then_some(())
        });
        if up.is_none() {
            return Err("the page server never came up".to_owned());
        }
        Ok(Self { url })
    }
}
