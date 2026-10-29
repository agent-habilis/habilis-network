use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::util::wait_for;

use crate::e2e::Skip;

use crate::util;
use std::path;
/// A Bun dev server (the harness page, the chat page), killed when it goes
/// out of scope. Stderr is discarded — the old piped-but-never-read handle
/// could only ever stall the child on a full pipe.
pub(in crate::e2e) struct BunServer {
    child: Child,
    pub(in crate::e2e) url: String,
}

impl Drop for BunServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl BunServer {
    pub(in crate::e2e) fn serve(dir: &path::Path, script: &str, what: &str) -> Result<Self, Skip> {
        let port = super::free_port()?;
        let child = Command::new("bun")
            .arg("run")
            .arg(script)
            .arg(port.to_string())
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Skip(format!("could not start bun for {what}: {error}")))?;
        let server = Self {
            child,
            url: format!("http://127.0.0.1:{port}"),
        };
        let up = wait_for(Duration::from_secs(30), Duration::from_millis(250), || {
            util::reachable(&server.url).then_some(())
        });
        if up.is_none() {
            return Err(Skip(format!("the {what} server never came up")));
        }
        Ok(server)
    }
}
