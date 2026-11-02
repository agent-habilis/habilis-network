//! A static server for the benchmark pages, on a free port.
//!
//! `std::net` only: the runner has an HTTP client for the drivers but no
//! server, and sixty lines of `GET` is cheaper than a dependency or a bun
//! process for three files. The accept loop runs on a detached thread and
//! dies with the runner; the listener is never reused across runs.

use std::{fs, io};
mod static_server;

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::Path;

pub(crate) use static_server::StaticServer;

fn respond(mut stream: TcpStream, www: &Path, wasm: &Path) -> io::Result<()> {
    let mut request = [0u8; 4096];
    let read = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let wanted = match path {
        "/" | "/index.html" => Some(www.join("index.html")),
        "/raw.html" => Some(www.join("raw.html")),
        _ => path
            .strip_prefix("/wasm/")
            .filter(|name| !name.contains("..") && !name.contains('/'))
            .map(|name| wasm.join(name)),
    };
    let found = wanted.and_then(|file| fs::read(&file).ok().map(|body| (file, body)));

    let Some((file, body)) = found else {
        return stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    };
    let content_type = match file.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html",
        Some("js") => "text/javascript",
        // `instantiateStreaming` refuses anything else; the glue falls back,
        // with a warning, but there is no reason to make it.
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)
}
