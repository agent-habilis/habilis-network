# habilis-network-logging

The tracing sink and directive filter for habilis-network.

Three pieces: `log_filter` (the directive filter that pins connectivity
targets to `info` in release builds), the deferred per-member file sink
(`LogSink`), and the per-message logger on the `habilis_network::messages` target.

`--output json` on stdout is a separate path. Nothing here touches it.

See `src/lib.rs` for the API.
