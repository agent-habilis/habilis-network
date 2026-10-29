//! The JSON replies the IPC socket sends back.

use crate::protocol::{MessageId, message};
/// Richer `ok` response for the `msg` IPC that also echoes back
/// the authoritative message record. The echo has the same shape
/// `poll` returns per entry — `serde_json::to_value(msg)` — so
/// agents can treat it uniformly with `fetch_messages` results.
///
/// A caller that only reads `response["id"]` gets the id; the MCP server
/// reads the embedded `"message"` field for the full record.
#[must_use]
/// # Panics
/// Panics if an internal invariant is violated.
pub fn json_ok_msg(id: &MessageId, message: &message::Verified) -> String {
    serde_json::json!({
        "ok": true,
        "id": id,
        "message": serde_json::to_value(message).expect("Message serialize is infallible"),
    })
    .to_string()
}

/// Lean `{ok, id}` response — used by IPC commands that don't have
/// a message to echo back (currently test-only).
#[cfg(test)]
pub(crate) fn json_ok(id: &str) -> String {
    serde_json::json!({"ok": true, "id": id}).to_string()
}

/// Bare `{ok:true}` ack for fire-and-forget IPC commands (`ping`) that
/// have no id or payload to return.
#[must_use]
pub fn json_ack() -> String {
    serde_json::json!({"ok": true}).to_string()
}

/// The JSON reply of a failed IPC command, with `ok` false and the `error` text.
#[must_use]
pub fn json_error(error: &str) -> String {
    serde_json::json!({"ok": false, "error": error}).to_string()
}
