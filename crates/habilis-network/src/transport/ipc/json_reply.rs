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
///
/// # Examples
///
/// It renders the reply that says a message was sent, as JSON. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::protocol::{MessageId, Verified};
/// use habilis_network::runtime::ipc::json_ok_msg;
///
/// # fn demo(id: &MessageId, message: &Verified) -> String {
/// json_ok_msg(id, message)
/// # }
/// ```
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
///
/// # Examples
///
/// The acknowledgement reply is valid JSON.
///
/// ```
/// use habilis_network::runtime::ipc::json_ack;
///
/// let ack = json_ack();
/// assert!(serde_json::from_str::<serde_json::Value>(&ack).is_ok());
/// ```
#[must_use]
pub fn json_ack() -> String {
    serde_json::json!({"ok": true}).to_string()
}

/// The JSON reply of a failed IPC command, with `ok` false and the `error` text.
///
/// # Examples
///
/// The error reply carries the error text it was given.
///
/// ```
/// use habilis_network::runtime::ipc::json_error;
///
/// assert!(json_error("boom").contains("boom"));
/// ```
#[must_use]
pub fn json_error(error: &str) -> String {
    serde_json::json!({"ok": false, "error": error}).to_string()
}
