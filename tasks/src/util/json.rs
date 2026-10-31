/// `Runtime.evaluate` and `execute/sync` both hand back a JSON value; a string
/// result should read as its contents, not as a quoted literal.
pub(crate) fn json_to_string(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}
