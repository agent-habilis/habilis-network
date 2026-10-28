/// Serialize `value` as the JSON body of a control frame, or `None` when it
/// will not fit a [`MessageBody`](crate::protocol::MessageBody).
///
/// Both failure modes are unreachable for the types that use this — a struct of
/// strings and numbers always serializes, and its JSON carries no control
/// characters — but a control broadcast that cannot build its body drops the
/// tick rather than panicking, so every caller was writing the same pair of
/// `let ... else { return; }` guards.
pub(crate) fn json_body<T: serde::Serialize>(value: &T) -> Option<crate::protocol::MessageBody> {
    let json = serde_json::to_string(value).ok()?;
    crate::protocol::MessageBody::try_new(json).ok()
}
