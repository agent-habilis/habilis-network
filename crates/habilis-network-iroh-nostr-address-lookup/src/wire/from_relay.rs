//! A frame from a relay.

use serde_json::Value;

use crate::event::Event;

/// A frame from a relay. Anything we do not act on is `Other`.
#[derive(Debug)]
pub(crate) enum FromRelay {
    Event {
        sub_id: String,
        event: Event,
    },
    Ok {
        accepted: bool,
        reason: String,
    },
    Closed {
        sub_id: String,
        reason: String,
    },
    /// The relay finished the stored events of a REQ: it serves us.
    Eose,
    Other,
}

pub(crate) fn parse(text: &str) -> FromRelay {
    let parsed: Result<Value, _> = serde_json::from_str(text);
    let Ok(Value::Array(items)) = parsed else {
        return FromRelay::Other;
    };
    let string = |index: usize| items.get(index).and_then(Value::as_str).map(str::to_owned);
    match items.first().and_then(Value::as_str) {
        Some("EVENT") => {
            let (Some(sub_id), Some(raw)) = (string(1), items.get(2)) else {
                return FromRelay::Other;
            };
            match serde_json::from_value(raw.clone()) {
                Ok(event) => FromRelay::Event { sub_id, event },
                Err(_) => FromRelay::Other,
            }
        }
        Some("OK") => FromRelay::Ok {
            accepted: items.get(2).and_then(Value::as_bool).unwrap_or(false),
            reason: string(3).unwrap_or_default(),
        },
        Some("CLOSED") => FromRelay::Closed {
            sub_id: string(1).unwrap_or_default(),
            reason: string(2).unwrap_or_default(),
        },
        Some("EOSE") => FromRelay::Eose,
        _ => FromRelay::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{FromRelay, parse};
    use crate::event::{Event, Keys};
    use crate::lane::Lane;

    #[test]
    fn relay_frames_parse() {
        let event = Event::sign(Lane::Signal, &Keys::generate(), 1, &[1u8; 32], "c".into());
        let text = serde_json::json!(["EVENT", "s1", event]).to_string();
        assert!(
            matches!(parse(&text), FromRelay::Event { sub_id, event: got } if sub_id == "s1" && got == event),
            "an EVENT frame names its sub_id and carries the event"
        );
        assert!(
            matches!(
                parse(r#"["OK","abc",false,"rate-limited: x"]"#),
                FromRelay::Ok { accepted: false, reason } if reason == "rate-limited: x"
            ),
            "an OK frame carries the verdict and the reason"
        );
        assert!(
            matches!(
                parse(r#"["CLOSED","s1","blocked: no"]"#),
                FromRelay::Closed { sub_id, reason } if sub_id == "s1" && reason == "blocked: no"
            ),
            "a CLOSED frame names its sub_id and the reason"
        );
        assert!(
            matches!(parse(r#"["EOSE","s1"]"#), FromRelay::Eose),
            "EOSE means the relay finished the stored events"
        );
        assert!(
            matches!(parse(r#"["NOTICE","hi"]"#), FromRelay::Other),
            "a frame we do not act on is Other"
        );
        assert!(
            matches!(parse("not json"), FromRelay::Other),
            "text that is not JSON is Other"
        );
    }
}
