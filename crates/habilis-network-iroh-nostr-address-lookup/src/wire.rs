//! The NIP-01 frames between a client and a relay, and what a relay's refusal
//! means for us.

use serde_json::Value;

use crate::event::{Event, TAG};

/// A subscription filter: the kinds and `x` tags to deliver. `since` is filled
/// in when the REQ is sent, so a resubscribe after a reconnect asks only for
/// what comes next.
///
/// It reaches [`SINCE_SLACK`] into the past because a relay compares it with
/// the *publisher's* clock: a subscription that starts at our "now" drops
/// every event from a peer whose clock is behind ours. Ephemeral events are
/// never stored, so the slack returns nothing old.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Filter {
    pub(crate) kinds: Vec<u32>,
    pub(crate) tags: Vec<String>,
}

/// Matches the engine's replay window: a peer skewed by less than this is one
/// it would accept.
pub(crate) const SINCE_SLACK: u64 = 120;

pub(crate) fn req(sub_id: &str, filter: &Filter, now: u64) -> String {
    let since = now.saturating_sub(SINCE_SLACK);
    let mut object = serde_json::Map::new();
    object.insert("kinds".into(), filter.kinds.clone().into());
    object.insert(format!("#{TAG}"), filter.tags.clone().into());
    object.insert("since".into(), since.into());
    serde_json::json!(["REQ", sub_id, object]).to_string()
}

pub(crate) fn close(sub_id: &str) -> String {
    serde_json::json!(["CLOSE", sub_id]).to_string()
}

pub(crate) fn event(event: &Event) -> String {
    serde_json::json!(["EVENT", event]).to_string()
}

/// A frame from a relay. Anything we do not act on is `Other`.
#[derive(Debug)]
pub(crate) enum FromRelay {
    Event { sub_id: String, event: Event },
    Ok { accepted: bool, reason: String },
    Closed { sub_id: String, reason: String },
    Other,
}

pub(crate) fn parse(text: &str) -> FromRelay {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(text) else {
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
        _ => FromRelay::Other,
    }
}

/// What a refusal's machine-readable prefix (NIP-01) tells us to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Slow down: back off before the next publish or REQ.
    RateLimited,
    /// This relay will never serve us: stop using it for good.
    Retire,
    /// Harmless: the relay already has it.
    Duplicate,
    /// Anything else: log it and carry on.
    Other,
}

pub(crate) fn classify(reason: &str) -> Verdict {
    let prefix = reason.split(':').next().unwrap_or_default();
    match prefix {
        "rate-limited" => Verdict::RateLimited,
        "blocked" | "restricted" | "auth-required" | "pow" => Verdict::Retire,
        "duplicate" => Verdict::Duplicate,
        _ => Verdict::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Keys;

    #[test]
    fn refusal_prefixes_map_to_what_trystero_does() {
        assert_eq!(classify("rate-limited: slow down"), Verdict::RateLimited);
        for terminal in [
            "blocked: you are banned",
            "restricted: members only",
            "auth-required: NIP-42",
            "pow: difficulty 20",
        ] {
            assert_eq!(classify(terminal), Verdict::Retire, "{terminal}");
        }
        assert_eq!(classify("duplicate: have it"), Verdict::Duplicate);
        assert_eq!(classify("error: disk full"), Verdict::Other);
        assert_eq!(classify(""), Verdict::Other);
    }

    #[test]
    fn a_req_carries_kinds_tags_and_since() {
        let filter = Filter {
            kinds: vec![20_001],
            tags: vec!["ab".into()],
        };
        let value: Value = serde_json::from_str(&req("s1", &filter, 1000)).unwrap();
        assert_eq!(
            value,
            serde_json::json!(["REQ", "s1", {"kinds": [20001], "#x": ["ab"], "since": 880}])
        );
    }

    #[test]
    fn relay_frames_parse() {
        let event = Event::sign(&Keys::generate(), 1, &[1u8; 32], "c".into());
        let text = serde_json::json!(["EVENT", "s1", event]).to_string();
        assert!(
            matches!(parse(&text), FromRelay::Event { sub_id, event: got } if sub_id == "s1" && got == event)
        );
        assert!(matches!(
            parse(r#"["OK","abc",false,"rate-limited: x"]"#),
            FromRelay::Ok { accepted: false, reason } if reason == "rate-limited: x"
        ));
        assert!(matches!(
            parse(r#"["CLOSED","s1","blocked: no"]"#),
            FromRelay::Closed { sub_id, reason } if sub_id == "s1" && reason == "blocked: no"
        ));
        assert!(matches!(parse(r#"["EOSE","s1"]"#), FromRelay::Other));
        assert!(matches!(parse("not json"), FromRelay::Other));
    }
}
