//! A subscription filter, and the frames a client sends a relay.

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

pub(crate) fn request(sub_id: &str, filter: &Filter, now: u64) -> String {
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

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{Filter, request};

    #[test]
    fn a_req_carries_kinds_tags_and_since() {
        let filter = Filter {
            kinds: vec![20_001],
            tags: vec!["ab".into()],
        };
        let value: Value =
            serde_json::from_str(&request("s1", &filter, 1000)).expect("the REQ is JSON");
        assert_eq!(
            value,
            serde_json::json!(["REQ", "s1", {"kinds": [20001], "#x": ["ab"], "since": 880}]),
            "the REQ names the kinds and the tag, and reaches 120 s before now"
        );
    }
}
