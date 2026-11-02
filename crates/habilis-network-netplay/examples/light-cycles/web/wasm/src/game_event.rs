use serde::Serialize;

/// A lobby change since the last [`Game::drain_events`] call — the JS
/// side has no HUD loop of its own to notice this directly, unlike
/// `native/game`'s TUI, which redraws the whole roster every frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum GameEvent {
    Joined { pubkey: String, nick: String },
    Left { pubkey: String, nick: String },
}
