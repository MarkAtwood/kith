use serde::{Deserialize, Serialize};

/// A state-change notification emitted by the store layer when any JMAP
/// object type advances its state counter.
///
/// Consumers subscribe via `kith_events::make_channel` and receive one
/// `StateChange` for every object type that was modified.  The receiver
/// calls `<Type>/changes` to pull the delta — the event only signals
/// *that* a change occurred, not *what* changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// JMAP object type name, e.g. "ChatContact", "Chat", "Message".
    pub type_name: String,
    /// New opaque state token, e.g. "s-42".
    pub new_state: String,
}
