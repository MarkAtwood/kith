//! Space-layer store operations (draft-atwood-jmap-chat-00 §4.20-4.27).
//!
//! Provides CRUD for Space, SpaceRole, SpaceMember, Category,
//! SpaceInvite, SpaceBan, and channel permission overrides.

use kith_core::StateChange;
use rusqlite::Connection;
use tokio::sync::broadcast;

/// Store view for Space-layer operations.
pub struct SpaceStore<'a> {
    conn: &'a Connection,
    events_tx: Option<&'a broadcast::Sender<StateChange>>,
}

impl<'a> SpaceStore<'a> {
    pub(crate) fn new(
        conn: &'a Connection,
        events_tx: Option<&'a broadcast::Sender<StateChange>>,
    ) -> Self {
        Self { conn, events_tx }
    }
}
