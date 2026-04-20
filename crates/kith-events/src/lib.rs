use tokio::sync::broadcast;

pub use kith_core::StateChange;

/// Type alias for the sending half of the events broadcast channel.
pub type EventSender = broadcast::Sender<StateChange>;

/// Type alias for the receiving half of the events broadcast channel.
pub type EventReceiver = broadcast::Receiver<StateChange>;

/// Create a broadcast channel for state-change notifications.
///
/// The recommended capacity is 64: large enough that a burst of writes
/// does not drop events before the EventSource handler can drain them,
/// small enough to avoid unbounded memory growth.
///
/// Callers that fall behind will receive `RecvError::Lagged`; they should
/// resync via `<Type>/changes` with their last known state token.
pub fn make_channel(capacity: usize) -> (EventSender, EventReceiver) {
    broadcast::channel(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_core::StateChange;

    #[tokio::test]
    async fn test_channel_roundtrip() {
        let (tx, mut rx) = make_channel(64);
        let original = StateChange {
            type_name: "Message".to_string(),
            new_state: "s-1".to_string(),
        };
        let _ = tx.send(original.clone());
        let received = rx.recv().await.expect("recv must succeed");
        assert_eq!(received.type_name, original.type_name);
        assert_eq!(received.new_state, original.new_state);
    }

    #[tokio::test]
    async fn test_channel_multiple_subscribers() {
        let (tx, mut rx1) = make_channel(64);
        let mut rx2 = tx.subscribe();
        let msg = StateChange {
            type_name: "Chat".to_string(),
            new_state: "s-2".to_string(),
        };
        tx.send(msg.clone())
            .expect("send must succeed with two receivers");
        let r1 = rx1.recv().await.expect("rx1 must receive");
        let r2 = rx2.recv().await.expect("rx2 must receive");
        assert_eq!(r1.type_name, msg.type_name);
        assert_eq!(r1.new_state, msg.new_state);
        assert_eq!(r2.type_name, msg.type_name);
        assert_eq!(r2.new_state, msg.new_state);
    }

    #[tokio::test]
    async fn test_channel_no_receivers_ok() {
        let (tx, rx) = make_channel(64);
        drop(rx);
        let result = tx.send(StateChange {
            type_name: "Contact".to_string(),
            new_state: "s-3".to_string(),
        });
        // SendError when no receivers is expected; must not panic
        assert!(
            result.is_err(),
            "send with no receivers must return SendError"
        );
    }

    #[test]
    fn test_store_set_events_tx() {
        let mut store = kith_store::Store::open_in_memory().expect("in-memory store must open");
        assert!(store.events_tx.is_none(), "events_tx must start as None");
        let (tx, _rx) = make_channel(64);
        store.set_events_tx(tx);
        assert!(
            store.events_tx.is_some(),
            "events_tx must be Some after set"
        );
    }

    // -----------------------------------------------------------------------
    // test_lagged_receiver_skips
    // Oracle: tokio broadcast channel semantics (tokio docs §broadcast).
    // When a receiver falls behind and messages are dropped, recv() returns
    // Err(RecvError::Lagged(n)) indicating n messages were dropped.  After
    // that, the receiver continues to deliver subsequent messages normally.
    // BroadcastStream maps Lagged to Err items, not stream termination.
    // filter_map that drops Err items must let the stream continue and end
    // cleanly when the sender is dropped (RecvError::Closed → stream end).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_lagged_receiver_skips() {
        use tokio_stream::{wrappers::BroadcastStream, StreamExt};

        // capacity 1 — easy to overflow with 3 sends
        let (tx, rx) = make_channel(1);

        // Send 3 messages: only the last one survives in the ring buffer.
        // rx has not consumed anything, so it will receive Lagged(2) then msg3.
        let _ = tx.send(StateChange {
            type_name: "Contact".to_string(),
            new_state: "s-1".to_string(),
        });
        let _ = tx.send(StateChange {
            type_name: "Chat".to_string(),
            new_state: "s-2".to_string(),
        });
        let _ = tx.send(StateChange {
            type_name: "Message".to_string(),
            new_state: "s-3".to_string(),
        });

        // Drop tx so the BroadcastStream terminates after draining.
        drop(tx);

        // Wrap in BroadcastStream; filter_map skips Lagged errors without
        // terminating the stream — only Ok(StateChange) values are yielded.
        let events: Vec<StateChange> = BroadcastStream::new(rx)
            .filter_map(|result| result.ok())
            .collect()
            .await;

        // Oracle: capacity-1 channel with 3 sends retains only the last
        // message.  The stream must yield exactly 1 event (s-3) without
        // panicking or propagating the Lagged error as a stream termination.
        assert_eq!(
            events.len(),
            1,
            "exactly one message survives in a capacity-1 channel after 3 sends"
        );
        assert_eq!(events[0].type_name, "Message");
        assert_eq!(events[0].new_state, "s-3");
        // Key assertion: stream ended normally (collect returned) — no panic.
    }
}
