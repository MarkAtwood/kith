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
///
/// # Panics
/// Panics if `capacity == 0`. This mirrors the behaviour of the underlying
/// `tokio::sync::broadcast::channel` (which also panics on zero capacity).
/// The assert fires first to give a clearer error message. All production
/// call sites use a hardcoded non-zero literal; if you need a variable
/// capacity, use `std::num::NonZeroUsize` at the call site to enforce the
/// constraint before calling this function.
pub fn make_channel(capacity: usize) -> (EventSender, EventReceiver) {
    assert!(
        capacity > 0,
        "broadcast channel capacity must be greater than zero (tokio would also panic)"
    );
    broadcast::channel(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_core::StateChange;

    #[tokio::test]
    async fn test_channel_roundtrip() {
        let (tx, mut rx) = make_channel(64);
        let original = StateChange::new("Message", "s-1");
        let _ = tx.send(original.clone());
        let received = rx.recv().await.expect("recv must succeed");
        assert_eq!(received.type_name, original.type_name);
        assert_eq!(received.new_state, original.new_state);
    }

    #[tokio::test]
    async fn test_channel_multiple_subscribers() {
        let (tx, mut rx1) = make_channel(64);
        let mut rx2 = tx.subscribe();
        let msg = StateChange::new("Chat", "s-2");
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
        let result = tx.send(StateChange::new("ChatContact", "s-3"));
        // SendError when no receivers is expected; must not panic
        assert!(
            result.is_err(),
            "send with no receivers must return SendError"
        );
    }

    #[test]
    fn test_make_channel_returns_sender_and_receiver() {
        // Oracle: broadcast channel semantics — sender.receiver_count() reports the
        // number of live receivers. A fresh channel via make_channel(64) must have
        // exactly one receiver (the one returned by the call).
        let (tx, _rx) = make_channel(64);
        assert_eq!(
            tx.receiver_count(),
            1,
            "make_channel must return exactly one receiver"
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
        let _ = tx.send(StateChange::new("ChatContact", "s-1"));
        let _ = tx.send(StateChange::new("Chat", "s-2"));
        let _ = tx.send(StateChange::new("Message", "s-3"));

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

    #[test]
    #[should_panic(expected = "broadcast channel capacity must be greater than zero")]
    fn test_make_channel_zero_capacity_panics() {
        // Oracle: capacity=0 must panic (documented precondition); this also
        // prevents the underlying tokio panic from surfacing with a less
        // useful message.
        make_channel(0);
    }
}
