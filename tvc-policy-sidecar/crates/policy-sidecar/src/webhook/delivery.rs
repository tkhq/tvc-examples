//! Bounded completion tracking and serialization within one server process.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Weak},
};
use tokio::sync::Mutex;

const COMPLETED_EVENT_CAPACITY: usize = 1_024;

/// Bounded, process-local idempotency state plus per-event locks.
#[derive(Clone)]
pub(crate) struct DeliveryTracker {
    inner: Arc<Mutex<DeliveryTrackerState>>,
}

struct DeliveryTrackerState {
    completed: HashSet<String>,
    completion_order: VecDeque<String>,
    event_locks: HashMap<String, Weak<Mutex<()>>>,
}

impl DeliveryTracker {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DeliveryTrackerState {
                completed: HashSet::new(),
                completion_order: VecDeque::new(),
                event_locks: HashMap::new(),
            })),
        }
    }

    pub(super) async fn lock_for(&self, event_id: &str) -> Arc<Mutex<()>> {
        let mut state = self.inner.lock().await;
        // Failed deliveries are intentionally not marked complete. Remove their dead weak locks
        // opportunistically so a stream of unique failures cannot grow this map without bound.
        state
            .event_locks
            .retain(|_, event_lock| event_lock.strong_count() > 0);
        if let Some(lock) = state.event_locks.get(event_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        state
            .event_locks
            .insert(event_id.to_owned(), Arc::downgrade(&lock));
        lock
    }

    pub(super) async fn is_completed(&self, event_id: &str) -> bool {
        self.inner.lock().await.completed.contains(event_id)
    }

    pub(super) async fn complete(&self, event_id: &str) {
        let mut state = self.inner.lock().await;
        if !state.completed.insert(event_id.to_owned()) {
            return;
        }
        state.completion_order.push_back(event_id.to_owned());
        while state.completed.len() > COMPLETED_EVENT_CAPACITY {
            if let Some(expired_event_id) = state.completion_order.pop_front() {
                state.completed.remove(&expired_event_id);
                state.event_locks.remove(&expired_event_id);
            }
        }
    }
}
