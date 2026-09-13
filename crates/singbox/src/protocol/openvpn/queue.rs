use std::collections::VecDeque;

use parking_lot::Mutex;
use tokio::sync::Notify;

pub const DATA_PACKET_BATCH_SIZE: usize = 64;
pub const DATA_PACKET_QUEUE_CAPACITY: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueOverflowPolicy {
    DropOldest,
    DropNewest,
}

/// Bounded packet queue used between the OpenVPN link and tunnel planes.
/// Wakeups retain one permit, matching sing-openvpn's buffered wake channel.
#[derive(Debug)]
pub struct DataPacketQueue<T> {
    capacity: usize,
    items: Mutex<VecDeque<T>>,
    wake: Notify,
}

impl<T> DataPacketQueue<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "OpenVPN data queue capacity must be positive");
        Self {
            capacity,
            items: Mutex::new(VecDeque::with_capacity(capacity)),
            wake: Notify::new(),
        }
    }

    pub fn push_batch<I>(&self, items: I, policy: QueueOverflowPolicy) -> Vec<T>
    where
        I: IntoIterator<Item = T>,
    {
        let mut queue = self.items.lock();
        let was_empty = queue.is_empty();
        let mut dropped = Vec::new();
        for item in items {
            if queue.len() == self.capacity {
                match policy {
                    QueueOverflowPolicy::DropOldest => {
                        dropped.push(queue.pop_front().unwrap());
                    }
                    QueueOverflowPolicy::DropNewest => {
                        dropped.push(item);
                        continue;
                    }
                }
            }
            queue.push_back(item);
        }
        let became_non_empty = was_empty && !queue.is_empty();
        drop(queue);
        if became_non_empty {
            self.wake.notify_one();
        }
        dropped
    }

    /// Pop at most `maximum` entries. A maximum of zero means unlimited.
    /// When `same_run` is supplied, the batch ends before the first item that
    /// does not belong to the first item's vectorized I/O run.
    pub fn pop(
        &self,
        maximum: usize,
        same_run: Option<impl Fn(&T, &T) -> bool>,
    ) -> Vec<T> {
        let mut queue = self.items.lock();
        let mut count = if maximum == 0 {
            queue.len()
        } else {
            queue.len().min(maximum)
        };
        if count > 1
            && let Some(predicate) = same_run
        {
            let first = queue.front().unwrap();
            count = queue
                .iter()
                .take(count)
                .position(|item| !predicate(first, item))
                .unwrap_or(count);
        }
        let output: Vec<_> = queue.drain(..count).collect();
        let has_more = !queue.is_empty();
        drop(queue);
        if has_more {
            self.wake.notify_one();
        }
        output
    }

    pub async fn notified(&self) {
        self.wake.notified().await;
    }

    pub fn drain(&self) -> Vec<T> {
        self.items.lock().drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.items.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_policies_match_client_and_server_queues() {
        let queue = DataPacketQueue::new(3);
        assert!(
            queue
                .push_batch([1, 2, 3], QueueOverflowPolicy::DropOldest)
                .is_empty()
        );
        assert_eq!(
            queue.push_batch([4, 5], QueueOverflowPolicy::DropOldest),
            [1, 2]
        );
        assert_eq!(queue.drain(), [3, 4, 5]);

        queue.push_batch([1, 2, 3], QueueOverflowPolicy::DropNewest);
        assert_eq!(
            queue.push_batch([4, 5], QueueOverflowPolicy::DropNewest),
            [4, 5]
        );
        assert_eq!(queue.drain(), [1, 2, 3]);
    }

    #[test]
    fn pop_stops_at_vectorized_run_boundary() {
        let queue = DataPacketQueue::new(8);
        queue.push_batch([10, 12, 14, 3, 5], QueueOverflowPolicy::DropOldest);
        assert_eq!(
            queue.pop(8, Some(|first: &i32, item: &i32| first % 2 == item % 2)),
            [10, 12, 14]
        );
        assert_eq!(queue.pop(1, None::<fn(&i32, &i32) -> bool>), [3]);
        assert_eq!(queue.drain(), [5]);
    }

    #[tokio::test]
    async fn wake_permit_is_retained_until_consumer_waits() {
        let queue = DataPacketQueue::new(2);
        queue.push_batch([1], QueueOverflowPolicy::DropOldest);
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            queue.notified(),
        )
        .await
        .unwrap();
    }
}
