use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub const DEFAULT_REPLAY_WINDOW_SIZE: u32 = 64;
pub const MAX_REPLAY_WINDOW_SIZE: u32 = 65_536;
pub const DEFAULT_REPLAY_WINDOW_TIME: Duration = Duration::from_secs(15);
pub const MAX_REPLAY_WINDOW_TIME: Duration = Duration::from_secs(600);

#[derive(Debug)]
struct ReplayInner {
    initialized: bool,
    highest_id: u32,
    highest_timestamp: u32,
    bitmap: Vec<u64>,
    arrival_times: Vec<Option<Instant>>,
    minimum_id: u32,
}

/// OpenVPN packet-id replay protection, including long-form timestamp epochs.
#[derive(Debug)]
pub struct ReplayWindow {
    window_size: u32,
    time_window: Duration,
    inner: Mutex<ReplayInner>,
}

impl ReplayWindow {
    pub fn new(window_size: u32, time_window: Duration) -> Self {
        Self {
            window_size,
            time_window,
            inner: Mutex::new(ReplayInner {
                initialized: false,
                highest_id: 0,
                highest_timestamp: 0,
                bitmap: vec![0; window_size.div_ceil(64) as usize],
                arrival_times: vec![None; window_size as usize],
                minimum_id: 0,
            }),
        }
    }

    pub fn accept(&self, packet_id: u32) -> bool {
        self.accept_at(packet_id, Instant::now())
    }

    pub fn accept_long_form(&self, packet_id: u32, timestamp: u32) -> bool {
        self.accept_long_form_at(packet_id, timestamp, Instant::now())
    }

    fn accept_at(&self, packet_id: u32, now: Instant) -> bool {
        if packet_id == 0 {
            return false;
        }
        self.accept_locked(&mut self.inner.lock(), packet_id, now)
    }

    fn accept_long_form_at(
        &self,
        packet_id: u32,
        timestamp: u32,
        now: Instant,
    ) -> bool {
        if packet_id == 0 {
            return false;
        }
        let mut inner = self.inner.lock();
        if !inner.initialized {
            if self.window_size == 0 && timestamp > 0 && packet_id != 1 {
                return false;
            }
            self.initialize(&mut inner, packet_id, timestamp, now);
            return true;
        }
        if timestamp < inner.highest_timestamp {
            return false;
        }
        if timestamp > inner.highest_timestamp {
            if self.window_size == 0 && packet_id != 1 {
                return false;
            }
            self.initialize(&mut inner, packet_id, timestamp, now);
            return true;
        }
        self.accept_locked(&mut inner, packet_id, now)
    }

    fn accept_locked(
        &self,
        inner: &mut ReplayInner,
        packet_id: u32,
        now: Instant,
    ) -> bool {
        if !inner.initialized {
            self.initialize(inner, packet_id, 0, now);
            return true;
        }
        if self.window_size == 0 {
            if packet_id != inner.highest_id.wrapping_add(1) {
                return false;
            }
            inner.highest_id = packet_id;
            return true;
        }
        self.reap(inner, now);
        if packet_id > inner.highest_id {
            let shift = packet_id - inner.highest_id;
            if shift >= self.window_size {
                inner.bitmap.fill(0);
                inner.arrival_times.fill(None);
            } else {
                shift_bitmap(&mut inner.bitmap, shift);
                shift_times(&mut inner.arrival_times, shift);
            }
            inner.bitmap[0] |= 1;
            inner.arrival_times[0] = Some(now);
            inner.highest_id = packet_id;
            return true;
        }
        if packet_id < inner.minimum_id {
            return false;
        }
        let offset = inner.highest_id - packet_id;
        if offset >= self.window_size {
            return false;
        }
        let word = (offset / 64) as usize;
        let mask = 1_u64 << (offset % 64);
        if inner.bitmap[word] & mask != 0 {
            return false;
        }
        inner.bitmap[word] |= mask;
        inner.arrival_times[offset as usize] = Some(now);
        true
    }

    fn initialize(
        &self,
        inner: &mut ReplayInner,
        packet_id: u32,
        timestamp: u32,
        now: Instant,
    ) {
        inner.initialized = true;
        inner.highest_timestamp = timestamp;
        inner.highest_id = packet_id;
        inner.minimum_id = 0;
        inner.bitmap.fill(0);
        inner.arrival_times.fill(None);
        if self.window_size > 0 {
            inner.bitmap[0] = 1;
            inner.arrival_times[0] = Some(now);
        }
    }

    fn reap(&self, inner: &mut ReplayInner, now: Instant) {
        if self.time_window.is_zero() {
            return;
        }
        for (offset, arrival) in inner.arrival_times.iter().enumerate() {
            if arrival.is_some_and(|arrival| {
                now.duration_since(arrival) > self.time_window
            }) {
                let minimum_id = inner
                    .highest_id
                    .wrapping_sub(offset as u32)
                    .wrapping_add(1);
                inner.minimum_id = inner.minimum_id.max(minimum_id);
                return;
            }
        }
    }
}

fn shift_bitmap(bitmap: &mut [u64], shift: u32) {
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    for target in (0..bitmap.len()).rev() {
        let Some(source) = target.checked_sub(word_shift) else {
            bitmap[target] = 0;
            continue;
        };
        let mut value = bitmap[source] << bit_shift;
        if bit_shift > 0 && source > 0 {
            value |= bitmap[source - 1] >> (64 - bit_shift);
        }
        bitmap[target] = value;
    }
}

fn shift_times(times: &mut [Option<Instant>], shift: u32) {
    let shift = shift as usize;
    if shift == 0 || times.is_empty() {
        return;
    }
    if shift >= times.len() {
        times.fill(None);
        return;
    }
    times.copy_within(..times.len() - shift, shift);
    times[..shift].fill(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reordering_once_and_rejects_old_packets() {
        let window = ReplayWindow::new(4, Duration::ZERO);
        assert!(window.accept(3));
        assert!(window.accept(2));
        assert!(!window.accept(2));
        assert!(window.accept(7));
        assert!(!window.accept(3));
        assert!(!window.accept(0));
    }

    #[test]
    fn zero_window_requires_monotonic_ids_and_epoch_restart_at_one() {
        let window = ReplayWindow::new(0, Duration::ZERO);
        assert!(window.accept_long_form(1, 10));
        assert!(window.accept_long_form(2, 10));
        assert!(!window.accept_long_form(4, 10));
        assert!(!window.accept_long_form(2, 11));
        assert!(window.accept_long_form(1, 11));
        assert!(!window.accept_long_form(2, 9));
    }

    #[test]
    fn time_window_expires_backtracking_ids() {
        let start = Instant::now();
        let window = ReplayWindow::new(8, Duration::from_secs(2));
        assert!(window.accept_at(2, start));
        assert!(window.accept_at(4, start + Duration::from_secs(1)));
        assert!(!window.accept_at(1, start + Duration::from_secs(3)));
        assert!(!window.accept_at(2, start + Duration::from_secs(3)));
        assert!(window.accept_at(3, start + Duration::from_secs(3)));
    }
}
