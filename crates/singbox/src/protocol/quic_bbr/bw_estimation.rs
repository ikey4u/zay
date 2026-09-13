// Adapted from sing-quic/congestion_meta2's bandwidth sampler (MIT) and
// quinn-proto's BBR bandwidth estimator (MIT OR Apache-2.0).

use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Debug, Display, Formatter};
use std::time::{Duration, Instant};

use super::min_max::MinMax;

const MAX_A0_CANDIDATES: usize = 256;

#[derive(Clone, Copy, Debug)]
struct AckPoint {
    time: Instant,
    total_acked: u64,
}

#[derive(Clone, Debug, Default)]
struct RecentAckPoints {
    points: [Option<AckPoint>; 2],
}

impl RecentAckPoints {
    fn update(&mut self, now: Instant, total_acked: u64) {
        match self.points[1] {
            Some(current) if now < current.time => {
                self.points[1] = Some(AckPoint {
                    time: now,
                    total_acked,
                });
            }
            Some(current) if now > current.time => {
                self.points[0] = Some(current);
                self.points[1] = Some(AckPoint {
                    time: now,
                    total_acked,
                });
            }
            Some(current) => {
                self.points[1] = Some(AckPoint {
                    total_acked,
                    ..current
                });
            }
            None => {
                self.points[1] = Some(AckPoint {
                    time: now,
                    total_acked,
                });
            }
        }
    }

    fn less_recent(&self) -> Option<AckPoint> {
        self.points[0]
            .filter(|point| point.total_acked != 0)
            .or(self.points[1])
    }
}

#[derive(Clone, Copy, Debug)]
struct SentPacketState {
    sequence: u64,
    sent_time: Instant,
    size: u64,
    total_sent: u64,
    total_acked: u64,
    total_sent_at_last_acked_packet: u64,
    last_acked_packet_sent_time: Option<Instant>,
    last_acked_packet_ack_time: Option<Instant>,
    app_limited: bool,
    bytes_in_flight: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SendTimeState {
    pub(crate) app_limited: bool,
    pub(crate) total_acked: u64,
    pub(crate) bytes_in_flight: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AckSample {
    pub(crate) bandwidth_increased: bool,
    pub(crate) non_app_limited: bool,
    pub(crate) bandwidth: u64,
    pub(crate) inflight: u64,
    pub(crate) send_state: SendTimeState,
}

impl SentPacketState {
    fn send_time_state(self) -> SendTimeState {
        SendTimeState {
            app_limited: self.app_limited,
            total_acked: self.total_acked,
            bytes_in_flight: self.bytes_in_flight,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    overestimate_avoidance: bool,
    last_sent_sequence: u64,
    app_limited_phase: bool,
    end_of_app_limited_phase: u64,
    total_acked: u64,
    total_sent: u64,
    total_sent_at_last_acked_packet: u64,
    last_acked_packet_sent_time: Option<Instant>,
    last_acked_packet_ack_time: Option<Instant>,
    max_filter: MinMax,
    acked_at_last_window: u64,
    sent_packets: BTreeMap<(u8, u64), SentPacketState>,
    recent_ack_points: RecentAckPoints,
    a0_candidates: VecDeque<AckPoint>,
}

impl BandwidthEstimation {
    pub(crate) fn new(overestimate_avoidance: bool) -> Self {
        Self {
            overestimate_avoidance,
            ..Self::default()
        }
    }

    pub(crate) fn on_sent_packet(
        &mut self,
        now: Instant,
        bytes: u64,
        packet_space: u8,
        packet_number: u64,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
        if app_limited && !self.app_limited_phase {
            self.app_limited_phase = true;
            self.end_of_app_limited_phase = self.last_sent_sequence;
        }
        self.last_sent_sequence = self.last_sent_sequence.saturating_add(1);
        self.total_sent = self.total_sent.saturating_add(bytes);

        // A transmission after quiescence is a valid (conservative) A0 point.
        // This is particularly important for the first flight.
        if bytes_in_flight == 0 {
            self.last_acked_packet_ack_time = Some(now);
            self.total_sent_at_last_acked_packet = self.total_sent;
            self.last_acked_packet_sent_time = Some(now);
            if self.overestimate_avoidance {
                self.recent_ack_points = RecentAckPoints::default();
                self.recent_ack_points.update(now, self.total_acked);
                self.a0_candidates.clear();
                self.push_a0(AckPoint {
                    time: now,
                    total_acked: self.total_acked,
                });
            }
        }

        self.sent_packets.insert(
            (packet_space, packet_number),
            SentPacketState {
                sequence: self.last_sent_sequence,
                sent_time: now,
                size: bytes,
                total_sent: self.total_sent,
                total_acked: self.total_acked,
                total_sent_at_last_acked_packet: self
                    .total_sent_at_last_acked_packet,
                last_acked_packet_sent_time: self.last_acked_packet_sent_time,
                last_acked_packet_ack_time: self.last_acked_packet_ack_time,
                app_limited: self.app_limited_phase,
                bytes_in_flight: bytes_in_flight.saturating_add(bytes),
            },
        );
    }

    pub(crate) fn on_ack_packet(
        &mut self,
        now: Instant,
        packet_space: u8,
        packet_number: u64,
        round: u64,
    ) -> Option<AckSample> {
        let sent = self.sent_packets.remove(&(packet_space, packet_number))?;

        self.total_acked = self.total_acked.saturating_add(sent.size);
        let mut sample = AckSample {
            bandwidth_increased: false,
            non_app_limited: !sent.app_limited,
            bandwidth: 0,
            inflight: self.total_acked.saturating_sub(sent.total_acked),
            send_state: sent.send_time_state(),
        };
        self.total_sent_at_last_acked_packet = sent.total_sent;
        self.last_acked_packet_sent_time = Some(sent.sent_time);
        self.last_acked_packet_ack_time = Some(now);
        if self.overestimate_avoidance {
            self.recent_ack_points.update(now, self.total_acked);
        }
        if self.app_limited_phase
            && sent.sequence > self.end_of_app_limited_phase
        {
            self.app_limited_phase = false;
        }

        let Some(previous_sent_time) = sent.last_acked_packet_sent_time else {
            return Some(sample);
        };

        let send_rate = if sent.sent_time > previous_sent_time {
            Self::bw_from_delta(
                sent.total_sent
                    .saturating_sub(sent.total_sent_at_last_acked_packet),
                sent.sent_time.duration_since(previous_sent_time),
            )
            .unwrap_or(0)
        } else {
            u64::MAX
        };

        let fallback_a0 =
            sent.last_acked_packet_ack_time.map(|time| AckPoint {
                time,
                total_acked: sent.total_acked,
            });
        let a0 = if self.overestimate_avoidance {
            self.choose_a0(sent.total_acked).or(fallback_a0)
        } else {
            fallback_a0
        };
        let Some(a0) = a0 else {
            return Some(sample);
        };
        let Some(delta) = now.checked_duration_since(a0.time) else {
            return Some(sample);
        };
        let Some(ack_rate) = Self::bw_from_delta(
            self.total_acked.saturating_sub(a0.total_acked),
            delta,
        ) else {
            return Some(sample);
        };

        let bandwidth = send_rate.min(ack_rate);
        let increased = self.max_filter.get() < bandwidth;
        if !sent.app_limited || increased {
            self.max_filter.update_max(round, bandwidth);
        }
        sample.bandwidth_increased = increased;
        sample.bandwidth = bandwidth;
        Some(sample)
    }

    pub(crate) fn retire_packet(
        &mut self,
        packet_space: u8,
        packet_number: u64,
    ) -> Option<SendTimeState> {
        self.sent_packets
            .remove(&(packet_space, packet_number))
            .map(SentPacketState::send_time_state)
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) const fn total_bytes_acked(&self) -> u64 {
        self.total_acked
    }

    pub(crate) fn end_acks(&mut self, starts_new_aggregation_epoch: bool) {
        self.acked_at_last_window = self.total_acked;
        if self.overestimate_avoidance
            && starts_new_aggregation_epoch
            && let Some(point) = self.recent_ack_points.less_recent()
        {
            self.push_a0(point);
        }
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    #[cfg(test)]
    pub(super) fn tracked_packet_count(&self) -> usize {
        self.sent_packets.len()
    }

    pub(crate) fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let bytes_ns = (bytes as u128).saturating_mul(1_000_000_000);
        Some((bytes_ns / window_duration_ns).min(u64::MAX as u128) as u64)
    }

    fn push_a0(&mut self, point: AckPoint) {
        if self.a0_candidates.len() == MAX_A0_CANDIDATES {
            self.a0_candidates.pop_front();
        }
        self.a0_candidates.push_back(point);
    }

    fn choose_a0(&mut self, total_acked_at_send: u64) -> Option<AckPoint> {
        if self.a0_candidates.len() <= 1 {
            return self.a0_candidates.front().copied();
        }

        let position = self
            .a0_candidates
            .iter()
            .position(|point| point.total_acked > total_acked_at_send);
        match position {
            Some(position) => {
                let selected = position.saturating_sub(1);
                for _ in 0..selected {
                    self.a0_candidates.pop_front();
                }
                self.a0_candidates.front().copied()
            }
            None => {
                let point = self.a0_candidates.back().copied();
                while self.a0_candidates.len() > 1 {
                    self.a0_candidates.pop_front();
                }
                point
            }
        }
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_flight_produces_a_bandwidth_sample() {
        let start = Instant::now();
        let mut sampler = BandwidthEstimation::new(true);
        sampler.on_sent_packet(start, 1_000, 0, 1, 0, false);
        let sample = sampler
            .on_ack_packet(start + Duration::from_millis(100), 0, 1, 1)
            .unwrap();
        assert!(sample.bandwidth_increased);
        assert!(sample.non_app_limited);
        assert_eq!(sample.bandwidth, 10_000);
        assert_eq!(sample.inflight, 1_000);
        assert_eq!(sample.send_state.bytes_in_flight, 1_000);
        assert_eq!(sampler.get_estimate(), 10_000);
    }

    #[test]
    fn app_limited_sample_only_updates_a_higher_maximum() {
        let start = Instant::now();
        let mut sampler = BandwidthEstimation::default();
        sampler.on_sent_packet(start, 1_000, 0, 1, 0, false);
        let _ =
            sampler.on_ack_packet(start + Duration::from_millis(100), 0, 1, 1);
        sampler.on_sent_packet(
            start + Duration::from_millis(200),
            1_000,
            0,
            2,
            0,
            true,
        );
        let _ =
            sampler.on_ack_packet(start + Duration::from_millis(400), 0, 2, 2);
        assert_eq!(sampler.get_estimate(), 10_000);
    }

    #[test]
    fn app_limited_phase_ends_only_after_a_new_packet_is_acked() {
        let start = Instant::now();
        let mut sampler = BandwidthEstimation::default();
        sampler.on_sent_packet(start, 1_000, 2, 10, 0, false);
        let _ =
            sampler.on_ack_packet(start + Duration::from_millis(10), 2, 10, 1);

        sampler.on_sent_packet(
            start + Duration::from_millis(20),
            1_000,
            2,
            11,
            0,
            true,
        );
        sampler.on_sent_packet(
            start + Duration::from_millis(21),
            1_000,
            2,
            12,
            1_000,
            false,
        );
        assert!(sampler.sent_packets[&(2, 11)].app_limited);
        assert!(sampler.sent_packets[&(2, 12)].app_limited);

        let _ =
            sampler.on_ack_packet(start + Duration::from_millis(30), 2, 11, 2);
        sampler.on_sent_packet(
            start + Duration::from_millis(31),
            1_000,
            2,
            13,
            1_000,
            false,
        );
        assert!(!sampler.sent_packets[&(2, 13)].app_limited);
    }

    #[test]
    fn high_bdp_flight_keeps_every_unresolved_packet() {
        let start = Instant::now();
        let mut sampler = BandwidthEstimation::new(true);

        // sing-quic's packet-number queue starts with 256 slots but grows with
        // the flight.  Treating that initial capacity as a hard limit drops
        // the oldest delivery state on ordinary high-BDP paths, so a reordered
        // ACK can no longer contribute its bytes or a bandwidth sample.
        for packet in 1..=512_u64 {
            sampler.on_sent_packet(
                start + Duration::from_micros(packet),
                1_200,
                2,
                packet,
                (packet - 1) * 1_200,
                false,
            );
        }
        assert_eq!(sampler.sent_packets.len(), 512);

        let sample = sampler
            .on_ack_packet(start + Duration::from_millis(100), 2, 1, 1)
            .unwrap();
        assert!(sample.bandwidth_increased);
        assert!(sample.non_app_limited);
        assert_eq!(sampler.total_acked, 1_200);
        assert_eq!(sampler.sent_packets.len(), 511);

        // ACK the newest packet next to exercise the same state under extreme
        // packet reordering.  Both ends of the flight must remain resolvable.
        let _ = sampler.on_ack_packet(
            start + Duration::from_millis(101),
            2,
            512,
            1,
        );
        assert_eq!(sampler.total_acked, 2_400);
        assert_eq!(sampler.sent_packets.len(), 510);
    }

    #[test]
    fn a0_candidates_are_bounded() {
        let start = Instant::now();
        let mut sampler = BandwidthEstimation::default();
        for index in 0..(MAX_A0_CANDIDATES + 10) {
            sampler.push_a0(AckPoint {
                time: start,
                total_acked: index as u64,
            });
        }
        assert_eq!(sampler.a0_candidates.len(), MAX_A0_CANDIDATES);
        assert_eq!(sampler.a0_candidates.front().unwrap().total_acked, 10);
    }
}
