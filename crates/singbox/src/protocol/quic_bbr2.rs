//! BBRv2 congestion control for Naive QUIC.
//!
//! Quinn does not currently ship a BBRv2 controller. This implementation is
//! adapted from the public Google/Cloudflare QUIC BBRv2 model: ACK and loss
//! signals are processed as one congestion event, bandwidth and inflight
//! lower/upper bounds react to loss, and ProbeBW uses the
//! Down/Cruise/Refill/Up cycle rather than BBRv1's fixed gain carousel.

use std::{
    any::Any,
    sync::Arc,
    time::{Duration, Instant},
};

use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory, ControllerMetrics},
};
use rand::{Rng, SeedableRng, rngs::StdRng};

use super::quic_bbr::{
    AckAggregationState, bw_estimation::BandwidthEstimation,
};

const INITIAL_WINDOW_PACKETS: u64 = 32;
const MIN_WINDOW_PACKETS: u64 = 4;
const MAX_WINDOW_BYTES: u64 = 200 * 1024 * 1024;

const STARTUP_PACING_GAIN: f64 = 2.773;
const STARTUP_CWND_GAIN: f64 = 2.0;
const DRAIN_PACING_GAIN: f64 = 1.0 / 2.885;
const PROBE_UP_PACING_GAIN: f64 = 1.25;
const PROBE_DOWN_PACING_GAIN: f64 = 0.9;
const PROBE_CWND_GAIN: f64 = 2.0;
const PROBE_UP_CWND_GAIN: f64 = 2.25;
const PROBE_RTT_BDP_FRACTION: f64 = 0.5;
const FULL_BW_THRESHOLD: f64 = 1.25;
const FULL_BW_ROUNDS: u8 = 3;
const STARTUP_FULL_LOSS_EVENTS: u8 = 8;
const PROBE_FULL_LOSS_EVENTS: u8 = 2;
const LOSS_THRESHOLD: f64 = 0.015;
const BETA: f64 = 0.3;
const INFLIGHT_HI_HEADROOM: f64 = 0.15;
const PROBE_RTT_PERIOD: Duration = Duration::from_secs(10);
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
const PROBE_BASE_DURATION: Duration = Duration::from_secs(2);
const PROBE_MAX_ROUNDS: u8 = 63;
const INITIAL_RTT: Duration = Duration::from_millis(333);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Startup,
    Drain,
    ProbeBw(ProbePhase),
    ProbeRtt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbePhase {
    Down,
    Cruise,
    Refill,
    Up,
}

/// Factory for the Naive QUIC BBRv2 controller.
#[derive(Clone, Debug)]
pub struct Bbr2Config {
    initial_window_packets: u64,
}

impl Default for Bbr2Config {
    fn default() -> Self {
        Self {
            initial_window_packets: INITIAL_WINDOW_PACKETS,
        }
    }
}

impl Bbr2Config {
    /// Override the initial congestion window in packets.
    pub fn initial_window_packets(&mut self, packets: u64) -> &mut Self {
        self.initial_window_packets = packets.max(MIN_WINDOW_PACKETS);
        self
    }
}

impl ControllerFactory for Bbr2Config {
    fn build(
        self: Arc<Self>,
        now: Instant,
        current_mtu: u16,
    ) -> Box<dyn Controller> {
        Box::new(Bbr2::new(self, now, current_mtu))
    }
}

/// QUIC BBRv2 sender state.
#[derive(Clone, Debug)]
pub struct Bbr2 {
    config: Arc<Bbr2Config>,
    sampler: BandwidthEstimation,
    ack_aggregation: AckAggregationState,
    rng: StdRng,
    mode: Mode,
    mtu: u64,
    initial_cwnd: u64,
    min_cwnd: u64,
    cwnd: u64,
    pacing_rate: u64,

    min_rtt: Duration,
    min_rtt_stamp: Instant,
    max_sent_packet: u64,
    round_end_packet: u64,
    round_count: u64,
    round_started: bool,

    full_bw: u64,
    full_bw_count: u8,
    full_bandwidth_reached: bool,
    bandwidth_lo: Option<u64>,
    inflight_lo: Option<u64>,
    inflight_hi: Option<u64>,

    bytes_acked: u64,
    bytes_lost: u64,
    loss_events: u8,
    bandwidth_increased: bool,
    extra_acked: u64,
    sample_min_rtt: Option<Duration>,
    largest_acked_packet: Option<u64>,
    last_event_time: Instant,

    phase_started: Instant,
    phase_rounds: u8,
    rounds_since_probe: u8,
    probe_wait: Duration,
    probe_up_acked: u64,
    probe_up_step: u64,
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,
}

impl Bbr2 {
    fn new(config: Arc<Bbr2Config>, now: Instant, current_mtu: u16) -> Self {
        let mtu = u64::from(current_mtu);
        let min_cwnd = MIN_WINDOW_PACKETS * mtu;
        let initial_cwnd = (config.initial_window_packets * mtu).max(min_cwnd);
        Self {
            config,
            sampler: BandwidthEstimation::new(true),
            rng: StdRng::from_entropy(),
            mode: Mode::Startup,
            mtu,
            initial_cwnd,
            min_cwnd,
            cwnd: initial_cwnd,
            pacing_rate: bandwidth(initial_cwnd, INITIAL_RTT)
                .saturating_mul_float(STARTUP_PACING_GAIN),
            min_rtt: INITIAL_RTT,
            min_rtt_stamp: now,
            max_sent_packet: 0,
            round_end_packet: 0,
            round_count: 0,
            round_started: false,
            full_bw: 0,
            full_bw_count: 0,
            full_bandwidth_reached: false,
            bandwidth_lo: None,
            inflight_lo: None,
            inflight_hi: None,
            bytes_acked: 0,
            bytes_lost: 0,
            loss_events: 0,
            bandwidth_increased: false,
            extra_acked: 0,
            sample_min_rtt: None,
            largest_acked_packet: None,
            last_event_time: now,
            phase_started: now,
            phase_rounds: 0,
            rounds_since_probe: 0,
            probe_wait: PROBE_BASE_DURATION,
            probe_up_acked: 0,
            probe_up_step: mtu,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            ack_aggregation: AckAggregationState::new(true, false),
        }
    }

    fn bandwidth_estimate(&self) -> u64 {
        match self.bandwidth_lo {
            Some(lower) => self.sampler.get_estimate().min(lower),
            None => self.sampler.get_estimate(),
        }
    }

    fn bdp(&self, gain: f64) -> u64 {
        bandwidth_bytes(self.bandwidth_estimate(), self.min_rtt, gain)
    }

    fn pacing_gain(&self) -> f64 {
        match self.mode {
            Mode::Startup => STARTUP_PACING_GAIN,
            Mode::Drain => DRAIN_PACING_GAIN,
            Mode::ProbeBw(ProbePhase::Up) => PROBE_UP_PACING_GAIN,
            Mode::ProbeBw(ProbePhase::Down) => PROBE_DOWN_PACING_GAIN,
            Mode::ProbeBw(ProbePhase::Cruise | ProbePhase::Refill)
            | Mode::ProbeRtt => 1.0,
        }
    }

    fn cwnd_gain(&self) -> f64 {
        match self.mode {
            Mode::Startup => STARTUP_CWND_GAIN,
            Mode::ProbeBw(ProbePhase::Up) => PROBE_UP_CWND_GAIN,
            Mode::Drain | Mode::ProbeBw(_) | Mode::ProbeRtt => PROBE_CWND_GAIN,
        }
    }

    fn target_inflight(&self) -> u64 {
        let mut target = self
            .bdp(self.cwnd_gain())
            .saturating_add(self.extra_acked)
            .max(self.min_cwnd);
        if let Some(lo) = self.inflight_lo {
            target = target.min(lo.max(self.min_cwnd));
        }
        if let Some(hi) = self.inflight_hi {
            target = target.min(hi.max(self.min_cwnd));
        }
        target
    }

    fn check_full_bandwidth(&mut self, app_limited: bool) {
        if self.full_bandwidth_reached || app_limited {
            return;
        }
        let estimate = self.sampler.get_estimate();
        if self.full_bw == 0
            || estimate >= self.full_bw.saturating_mul_float(FULL_BW_THRESHOLD)
        {
            self.full_bw = estimate;
            self.full_bw_count = 0;
        } else {
            self.full_bw_count = self.full_bw_count.saturating_add(1);
            if self.full_bw_count >= FULL_BW_ROUNDS {
                self.full_bandwidth_reached = true;
            }
        }
    }

    fn loss_is_too_high(&self, prior_in_flight: u64) -> bool {
        self.loss_events > 0
            && prior_in_flight > 0
            && self.bytes_lost as f64 > prior_in_flight as f64 * LOSS_THRESHOLD
    }

    fn adapt_lower_bounds(&mut self, prior_in_flight: u64) {
        if self.bytes_lost == 0 {
            if self.round_started {
                self.bandwidth_lo = None;
                self.inflight_lo = None;
            }
            return;
        }
        let estimate = self.bandwidth_estimate();
        let loss_rate = bandwidth(self.bytes_lost, self.min_rtt);
        let beta_bw = estimate.saturating_mul_float(1.0 - BETA);
        self.bandwidth_lo =
            Some(estimate.saturating_sub(loss_rate).max(beta_bw).max(1));
        let beta_inflight = prior_in_flight.saturating_mul_float(1.0 - BETA);
        self.inflight_lo = Some(
            prior_in_flight
                .saturating_sub(self.bytes_lost)
                .max(beta_inflight)
                .max(self.min_cwnd),
        );
    }

    fn bound_inflight_hi(&mut self, prior_in_flight: u64) {
        let headroom =
            prior_in_flight.saturating_mul_float(1.0 - INFLIGHT_HI_HEADROOM);
        let delivered = self
            .bdp(1.0)
            .max(prior_in_flight.saturating_sub(self.bytes_lost));
        let candidate = headroom.max(delivered).max(self.min_cwnd);
        self.inflight_hi = Some(
            self.inflight_hi
                .map_or(candidate, |current| current.min(candidate)),
        );
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw(ProbePhase::Down);
        self.phase_started = now;
        self.phase_rounds = 0;
        self.rounds_since_probe = 0;
        self.probe_wait = PROBE_BASE_DURATION
            + Duration::from_millis(self.rng.gen_range(0..=1000));
    }

    fn set_probe_phase(&mut self, phase: ProbePhase, now: Instant) {
        self.mode = Mode::ProbeBw(phase);
        self.phase_started = now;
        self.phase_rounds = 0;
        if phase == ProbePhase::Up {
            self.probe_up_acked = 0;
            let bdp_packets = self.bdp(1.0).div_ceil(self.mtu).max(1);
            self.probe_up_step = (self.mtu * bdp_packets).div_ceil(8);
        }
    }

    fn update_mode(
        &mut self,
        now: Instant,
        in_flight: u64,
        prior_in_flight: u64,
        app_limited: bool,
    ) {
        if self.mode != Mode::ProbeRtt
            && now.saturating_duration_since(self.min_rtt_stamp)
                >= PROBE_RTT_PERIOD
            && !app_limited
        {
            self.mode = Mode::ProbeRtt;
            self.probe_rtt_done_stamp = None;
            self.probe_rtt_round_done = false;
            return;
        }

        match self.mode {
            Mode::Startup => {
                if self.round_started {
                    self.check_full_bandwidth(app_limited);
                }
                if self.loss_events >= STARTUP_FULL_LOSS_EVENTS
                    && self.loss_is_too_high(prior_in_flight)
                {
                    self.full_bandwidth_reached = true;
                    self.bound_inflight_hi(prior_in_flight);
                }
                if self.full_bandwidth_reached {
                    self.mode = Mode::Drain;
                }
            }
            Mode::Drain => {
                if in_flight <= self.bdp(1.0).max(self.min_cwnd) {
                    self.enter_probe_bw(now);
                }
            }
            Mode::ProbeBw(ProbePhase::Down) => {
                if in_flight <= self.bdp(1.0).max(self.min_cwnd)
                    || now.saturating_duration_since(self.phase_started)
                        >= self.min_rtt
                {
                    self.set_probe_phase(ProbePhase::Cruise, now);
                }
            }
            Mode::ProbeBw(ProbePhase::Cruise) => {
                if self.round_started {
                    self.rounds_since_probe =
                        self.rounds_since_probe.saturating_add(1);
                }
                if now.saturating_duration_since(self.phase_started)
                    >= self.probe_wait
                    || self.rounds_since_probe >= PROBE_MAX_ROUNDS
                {
                    self.set_probe_phase(ProbePhase::Refill, now);
                    self.bandwidth_lo = None;
                    self.inflight_lo = None;
                }
            }
            Mode::ProbeBw(ProbePhase::Refill) => {
                if self.round_started {
                    self.set_probe_phase(ProbePhase::Up, now);
                }
            }
            Mode::ProbeBw(ProbePhase::Up) => {
                self.probe_up_acked =
                    self.probe_up_acked.saturating_add(self.bytes_acked);
                if let Some(hi) = self.inflight_hi.as_mut() {
                    while self.probe_up_acked >= self.probe_up_step {
                        self.probe_up_acked -= self.probe_up_step;
                        *hi = hi.saturating_add(self.mtu);
                    }
                }
                if (self.loss_events >= PROBE_FULL_LOSS_EVENTS
                    && self.loss_is_too_high(prior_in_flight))
                    || self.phase_rounds >= 2
                {
                    if self.loss_is_too_high(prior_in_flight) {
                        self.bound_inflight_hi(prior_in_flight);
                    }
                    self.set_probe_phase(ProbePhase::Down, now);
                }
            }
            Mode::ProbeRtt => {
                let target = self.probe_rtt_cwnd();
                if self.probe_rtt_done_stamp.is_none() && in_flight <= target {
                    self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
                    self.probe_rtt_round_done = false;
                }
                if self.round_started && self.probe_rtt_done_stamp.is_some() {
                    self.probe_rtt_round_done = true;
                }
                if self.probe_rtt_round_done
                    && self.probe_rtt_done_stamp.is_some_and(|done| now >= done)
                {
                    self.min_rtt_stamp = now;
                    self.enter_probe_bw(now);
                }
            }
        }

        if self.round_started
            && let Mode::ProbeBw(_) = self.mode
        {
            self.phase_rounds = self.phase_rounds.saturating_add(1);
        }
    }

    fn probe_rtt_cwnd(&self) -> u64 {
        self.bdp(PROBE_RTT_BDP_FRACTION).max(self.min_cwnd)
    }

    fn update_pacing_rate(&mut self) {
        let estimate = self.bandwidth_estimate();
        if estimate == 0 {
            return;
        }
        let target = estimate.saturating_mul_float(self.pacing_gain());
        if self.mode == Mode::Startup && !self.full_bandwidth_reached {
            self.pacing_rate = self.pacing_rate.max(target);
        } else {
            self.pacing_rate = target.max(1);
        }
    }

    fn update_cwnd(&mut self) {
        if self.mode == Mode::ProbeRtt {
            self.cwnd = self.probe_rtt_cwnd();
            return;
        }
        let target = self.target_inflight();
        if self.full_bandwidth_reached {
            self.cwnd = self.cwnd.saturating_add(self.bytes_acked).min(target);
        } else if self.cwnd < target || self.round_count < 3 {
            self.cwnd = self.cwnd.saturating_add(self.bytes_acked);
        }
        self.cwnd = self.cwnd.clamp(self.min_cwnd, MAX_WINDOW_BYTES);
    }

    fn finish_event(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let newly_acked = self.sampler.bytes_acked_this_window();
        if newly_acked > 0 {
            let excess_acked =
                self.ack_aggregation.update_ack_aggregation_bytes(
                    newly_acked,
                    now,
                    self.round_count,
                    self.sampler.get_estimate(),
                    self.bandwidth_increased,
                );
            self.sampler.end_acks(excess_acked == 0);
            self.extra_acked = if self.full_bandwidth_reached {
                self.ack_aggregation.max_ack_height()
            } else {
                excess_acked
            }
            .min(self.cwnd);
        }

        self.largest_acked_packet =
            largest_packet_num_acked.or(self.largest_acked_packet);
        self.round_started = self
            .largest_acked_packet
            .is_some_and(|packet| packet > self.round_end_packet);
        if self.round_started {
            self.round_count = self.round_count.saturating_add(1);
            self.round_end_packet = self.max_sent_packet;
        }

        let prior_in_flight = in_flight
            .saturating_add(self.bytes_acked)
            .saturating_add(self.bytes_lost);
        self.adapt_lower_bounds(prior_in_flight);
        self.update_mode(now, in_flight, prior_in_flight, app_limited);
        self.update_pacing_rate();
        self.update_cwnd();
        self.bytes_acked = 0;
        self.bytes_lost = 0;
        self.loss_events = 0;
        self.bandwidth_increased = false;
        self.sample_min_rtt = None;
        self.largest_acked_packet = None;
        self.last_event_time = now;
        self.round_started = false;
    }
}

impl Controller for Bbr2 {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, last_packet_number: u64) {
        self.max_sent_packet = self.max_sent_packet.max(last_packet_number);
    }

    fn on_sent_packet(
        &mut self,
        now: Instant,
        bytes: u64,
        packet_space: u8,
        packet_number: u64,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
        self.max_sent_packet = self.max_sent_packet.max(packet_number);
        self.sampler.on_sent_packet(
            now,
            bytes,
            packet_space,
            packet_number,
            bytes_in_flight,
            app_limited,
        );
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.bytes_acked = self.bytes_acked.saturating_add(bytes);
        let sample = now
            .checked_duration_since(sent)
            .unwrap_or_else(|| rtt.min());
        self.sample_min_rtt = Some(
            self.sample_min_rtt
                .map_or(sample, |current| current.min(sample)),
        );
        if sample < self.min_rtt {
            self.min_rtt = sample;
            self.min_rtt_stamp = now;
        }
    }

    fn on_ack_packet(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        packet_space: u8,
        packet_number: u64,
        _app_limited: bool,
    ) {
        let (bandwidth_increased, _) = self.sampler.on_ack_packet(
            now,
            packet_space,
            packet_number,
            self.round_count,
        );
        self.bandwidth_increased |= bandwidth_increased;
        self.largest_acked_packet = Some(
            self.largest_acked_packet
                .map_or(packet_number, |current| current.max(packet_number)),
        );
    }

    fn on_lost_packet(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        packet_space: u8,
        packet_number: u64,
    ) {
        self.sampler.retire_packet(packet_space, packet_number);
        self.bytes_lost = self.bytes_lost.saturating_add(bytes);
    }

    fn on_discarded_packet(&mut self, packet_space: u8, packet_number: u64) {
        self.sampler.retire_packet(packet_space, packet_number);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if lost_bytes > 0 {
            self.bytes_lost = self.bytes_lost.max(lost_bytes);
            self.loss_events = self.loss_events.saturating_add(1);
        }
    }

    fn on_end_congestion_event(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
        _rtt: &RttEstimator,
    ) {
        self.finish_event(
            now,
            in_flight,
            app_limited,
            largest_packet_num_acked,
        );
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let old_mtu = self.mtu;
        self.mtu = u64::from(new_mtu);
        self.min_cwnd = MIN_WINDOW_PACKETS * self.mtu;
        self.initial_cwnd = self
            .config
            .initial_window_packets
            .saturating_mul(self.mtu)
            .max(self.min_cwnd);
        if old_mtu > 0 {
            self.cwnd = ((self.cwnd as u128 * self.mtu as u128)
                / old_mtu as u128)
                .min(MAX_WINDOW_BYTES as u128) as u64;
        }
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    fn window(&self) -> u64 {
        if self.mode == Mode::ProbeRtt {
            self.probe_rtt_cwnd()
        } else {
            self.cwnd
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.ssthresh = self.inflight_hi;
        metrics.pacing_rate = Some(self.pacing_rate.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.initial_cwnd
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

fn bandwidth(bytes: u64, duration: Duration) -> u64 {
    if duration.is_zero() {
        return u64::MAX;
    }
    ((bytes as u128 * 1_000_000_000) / duration.as_nanos())
        .min(u64::MAX as u128) as u64
}

fn bandwidth_bytes(rate: u64, duration: Duration, gain: f64) -> u64 {
    let bytes =
        (rate as u128).saturating_mul(duration.as_nanos()) / 1_000_000_000;
    (bytes as f64 * gain).min(u64::MAX as f64) as u64
}

trait SaturatingFloat {
    fn saturating_mul_float(self, factor: f64) -> Self;
}

impl SaturatingFloat for u64 {
    fn saturating_mul_float(self, factor: f64) -> Self {
        (self as f64 * factor).clamp(0.0, u64::MAX as f64) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(now: Instant) -> Bbr2 {
        Bbr2::new(Arc::new(Bbr2Config::default()), now, 1_200)
    }

    fn ack_round(
        controller: &mut Bbr2,
        start: Instant,
        packet: u64,
        rtt: Duration,
    ) {
        controller.on_sent_packet(start, 1_200, 2, packet, 0, false);
        controller.on_sent(start, 1_200, packet);
        let now = start + rtt;
        controller.on_ack_packet(now, start, 1_200, 2, packet, false);
        controller.bytes_acked += 1_200;
        controller.sample_min_rtt = Some(rtt);
        if rtt < controller.min_rtt {
            controller.min_rtt = rtt;
            controller.min_rtt_stamp = now;
        }
        controller.finish_event(now, 0, false, Some(packet));
    }

    #[test]
    fn startup_plateau_drains_into_probe_bw() {
        let start = Instant::now();
        let mut controller = controller(start);
        for round in 1..=5 {
            ack_round(
                &mut controller,
                start + Duration::from_secs(round),
                round,
                Duration::from_millis(100),
            );
        }
        assert!(controller.full_bandwidth_reached);
        assert!(matches!(
            controller.mode,
            Mode::Drain | Mode::ProbeBw(ProbePhase::Down)
        ));
        if controller.mode == Mode::Drain {
            controller.finish_event(
                start + Duration::from_secs(7),
                0,
                false,
                Some(6),
            );
            assert_eq!(controller.mode, Mode::ProbeBw(ProbePhase::Down));
        }
    }

    #[test]
    fn high_loss_sets_bbr2_model_bounds() {
        let start = Instant::now();
        let mut controller = controller(start);
        controller.full_bw = 1_000_000;
        controller.bytes_acked = 12_000;
        controller.bytes_lost = 12_000;
        controller.loss_events = STARTUP_FULL_LOSS_EVENTS;
        controller.finish_event(
            start + Duration::from_millis(100),
            24_000,
            false,
            Some(1),
        );
        assert!(controller.bandwidth_lo.is_some());
        assert!(controller.inflight_lo.is_some());
        assert!(controller.inflight_hi.is_some());
        assert_eq!(controller.mode, Mode::Drain);
    }

    #[test]
    fn probe_rtt_is_time_and_inflight_gated() {
        let start = Instant::now();
        let mut controller = controller(start);
        controller.mode = Mode::ProbeBw(ProbePhase::Cruise);
        controller.min_rtt_stamp = start;
        controller.finish_event(start + PROBE_RTT_PERIOD, 0, false, Some(1));
        assert_eq!(controller.mode, Mode::ProbeRtt);
        assert_eq!(controller.window(), controller.probe_rtt_cwnd());
    }

    #[test]
    fn mtu_update_scales_window_and_floor() {
        let start = Instant::now();
        let mut controller = controller(start);
        let old = controller.window();
        controller.on_mtu_update(1_350);
        assert_eq!(controller.initial_window(), 32 * 1_350);
        assert!(controller.window() > old);
        assert!(controller.window() >= 4 * 1_350);
    }

    #[test]
    fn ack_aggregation_adds_bounded_inflight_budget() {
        let start = Instant::now();
        let mut controller = controller(start);
        controller.min_rtt = Duration::from_millis(100);
        controller
            .sampler
            .on_sent_packet(start, 6_000, 2, 1, 0, false);
        controller.sampler.on_ack_packet(
            start + Duration::from_millis(100),
            2,
            1,
            1,
        );

        let bandwidth = controller.sampler.get_estimate();
        assert_eq!(bandwidth, 60_000);
        assert_eq!(
            controller.ack_aggregation.update_ack_aggregation_bytes(
                6_000,
                start + Duration::from_millis(100),
                1,
                bandwidth,
                true,
            ),
            0
        );
        let excess = controller.ack_aggregation.update_ack_aggregation_bytes(
            12_000,
            start + Duration::from_millis(101),
            1,
            bandwidth,
            false,
        );
        assert_eq!(excess, 17_880);

        controller.full_bandwidth_reached = true;
        controller.extra_acked = controller
            .ack_aggregation
            .max_ack_height()
            .min(controller.cwnd);
        let base = controller
            .bdp(controller.cwnd_gain())
            .max(controller.min_cwnd);
        assert_eq!(controller.target_inflight(), base + excess);

        controller.inflight_hi = Some(base + controller.mtu);
        assert_eq!(controller.target_inflight(), base + controller.mtu);
    }

    #[test]
    fn loss_only_event_preserves_ack_aggregation_budget() {
        let start = Instant::now();
        let mut controller = controller(start);
        assert_eq!(
            controller
                .ack_aggregation
                .update_ack_aggregation_bytes(6_000, start, 1, 60_000, false,),
            0
        );
        let extra = controller.ack_aggregation.update_ack_aggregation_bytes(
            12_000,
            start + Duration::from_millis(1),
            1,
            60_000,
            false,
        );
        assert_eq!(extra, 17_880);
        controller.full_bandwidth_reached = true;
        controller.extra_acked = extra;
        controller.bytes_lost = controller.mtu;

        controller.finish_event(
            start + Duration::from_secs(1),
            controller.cwnd,
            false,
            None,
        );

        assert_eq!(controller.extra_acked, extra);
    }
}
