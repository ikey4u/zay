// Adapted from quinn-proto's BBR controller (MIT OR Apache-2.0) and
// parameterized to match sing-quic/congestion_meta2 profile behavior.

use std::any::Any;
use std::fmt::{self, Debug};
use std::sync::Arc;

use rand::{Rng, SeedableRng};

use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory, ControllerMetrics},
};
use std::time::{Duration, Instant};

use self::bw_estimation::BandwidthEstimation;

pub(crate) mod bw_estimation;
mod min_max;

const INITIAL_CONGESTION_WINDOW_PACKETS: u64 = 32;

/// Hysteria2's BBR compatibility profiles.
///
/// Parameter values and transitions follow `sing-quic/congestion_meta2`.
/// The controller implementation is adapted from Quinn's BSD-3-Clause BBR
/// implementation because Quinn's public `BbrConfig` does not expose these
/// knobs.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub enum BbrProfile {
    Conservative,
    #[default]
    Standard,
    Aggressive,
}

impl BbrProfile {
    pub fn parse(value: &str) -> Result<Self, BbrProfileError> {
        match value {
            "" | "standard" => Ok(Self::Standard),
            "conservative" => Ok(Self::Conservative),
            "aggressive" => Ok(Self::Aggressive),
            _ => Err(BbrProfileError(value.to_owned())),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Standard => "standard",
            Self::Aggressive => "aggressive",
        }
    }

    const fn parameters(self) -> ProfileParameters {
        match self {
            Self::Conservative => ProfileParameters {
                high_gain: 2.25,
                high_cwnd_gain: 1.75,
                congestion_window_gain: 1.75,
                startup_rtts: 2,
                drain_to_target: true,
                detect_overshooting: true,
                bytes_lost_multiplier: 1,
                enable_ack_aggregation_startup: false,
                expire_ack_aggregation_startup: false,
                enable_overestimate_avoidance: true,
                reduce_extra_acked_on_bandwidth_increase: true,
            },
            Self::Standard => ProfileParameters {
                high_gain: 2.885,
                high_cwnd_gain: 2.0,
                congestion_window_gain: 2.0,
                startup_rtts: 3,
                drain_to_target: false,
                detect_overshooting: false,
                bytes_lost_multiplier: 2,
                enable_ack_aggregation_startup: false,
                expire_ack_aggregation_startup: false,
                enable_overestimate_avoidance: false,
                reduce_extra_acked_on_bandwidth_increase: false,
            },
            Self::Aggressive => ProfileParameters {
                high_gain: 3.0,
                high_cwnd_gain: 2.25,
                congestion_window_gain: 2.5,
                startup_rtts: 4,
                drain_to_target: false,
                detect_overshooting: false,
                bytes_lost_multiplier: 2,
                enable_ack_aggregation_startup: true,
                expire_ack_aggregation_startup: true,
                enable_overestimate_avoidance: false,
                reduce_extra_acked_on_bandwidth_increase: false,
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BbrProfileError(String);

impl fmt::Display for BbrProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unsupported BBR profile: {}", self.0)
    }
}

impl std::error::Error for BbrProfileError {}

#[derive(Debug, Clone, Copy)]
struct ProfileParameters {
    high_gain: f32,
    high_cwnd_gain: f32,
    congestion_window_gain: f32,
    startup_rtts: u64,
    drain_to_target: bool,
    detect_overshooting: bool,
    bytes_lost_multiplier: u64,
    enable_ack_aggregation_startup: bool,
    expire_ack_aggregation_startup: bool,
    enable_overestimate_avoidance: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

/// Experimental! Use at your own risk.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on google's quiche implementation <https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/congestion_control/bbr_sender.cc>
/// of BBR <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>.
/// More discussion and links at <https://groups.google.com/g/bbr-dev>.
#[derive(Debug, Clone)]
pub struct Bbr {
    parameters: ProfileParameters,
    current_mtu: u64,
    max_bandwidth: BandwidthEstimation,
    acked_bytes: u64,
    mode: Mode,
    loss_state: LossState,
    recovery_state: RecoveryState,
    recovery_window: u64,
    is_at_full_bandwidth: bool,
    pacing_gain: f32,
    high_gain: f32,
    drain_gain: f32,
    cwnd_gain: f32,
    high_cwnd_gain: f32,
    last_cycle_start: Option<Instant>,
    current_cycle_offset: u8,
    init_cwnd: u64,
    min_cwnd: u64,
    prev_in_flight_count: u64,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_last_started_at: Option<Instant>,
    min_rtt: Duration,
    exiting_quiescence: bool,
    pacing_rate: u64,
    max_acked_packet_number: u64,
    max_sent_packet_number: u64,
    end_recovery_at_packet_number: u64,
    cwnd: u64,
    current_round_trip_end_packet_number: u64,
    round_count: u64,
    bw_at_last_round: u64,
    round_wo_bw_gain: u64,
    ack_aggregation: AckAggregationState,
    random_number_generator: rand::rngs::StdRng,
    has_non_app_limited_sample: bool,
    bytes_lost_while_detecting_overshooting: u64,
    bandwidth_increased: bool,
    loss_events_in_round: u64,
    bytes_lost_in_round: u64,
}

impl Bbr {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<BbrConfig>, current_mtu: u16) -> Self {
        let initial_window =
            INITIAL_CONGESTION_WINDOW_PACKETS * u64::from(current_mtu);
        let parameters = config.profile.parameters();
        Self {
            parameters,
            current_mtu: current_mtu as u64,
            max_bandwidth: BandwidthEstimation::new(
                parameters.enable_overestimate_avoidance,
            ),
            acked_bytes: 0,
            mode: Mode::Startup,
            loss_state: Default::default(),
            recovery_state: RecoveryState::NotInRecovery,
            recovery_window: 0,
            is_at_full_bandwidth: false,
            pacing_gain: parameters.high_gain,
            high_gain: parameters.high_gain,
            drain_gain: 1.0 / parameters.high_gain,
            cwnd_gain: parameters.high_cwnd_gain,
            high_cwnd_gain: parameters.high_cwnd_gain,
            last_cycle_start: None,
            current_cycle_offset: 0,
            init_cwnd: initial_window,
            min_cwnd: calculate_min_window(current_mtu as u64),
            prev_in_flight_count: 0,
            exit_probe_rtt_at: None,
            probe_rtt_last_started_at: None,
            min_rtt: Default::default(),
            exiting_quiescence: false,
            pacing_rate: 0,
            max_acked_packet_number: 0,
            max_sent_packet_number: 0,
            end_recovery_at_packet_number: 0,
            cwnd: initial_window,
            current_round_trip_end_packet_number: 0,
            round_count: 0,
            bw_at_last_round: 0,
            round_wo_bw_gain: 0,
            ack_aggregation: AckAggregationState::new(
                parameters.enable_overestimate_avoidance,
                parameters.reduce_extra_acked_on_bandwidth_increase,
            ),
            random_number_generator: rand::rngs::StdRng::from_entropy(),
            has_non_app_limited_sample: false,
            bytes_lost_while_detecting_overshooting: 0,
            bandwidth_increased: false,
            loss_events_in_round: 0,
            bytes_lost_in_round: 0,
        }
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.cwnd_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = self.parameters.congestion_window_gain;
        self.last_cycle_start = Some(now);
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let mut rand_index = self
            .random_number_generator
            .gen_range(0..K_PACING_GAIN.len() as u8 - 1);
        if rand_index >= 1 {
            rand_index += 1;
        }
        self.current_cycle_offset = rand_index;
        self.pacing_gain = K_PACING_GAIN[rand_index as usize];
    }

    fn update_recovery_state(&mut self, is_round_start: bool) {
        // sing-quic keeps packet conservation disabled during STARTUP. Losses
        // are considered separately by the startup-loss exit threshold.
        if !self.is_at_full_bandwidth {
            return;
        }
        // Exit recovery when there are no losses for a round.
        if self.loss_state.has_losses() {
            self.end_recovery_at_packet_number = self.max_sent_packet_number;
        }
        match self.recovery_state {
            // Enter conservation on the first loss.
            RecoveryState::NotInRecovery if self.loss_state.has_losses() => {
                self.recovery_state = RecoveryState::Conservation;
                // This will cause the |recovery_window| to be set to the
                // correct value in CalculateRecoveryWindow().
                self.recovery_window = 0;
                // Since the conservation phase is meant to be lasting for a whole
                // round, extend the current round as if it were started right now.
                self.current_round_trip_end_packet_number =
                    self.max_sent_packet_number;
            }
            RecoveryState::Growth | RecoveryState::Conservation => {
                if self.recovery_state == RecoveryState::Conservation
                    && is_round_start
                {
                    self.recovery_state = RecoveryState::Growth;
                }
                // Exit recovery if appropriate.
                if !self.loss_state.has_losses()
                    && self.max_acked_packet_number
                        > self.end_recovery_at_packet_number
                {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
            _ => {}
        }
    }

    fn update_gain_cycle_phase(&mut self, now: Instant, in_flight: u64) {
        // In most cases, the cycle is advanced after an RTT passes.
        let mut should_advance_gain_cycling = self
            .last_cycle_start
            .map(|last_cycle_start| {
                now.duration_since(last_cycle_start) > self.min_rtt
            })
            .unwrap_or(false);
        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as
        // long as there are no losses suggesting that the buffers are not able to
        // hold that much.
        if self.pacing_gain > 1.0
            && !self.loss_state.has_losses()
            && self.prev_in_flight_count
                < self.get_target_cwnd(self.pacing_gain)
        {
            should_advance_gain_cycling = false;
        }

        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the
        // number of bytes in flight falls down to the estimated BDP value earlier,
        // conclude that the queue has been successfully drained and exit this cycle
        // early.
        if self.pacing_gain < 1.0 && in_flight <= self.get_target_cwnd(1.0) {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.current_cycle_offset =
                (self.current_cycle_offset + 1) % K_PACING_GAIN.len() as u8;
            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.  Low gain mode
            // will be exited immediately when the target BDP is achieved.
            if self.parameters.drain_to_target
                && self.pacing_gain < 1.0
                && (K_PACING_GAIN[self.current_cycle_offset as usize] - 1.0)
                    .abs()
                    < f32::EPSILON
                && in_flight > self.get_target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain =
                K_PACING_GAIN[self.current_cycle_offset as usize];
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: u64) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && in_flight <= self.get_target_cwnd(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn is_min_rtt_expired(&self, now: Instant, app_limited: bool) -> bool {
        !app_limited
            && self
                .probe_rtt_last_started_at
                .map(|last| {
                    now.saturating_duration_since(last)
                        > Duration::from_secs(10)
                })
                .unwrap_or(true)
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
        let min_rtt_expired = self.is_min_rtt_expired(now, app_limited);
        if min_rtt_expired
            && !self.exiting_quiescence
            && self.mode != Mode::ProbeRtt
        {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit ProbeRtt until the
            // |bytes_in_flight| is at the target small value.
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);
        }

        if self.mode == Mode::ProbeRtt {
            match self.exit_probe_rtt_at {
                None => {
                    // If the window has reached the appropriate size, schedule exiting
                    // ProbeRtt.  The CWND during ProbeRtt is
                    // kMinimumCongestionWindow, but we allow an extra packet since QUIC
                    // checks CWND before sending a packet.
                    if bytes_in_flight
                        < self.get_probe_rtt_cwnd() + self.current_mtu
                    {
                        const K_PROBE_RTT_TIME: Duration =
                            Duration::from_millis(200);
                        self.exit_probe_rtt_at = Some(now + K_PROBE_RTT_TIME);
                    }
                }
                Some(exit_time) if is_round_start && now >= exit_time => {
                    if !self.is_at_full_bandwidth {
                        self.enter_startup_mode();
                    } else {
                        self.enter_probe_bandwidth_mode(now);
                    }
                }
                Some(_) => {}
            }
        }

        self.exiting_quiescence = false;
    }

    fn get_target_cwnd(&self, gain: f32) -> u64 {
        let bw = self.max_bandwidth.get_estimate();
        let bdp = self.min_rtt.as_micros() as u64 * bw;
        let bdpf = bdp as f64;
        let cwnd = ((gain as f64 * bdpf) / 1_000_000f64) as u64;
        // BDP estimate will be zero if no bandwidth samples are available yet.
        if cwnd == 0 {
            return ((gain as f64 * self.init_cwnd as f64) as u64)
                .max(self.min_cwnd);
        }
        cwnd.max(self.min_cwnd)
    }

    fn get_probe_rtt_cwnd(&self) -> u64 {
        self.min_cwnd
    }

    fn calculate_pacing_rate(&mut self, bytes_lost: u64) {
        let bw = self.max_bandwidth.get_estimate();
        if bw == 0 {
            return;
        }
        let target_rate = (bw as f64 * self.pacing_gain as f64) as u64;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements are
        // available.
        if self.pacing_rate == 0 && self.min_rtt.as_nanos() != 0 {
            self.pacing_rate = BandwidthEstimation::bw_from_delta(
                self.init_cwnd,
                self.min_rtt,
            )
            .unwrap();
            return;
        }

        if self.parameters.detect_overshooting {
            self.bytes_lost_while_detecting_overshooting = self
                .bytes_lost_while_detecting_overshooting
                .saturating_add(bytes_lost);
            if self.pacing_rate > target_rate
                && self.bytes_lost_while_detecting_overshooting > 0
                && (self.has_non_app_limited_sample
                    || self
                        .bytes_lost_while_detecting_overshooting
                        .saturating_mul(self.parameters.bytes_lost_multiplier)
                        > self.init_cwnd)
            {
                let minimum_rate = BandwidthEstimation::bw_from_delta(
                    self.init_cwnd,
                    self.min_rtt,
                )
                .unwrap_or(0);
                self.pacing_rate = target_rate.max(minimum_rate);
                self.bytes_lost_while_detecting_overshooting = 0;
                self.parameters.detect_overshooting = false;
            }
        }

        // Do not decrease the pacing rate during startup.
        if self.pacing_rate < target_rate {
            self.pacing_rate = target_rate;
        }
    }

    fn calculate_cwnd(&mut self, bytes_acked: u64, excess_acked: u64) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window += self.ack_aggregation.max_ack_height.get();
        } else if self.parameters.enable_ack_aggregation_startup {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max filter.
            target_window += excess_acked;
        }
        // Instead of immediately setting the target CWND as the new one, BBR grows
        // the CWND towards |target_window| by only increasing it |bytes_acked| at a
        // time.
        if self.is_at_full_bandwidth {
            self.cwnd = target_window.min(self.cwnd + bytes_acked);
        } else if self.cwnd < target_window || self.acked_bytes < self.init_cwnd
        {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.cwnd += bytes_acked;
        }

        // Enforce the limits on the congestion window.
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn calculate_recovery_window(
        &mut self,
        bytes_acked: u64,
        bytes_lost: u64,
        in_flight: u64,
    ) {
        if !self.recovery_state.in_recovery() {
            return;
        }
        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.min_cwnd.max(in_flight + bytes_acked);
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            // k_max_segment_size = current_mtu
            self.recovery_window = self.current_mtu;
        }
        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window += bytes_acked;
        }

        // Sanity checks.  Ensure that we always allow to send at least an MSS or
        // |bytes_acked| in response, whichever is larger.
        self.recovery_window = self
            .recovery_window
            .max(in_flight + bytes_acked)
            .max(self.min_cwnd);
    }

    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    fn check_if_full_bw_reached(&mut self, app_limited: bool) {
        if app_limited {
            return;
        }
        let target = (self.bw_at_last_round as f64
            * K_STARTUP_GROWTH_TARGET as f64) as u64;
        let bw = self.max_bandwidth.get_estimate();
        if bw >= target {
            self.bw_at_last_round = bw;
            self.round_wo_bw_gain = 0;
            if self.parameters.expire_ack_aggregation_startup {
                self.ack_aggregation.max_ack_height.reset();
            }
            return;
        }

        self.round_wo_bw_gain += 1;
        if self.round_wo_bw_gain >= self.parameters.startup_rtts
            || self.should_exit_startup_due_to_loss()
        {
            self.is_at_full_bandwidth = true;
        }
    }

    fn should_exit_startup_due_to_loss(&self) -> bool {
        self.loss_events_in_round >= 8
            && self.prev_in_flight_count > 0
            && self.bytes_lost_in_round
                > (self.prev_in_flight_count as f64 * 0.02) as u64
    }
}

impl Controller for Bbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.max_sent_packet_number = last_packet_number;
        let _ = (now, bytes);
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
        self.max_sent_packet_number =
            self.max_sent_packet_number.max(packet_number);
        self.max_bandwidth.on_sent_packet(
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
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        let _ = sent;
        self.acked_bytes += bytes;
        if self.is_min_rtt_expired(now, app_limited) || self.min_rtt > rtt.min()
        {
            self.min_rtt = rtt.min();
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
        let (increased, non_app_limited) = self.max_bandwidth.on_ack_packet(
            now,
            packet_space,
            packet_number,
            self.round_count,
        );
        self.bandwidth_increased |= increased;
        self.has_non_app_limited_sample |= non_app_limited;
    }

    fn on_lost_packet(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        packet_space: u8,
        packet_number: u64,
    ) {
        // Keep the delivery sampler proportional to the live QUIC flight.
        // sing-quic removes lost/obsolete packet state from its growable
        // packet-number queue; Quinn has already retired the packet when this
        // callback runs, so it cannot produce a later bandwidth sample.
        self.max_bandwidth
            .retire_packet(packet_space, packet_number);
    }

    fn on_discarded_packet(&mut self, packet_space: u8, packet_number: u64) {
        self.max_bandwidth
            .retire_packet(packet_space, packet_number);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window();
        let excess_acked = self.ack_aggregation.update_ack_aggregation_bytes(
            bytes_acked,
            now,
            self.round_count,
            self.max_bandwidth.get_estimate(),
            self.bandwidth_increased,
        );
        self.max_bandwidth.end_acks(excess_acked == 0);
        if let Some(largest_acked_packet) = largest_packet_num_acked {
            self.max_acked_packet_number = largest_acked_packet;
        }

        let mut is_round_start = false;
        if bytes_acked > 0 {
            is_round_start = self.max_acked_packet_number
                > self.current_round_trip_end_packet_number;
            if is_round_start {
                self.current_round_trip_end_packet_number =
                    self.max_sent_packet_number;
                self.round_count += 1;
            }
        }

        self.update_recovery_state(is_round_start);

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(now, in_flight);
        }

        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached(app_limited);
        }

        self.maybe_exit_startup_or_drain(now, in_flight);

        self.maybe_enter_or_exit_probe_rtt(
            now,
            is_round_start,
            in_flight,
            app_limited,
        );

        // After the model is updated, recalculate the pacing rate and congestion window.
        self.calculate_pacing_rate(self.loss_state.lost_bytes);
        self.calculate_cwnd(bytes_acked, excess_acked);
        self.calculate_recovery_window(
            bytes_acked,
            self.loss_state.lost_bytes,
            in_flight,
        );

        self.prev_in_flight_count = in_flight;
        self.bandwidth_increased = false;
        if is_round_start {
            self.loss_events_in_round = 0;
            self.bytes_lost_in_round = 0;
        }
        self.loss_state.reset();
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.loss_state.lost_bytes += lost_bytes;
        if lost_bytes > 0 {
            self.loss_events_in_round += 1;
            self.bytes_lost_in_round =
                self.bytes_lost_in_round.saturating_add(lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.min_cwnd = calculate_min_window(self.current_mtu);
        self.init_cwnd = (INITIAL_CONGESTION_WINDOW_PACKETS * self.current_mtu)
            .max(self.min_cwnd);
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    fn window(&self) -> u64 {
        if self.mode == Mode::ProbeRtt {
            return self.get_probe_rtt_cwnd();
        } else if self.recovery_state.in_recovery()
            && self.mode != Mode::Startup
        {
            return self.cwnd.min(self.recovery_window);
        }
        self.cwnd
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.pacing_rate * 8);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.init_cwnd
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the [`Bbr`] congestion controller
#[derive(Debug, Clone)]
pub struct BbrConfig {
    profile: BbrProfile,
}

impl BbrConfig {
    pub const fn new(profile: BbrProfile) -> Self {
        Self { profile }
    }

    pub const fn profile(&self) -> BbrProfile {
        self.profile
    }
}

impl Default for BbrConfig {
    fn default() -> Self {
        Self {
            profile: BbrProfile::Standard,
        }
    }
}

impl ControllerFactory for BbrConfig {
    fn build(
        self: Arc<Self>,
        _now: Instant,
        current_mtu: u16,
    ) -> Box<dyn Controller> {
        Box::new(Bbr::new(self, current_mtu))
    }
}

#[derive(Debug, Default, Copy, Clone)]
struct AckHeightEvent {
    extra_acked: u64,
    bytes_acked: u64,
    time_delta: Duration,
    round: u64,
}

#[derive(Debug, Copy, Clone)]
struct AckHeightFilter {
    window: u64,
    samples: [AckHeightEvent; 3],
}

impl AckHeightFilter {
    const fn get(&self) -> u64 {
        self.samples[0].extra_acked
    }

    fn reset(&mut self) {
        self.samples.fill(AckHeightEvent::default());
    }

    fn update(&mut self, event: AckHeightEvent) {
        if self.samples[0].extra_acked == 0
            || event.extra_acked >= self.samples[0].extra_acked
            || event.round.saturating_sub(self.samples[2].round) > self.window
        {
            self.samples.fill(event);
            return;
        }

        if event.extra_acked >= self.samples[1].extra_acked {
            self.samples[1] = event;
            self.samples[2] = event;
        } else if event.extra_acked >= self.samples[2].extra_acked {
            self.samples[2] = event;
        }

        let elapsed = event.round.saturating_sub(self.samples[0].round);
        if elapsed > self.window {
            self.samples[0] = self.samples[1];
            self.samples[1] = self.samples[2];
            self.samples[2] = event;
            if event.round.saturating_sub(self.samples[0].round) > self.window {
                self.samples[0] = self.samples[1];
                self.samples[1] = self.samples[2];
                self.samples[2] = event;
            }
        } else if self.samples[1].round == self.samples[0].round
            && elapsed > self.window / 4
        {
            self.samples[1] = event;
            self.samples[2] = event;
        } else if self.samples[2].round == self.samples[1].round
            && elapsed > self.window / 2
        {
            self.samples[2] = event;
        }
    }

    fn rebase(&mut self, bandwidth: u64) {
        let previous = self.samples;
        self.reset();
        for mut event in previous {
            let expected = bandwidth
                .saturating_mul(event.time_delta.as_micros() as u64)
                .saturating_div(1_000_000);
            if expected < event.bytes_acked {
                event.extra_acked = event.bytes_acked - expected;
                self.update(event);
            }
        }
    }
}

impl Default for AckHeightFilter {
    fn default() -> Self {
        Self {
            window: 10,
            samples: [AckHeightEvent::default(); 3],
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct AckAggregationState {
    max_ack_height: AckHeightFilter,
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: u64,
    bandwidth_threshold: u64,
    reduce_on_bandwidth_increase: bool,
}

impl AckAggregationState {
    fn new(
        overestimate_avoidance: bool,
        reduce_on_bandwidth_increase: bool,
    ) -> Self {
        Self {
            max_ack_height: AckHeightFilter::default(),
            aggregation_epoch_start_time: None,
            aggregation_epoch_bytes: 0,
            bandwidth_threshold: if overestimate_avoidance { 2 } else { 1 },
            reduce_on_bandwidth_increase,
        }
    }

    fn update_ack_aggregation_bytes(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round: u64,
        max_bandwidth: u64,
        bandwidth_increased: bool,
    ) -> u64 {
        if bandwidth_increased && self.reduce_on_bandwidth_increase {
            // sing-quic retains the three windowed events and recalculates
            // their heights at the new bandwidth instead of discarding the
            // ACK history outright.
            self.max_ack_height.rebase(max_bandwidth);
        }

        // Compute how many bytes are expected to be delivered, assuming max
        // bandwidth is correct.
        let expected_bytes_acked = max_bandwidth
            .saturating_mul(
                now.saturating_duration_since(
                    self.aggregation_epoch_start_time.unwrap_or(now),
                )
                .as_micros() as u64,
            )
            .saturating_div(1_000_000)
            .saturating_mul(self.bandwidth_threshold);

        // Reset the current aggregation epoch as soon as the ack arrival rate is
        // less than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes <= expected_bytes_acked {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = newly_acked_bytes;
            self.aggregation_epoch_start_time = Some(now);
            return 0;
        }

        // Compute how many extra bytes were delivered vs max bandwidth.
        // Include the bytes most recently acknowledged to account for stretch acks.
        self.aggregation_epoch_bytes += newly_acked_bytes;
        let diff = self.aggregation_epoch_bytes - expected_bytes_acked;
        self.max_ack_height.update(AckHeightEvent {
            extra_acked: diff,
            bytes_acked: self.aggregation_epoch_bytes,
            time_delta: now.saturating_duration_since(
                self.aggregation_epoch_start_time.unwrap_or(now),
            ),
            round,
        });
        diff
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Mode {
    // Startup phase of the connection.
    Startup,
    // After achieving the highest possible bandwidth during the startup, lower
    // the pacing rate in order to drain the queue.
    Drain,
    // Cruising mode.
    ProbeBw,
    // Temporarily slow down sending in order to empty the buffer and measure
    // the real minimum RTT.
    ProbeRtt,
}

// Indicates how the congestion control limits the amount of bytes in flight.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RecoveryState {
    // Do not limit.
    NotInRecovery,
    // Allow an extra outstanding byte for each byte acknowledged.
    Conservation,
    // Allow two extra outstanding bytes for each byte acknowledged (slow
    // start).
    Growth,
}

impl RecoveryState {
    pub(super) fn in_recovery(&self) -> bool {
        !matches!(self, Self::NotInRecovery)
    }
}

#[derive(Debug, Clone, Default)]
struct LossState {
    lost_bytes: u64,
}

impl LossState {
    pub(super) fn reset(&mut self) {
        self.lost_bytes = 0;
    }

    pub(super) fn has_losses(&self) -> bool {
        self.lost_bytes != 0
    }
}

fn calculate_min_window(current_mtu: u64) -> u64 {
    4 * current_mtu
}

// The cycle of gains used during the ProbeBw stage.
const K_PACING_GAIN: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

const K_STARTUP_GROWTH_TARGET: f32 = 1.25;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_sing_quic_profiles_and_empty_default() {
        assert_eq!(BbrProfile::parse(""), Ok(BbrProfile::Standard));
        assert_eq!(BbrProfile::parse("standard"), Ok(BbrProfile::Standard));
        assert_eq!(
            BbrProfile::parse("conservative"),
            Ok(BbrProfile::Conservative)
        );
        assert_eq!(BbrProfile::parse("aggressive"), Ok(BbrProfile::Aggressive));
        assert_eq!(
            BbrProfile::parse("fast").unwrap_err().to_string(),
            "unsupported BBR profile: fast"
        );
    }

    #[test]
    fn profile_parameters_match_sing_quic() {
        let conservative = BbrProfile::Conservative.parameters();
        assert_eq!(conservative.high_gain, 2.25);
        assert_eq!(conservative.high_cwnd_gain, 1.75);
        assert_eq!(conservative.congestion_window_gain, 1.75);
        assert_eq!(conservative.startup_rtts, 2);
        assert!(conservative.drain_to_target);
        assert!(conservative.detect_overshooting);
        assert_eq!(conservative.bytes_lost_multiplier, 1);
        assert!(conservative.enable_overestimate_avoidance);
        assert!(conservative.reduce_extra_acked_on_bandwidth_increase);

        let standard = BbrProfile::Standard.parameters();
        assert_eq!(standard.high_gain, 2.885);
        assert_eq!(standard.high_cwnd_gain, 2.0);
        assert_eq!(standard.congestion_window_gain, 2.0);
        assert_eq!(standard.startup_rtts, 3);
        assert_eq!(standard.bytes_lost_multiplier, 2);

        let aggressive = BbrProfile::Aggressive.parameters();
        assert_eq!(aggressive.high_gain, 3.0);
        assert_eq!(aggressive.high_cwnd_gain, 2.25);
        assert_eq!(aggressive.congestion_window_gain, 2.5);
        assert_eq!(aggressive.startup_rtts, 4);
        assert!(aggressive.enable_ack_aggregation_startup);
        assert!(aggressive.expire_ack_aggregation_startup);
    }

    #[test]
    fn controller_uses_sing_quic_packet_windows() {
        let controller =
            Bbr::new(Arc::new(BbrConfig::new(BbrProfile::Conservative)), 1_350);
        assert_eq!(controller.initial_window(), 32 * 1_350);
        assert_eq!(controller.min_cwnd, 4 * 1_350);
        assert_eq!(controller.get_target_cwnd(2.0), 64 * 1_350);
        assert_eq!(controller.get_probe_rtt_cwnd(), 4 * 1_350);
        assert_eq!(controller.high_gain, 2.25);
        assert_eq!(controller.high_cwnd_gain, 1.75);
    }

    #[test]
    fn startup_round_limits_and_loss_recovery_match_sing_quic() {
        for (profile, rounds) in [
            (BbrProfile::Conservative, 2),
            (BbrProfile::Standard, 3),
            (BbrProfile::Aggressive, 4),
        ] {
            let mut controller =
                Bbr::new(Arc::new(BbrConfig::new(profile)), 1_200);
            controller.bw_at_last_round = 1;
            for _ in 1..rounds {
                controller.check_if_full_bw_reached(false);
                assert!(!controller.is_at_full_bandwidth);
            }
            controller.check_if_full_bw_reached(false);
            assert!(controller.is_at_full_bandwidth);
        }

        let mut controller =
            Bbr::new(Arc::new(BbrConfig::new(BbrProfile::Standard)), 1_200);
        controller.loss_state.lost_bytes = 1_200;
        controller.update_recovery_state(false);
        assert_eq!(
            controller.recovery_state,
            RecoveryState::NotInRecovery,
            "packet conservation must stay disabled during STARTUP"
        );
    }

    #[test]
    fn conservative_ack_height_is_rebased_when_bandwidth_increases() {
        let mut filter = AckHeightFilter::default();
        filter.update(AckHeightEvent {
            extra_acked: 1_000,
            bytes_acked: 2_000,
            time_delta: Duration::from_millis(100),
            round: 1,
        });
        filter.rebase(15_000);
        assert_eq!(filter.get(), 500);

        filter.rebase(25_000);
        assert_eq!(filter.get(), 0);
    }

    #[test]
    fn lost_and_discarded_packets_are_retired_from_delivery_sampler() {
        let start = Instant::now();
        let mut controller =
            Bbr::new(Arc::new(BbrConfig::new(BbrProfile::Standard)), 1_200);
        for packet in 1..=512_u64 {
            let sent = start + Duration::from_micros(packet);
            controller.on_sent_packet(
                sent,
                1_200,
                2,
                packet,
                (packet - 1) * 1_200,
                false,
            );
        }
        assert_eq!(controller.max_bandwidth.tracked_packet_count(), 512);

        for packet in 1..=256_u64 {
            let sent = start + Duration::from_micros(packet);
            controller.on_lost_packet(
                start + Duration::from_millis(100),
                sent,
                1_200,
                2,
                packet,
            );
        }
        for packet in 257..=512_u64 {
            controller.on_discarded_packet(2, packet);
        }
        assert_eq!(controller.max_bandwidth.tracked_packet_count(), 0);
    }
}
