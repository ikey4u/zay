use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;

pub const PRE_PULL_INITIAL_PING_RESTART: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientPingTimeoutAction {
    #[default]
    None,
    Restart,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeepalivePolicy {
    pub ping_interval: Duration,
    pub ping_restart: Duration,
    pub ping_exit: Duration,
    pub inactive_timeout: Duration,
    pub inactive_minimum_bytes: u64,
    pub session_timeout: Duration,
    pub renegotiation_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveTerminal {
    SessionTimeout,
    InactiveTimeout,
    PingRestartTimeout,
    PingExitTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeepaliveDecision {
    pub request_renegotiation: bool,
    pub send_ping: bool,
    pub terminal: Option<KeepaliveTerminal>,
}

/// Clock state shared by the client/server keepalive loops. Callers perform
/// the actual I/O and soft reset, while this type preserves OpenVPN's timeout
/// precedence and its strict-vs-inclusive deadline comparisons.
#[derive(Debug, Clone)]
pub struct OpenVpnKeepaliveState {
    session_start: Instant,
    last_inbound: Option<Instant>,
    last_outbound: Option<Instant>,
    last_inactivity_reset: Instant,
    inactivity_bytes: u64,
    renegotiation_deadline: Option<Instant>,
}

impl OpenVpnKeepaliveState {
    pub fn new(now: Instant, renegotiation_interval: Duration) -> Self {
        Self {
            session_start: now,
            last_inbound: Some(now),
            last_outbound: None,
            last_inactivity_reset: now,
            inactivity_bytes: 0,
            renegotiation_deadline: (!renegotiation_interval.is_zero())
                .then(|| now + renegotiation_interval),
        }
    }

    pub fn mark_activity(
        &mut self,
        now: Instant,
        inbound: bool,
        outbound: bool,
    ) {
        if inbound {
            self.last_inbound = Some(now);
        }
        if outbound {
            self.last_outbound = Some(now);
        }
    }

    pub fn register_inactivity_bytes(
        &mut self,
        now: Instant,
        byte_count: u64,
        threshold: u64,
    ) {
        let (accumulator, reset) = register_inactivity_bytes(
            self.inactivity_bytes,
            byte_count,
            threshold,
        );
        self.inactivity_bytes = accumulator;
        if reset {
            self.last_inactivity_reset = now;
        }
    }

    pub fn note_renegotiated(
        &mut self,
        now: Instant,
        renegotiation_interval: Duration,
    ) {
        self.renegotiation_deadline = (!renegotiation_interval.is_zero())
            .then(|| now + renegotiation_interval);
    }

    pub fn evaluate(
        &self,
        now: Instant,
        policy: KeepalivePolicy,
    ) -> KeepaliveDecision {
        let request_renegotiation = self
            .renegotiation_deadline
            .is_some_and(|deadline| now >= deadline);
        let terminal = if !policy.session_timeout.is_zero()
            && now.saturating_duration_since(self.session_start)
                >= policy.session_timeout
        {
            Some(KeepaliveTerminal::SessionTimeout)
        } else if !policy.inactive_timeout.is_zero()
            && now.saturating_duration_since(self.last_inactivity_reset)
                >= policy.inactive_timeout
        {
            Some(KeepaliveTerminal::InactiveTimeout)
        } else {
            let (timeout, action) = effective_client_ping_timeout(
                policy.ping_restart,
                policy.ping_exit,
            );
            if self.last_inbound.is_some_and(|last| {
                !timeout.is_zero()
                    && now.saturating_duration_since(last) > timeout
            }) {
                match action {
                    ClientPingTimeoutAction::Restart => {
                        Some(KeepaliveTerminal::PingRestartTimeout)
                    }
                    ClientPingTimeoutAction::Exit => {
                        Some(KeepaliveTerminal::PingExitTimeout)
                    }
                    ClientPingTimeoutAction::None => None,
                }
            } else {
                None
            }
        };
        let send_ping = terminal.is_none()
            && !policy.ping_interval.is_zero()
            && self.last_outbound.is_none_or(|last| {
                now.saturating_duration_since(last) >= policy.ping_interval
            });
        KeepaliveDecision {
            request_renegotiation,
            send_ping,
            terminal,
        }
    }
}

pub fn effective_client_ping_timeout(
    ping_restart: Duration,
    ping_exit: Duration,
) -> (Duration, ClientPingTimeoutAction) {
    if !ping_exit.is_zero() {
        (ping_exit, ClientPingTimeoutAction::Exit)
    } else if !ping_restart.is_zero() {
        (ping_restart, ClientPingTimeoutAction::Restart)
    } else {
        (Duration::ZERO, ClientPingTimeoutAction::None)
    }
}

pub fn pre_pull_ping_restart(
    disabled: bool,
    configured: Duration,
    pull_enabled: bool,
    udp_transport: bool,
) -> Duration {
    if disabled {
        Duration::ZERO
    } else if !configured.is_zero() {
        configured
    } else if pull_enabled && udp_transport {
        PRE_PULL_INITIAL_PING_RESTART
    } else {
        Duration::ZERO
    }
}

pub const OPENVPN_DATA_CHANNEL_PING_PAYLOAD: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a,
    0x98, 0x1f, 0xc7, 0x48,
];
pub const OPENVPN_OCC_MAGIC: [u8; 16] = [
    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3,
    0xaf, 0xc5, 0x45, 0x9c,
];
pub const OPENVPN_OCC_REQUEST: u8 = 0;
pub const OPENVPN_OCC_REPLY: u8 = 1;
pub const OPENVPN_OCC_EXIT: u8 = 6;

pub fn openvpn_data_channel_exit_notify_payload() -> Vec<u8> {
    let mut payload = OPENVPN_OCC_MAGIC.to_vec();
    payload.push(OPENVPN_OCC_EXIT);
    payload
}

pub fn occ_opcode(payload: &[u8]) -> Option<u8> {
    payload
        .strip_prefix(&OPENVPN_OCC_MAGIC)
        .and_then(|remaining| remaining.first().copied())
}

pub fn build_occ_reply_payload(options_string: &str) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(OPENVPN_OCC_MAGIC.len() + options_string.len() + 2);
    payload.extend_from_slice(&OPENVPN_OCC_MAGIC);
    payload.push(OPENVPN_OCC_REPLY);
    payload.extend_from_slice(options_string.as_bytes());
    payload.push(0);
    payload
}

pub fn build_occ_response_for_incoming(
    incoming: &[u8],
    local_options_string: &str,
) -> Option<Vec<u8>> {
    (occ_opcode(incoming) == Some(OPENVPN_OCC_REQUEST)
        && !local_options_string.is_empty())
    .then(|| build_occ_reply_payload(local_options_string))
}

#[derive(Debug, Default)]
struct PendingInner {
    closed: bool,
    ping_pending: bool,
    occ_message: Option<Vec<u8>>,
}

/// The single-slot OpenVPN data-channel message queue. Pings take priority;
/// newer OCC messages replace older unsent ones, matching `occ_op` upstream.
#[derive(Debug, Default)]
pub struct PendingDataChannelMessages {
    inner: Mutex<PendingInner>,
    notify: Notify,
}

impl PendingDataChannelMessages {
    pub fn send_ping(&self) {
        let mut inner = self.inner.lock();
        if inner.closed {
            return;
        }
        inner.ping_pending = true;
        drop(inner);
        self.notify.notify_one();
    }

    pub fn send_occ_message(&self, payload: Vec<u8>) {
        if payload.is_empty() {
            return;
        }
        let mut inner = self.inner.lock();
        if inner.closed {
            return;
        }
        inner.occ_message = Some(payload);
        drop(inner);
        self.notify.notify_one();
    }

    pub fn take(&self) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock();
        if inner.closed {
            return None;
        }
        if inner.ping_pending {
            inner.ping_pending = false;
            return Some(OPENVPN_DATA_CHANNEL_PING_PAYLOAD.to_vec());
        }
        inner.occ_message.take()
    }

    pub async fn wait(&self) -> Option<Vec<u8>> {
        loop {
            let notified = self.notify.notified();
            if let Some(message) = self.take() {
                return Some(message);
            }
            if self.inner.lock().closed {
                return None;
            }
            notified.await;
        }
    }

    pub fn close(&self) {
        let mut inner = self.inner.lock();
        inner.closed = true;
        inner.ping_pending = false;
        inner.occ_message = None;
        drop(inner);
        self.notify.notify_waiters();
    }
}

pub fn register_inactivity_bytes(
    accumulator: u64,
    byte_count: u64,
    threshold: u64,
) -> (u64, bool) {
    let accumulated = accumulator.wrapping_add(byte_count);
    if accumulated >= threshold {
        (0, true)
    } else {
        (accumulated, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_occ_and_builds_nul_terminated_reply() {
        let mut request = OPENVPN_OCC_MAGIC.to_vec();
        request.push(OPENVPN_OCC_REQUEST);
        let reply =
            build_occ_response_for_incoming(&request, "V4,dev-type tun")
                .unwrap();
        assert_eq!(occ_opcode(&reply), Some(OPENVPN_OCC_REPLY));
        assert_eq!(reply.last(), Some(&0));
        assert!(build_occ_response_for_incoming(&request, "").is_none());
        assert_eq!(
            occ_opcode(&openvpn_data_channel_exit_notify_payload()),
            Some(OPENVPN_OCC_EXIT)
        );
    }

    #[test]
    fn pending_slot_prioritizes_ping_and_replaces_occ() {
        let pending = PendingDataChannelMessages::default();
        pending.send_occ_message(b"old".to_vec());
        pending.send_occ_message(b"new".to_vec());
        pending.send_ping();
        assert_eq!(pending.take().unwrap(), OPENVPN_DATA_CHANNEL_PING_PAYLOAD);
        assert_eq!(pending.take().unwrap(), b"new");
        assert!(pending.take().is_none());
        pending.close();
        pending.send_ping();
        assert!(pending.take().is_none());
    }

    #[tokio::test]
    async fn wait_retains_notification_until_message_is_taken() {
        let pending = PendingDataChannelMessages::default();
        pending.send_ping();
        assert_eq!(
            pending.wait().await.unwrap(),
            OPENVPN_DATA_CHANNEL_PING_PAYLOAD
        );
    }

    #[test]
    fn inactivity_zero_threshold_resets_on_any_activity() {
        assert_eq!(register_inactivity_bytes(0, 1, 0), (0, true));
        assert_eq!(register_inactivity_bytes(3, 4, 10), (7, false));
        assert_eq!(register_inactivity_bytes(7, 4, 10), (0, true));
    }

    #[test]
    fn keepalive_preserves_timeout_precedence_and_boundary_rules() {
        let start = Instant::now();
        let mut state =
            OpenVpnKeepaliveState::new(start, Duration::from_secs(30));
        state.mark_activity(start + Duration::from_secs(1), true, true);
        let policy = KeepalivePolicy {
            ping_interval: Duration::from_secs(10),
            ping_restart: Duration::from_secs(20),
            ping_exit: Duration::from_secs(15),
            inactive_timeout: Duration::from_secs(50),
            session_timeout: Duration::from_secs(60),
            ..KeepalivePolicy::default()
        };
        let boundary = state.evaluate(start + Duration::from_secs(16), policy);
        assert!(boundary.send_ping);
        assert_eq!(boundary.terminal, None);
        let expired = state.evaluate(start + Duration::from_secs(17), policy);
        assert_eq!(expired.terminal, Some(KeepaliveTerminal::PingExitTimeout));
        let session = state.evaluate(start + Duration::from_secs(60), policy);
        assert_eq!(session.terminal, Some(KeepaliveTerminal::SessionTimeout));
        assert!(session.request_renegotiation);
    }

    #[test]
    fn inactivity_threshold_and_renegotiation_reset_are_stateful() {
        let start = Instant::now();
        let mut state =
            OpenVpnKeepaliveState::new(start, Duration::from_secs(10));
        state.register_inactivity_bytes(start + Duration::from_secs(4), 4, 10);
        state.register_inactivity_bytes(start + Duration::from_secs(8), 6, 10);
        let policy = KeepalivePolicy {
            inactive_timeout: Duration::from_secs(5),
            ..KeepalivePolicy::default()
        };
        assert_eq!(
            state
                .evaluate(start + Duration::from_secs(12), policy)
                .terminal,
            None
        );
        assert_eq!(
            state
                .evaluate(start + Duration::from_secs(13), policy)
                .terminal,
            Some(KeepaliveTerminal::InactiveTimeout)
        );
        state.note_renegotiated(
            start + Duration::from_secs(12),
            Duration::from_secs(20),
        );
        assert!(
            !state
                .evaluate(
                    start + Duration::from_secs(31),
                    KeepalivePolicy::default()
                )
                .request_renegotiation
        );
    }

    #[test]
    fn pre_pull_udp_timeout_matches_openvpn_defaults() {
        assert_eq!(
            pre_pull_ping_restart(false, Duration::ZERO, true, true),
            Duration::from_secs(120)
        );
        assert_eq!(
            pre_pull_ping_restart(false, Duration::from_secs(9), true, true),
            Duration::from_secs(9)
        );
        assert_eq!(
            pre_pull_ping_restart(true, Duration::from_secs(9), true, true),
            Duration::ZERO
        );
    }
}
