use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use super::{SessionManager, next_key_id};

/// OpenVPN's default `--tran-window` and `KEY_SCAN_SIZE` limits.
pub const OPENVPN_TLS_TRANSITION_WINDOW: Duration = Duration::from_secs(3600);
pub const OPENVPN_TLS_KEY_SCAN_SIZE: usize = 3;

#[derive(Debug)]
pub struct OpenVpnReceiveKeyState<T> {
    pub key_id: u8,
    pub sequence: u64,
    pub session: Arc<SessionManager>,
    pub value: T,
    pub expires_at: Option<Instant>,
}

/// Active outbound key plus the small receive-key scan ring retained during
/// TLS soft-reset handover. Newer sequence numbers win promotion races.
#[derive(Debug)]
pub struct OpenVpnDataKeyRing<T> {
    receive: Vec<OpenVpnReceiveKeyState<T>>,
    send_key_id: u8,
    send_sequence: u64,
    promoted_sequence: u64,
    transition_window: Duration,
    scan_size: usize,
}

impl<T> OpenVpnDataKeyRing<T> {
    pub fn new(key_id: u8, session: Arc<SessionManager>, value: T) -> Self {
        Self::with_limits(
            key_id,
            session,
            value,
            OPENVPN_TLS_TRANSITION_WINDOW,
            OPENVPN_TLS_KEY_SCAN_SIZE,
        )
    }

    pub fn with_limits(
        key_id: u8,
        session: Arc<SessionManager>,
        value: T,
        transition_window: Duration,
        scan_size: usize,
    ) -> Self {
        Self {
            receive: vec![OpenVpnReceiveKeyState {
                key_id,
                sequence: 0,
                session,
                value,
                expires_at: None,
            }],
            send_key_id: key_id,
            send_sequence: 0,
            promoted_sequence: 0,
            transition_window,
            scan_size: scan_size.max(1),
        }
    }

    pub fn current_send_key_id(&self) -> u8 {
        self.send_key_id
    }

    pub fn next_soft_reset_key_id(&self) -> u8 {
        next_key_id(self.send_key_id)
    }

    pub fn current_send(&self) -> Option<&OpenVpnReceiveKeyState<T>> {
        self.receive.iter().find(|entry| {
            entry.key_id == self.send_key_id
                && entry.sequence == self.send_sequence
        })
    }

    /// Installs a negotiated receive key before it becomes the outbound key.
    /// Reusing a wrapped key-id replaces its older state, matching OpenVPN's
    /// 1..7 key-id cycle.
    pub fn stage(
        &mut self,
        key_id: u8,
        sequence: u64,
        session: Arc<SessionManager>,
        value: T,
        now: Instant,
    ) -> Result<(), DataKeyRingError> {
        validate_soft_reset_key_id(key_id)?;
        self.receive.retain(|entry| entry.key_id != key_id);
        self.receive.push(OpenVpnReceiveKeyState {
            key_id,
            sequence,
            session,
            value,
            expires_at: Some(now + self.transition_window),
        });
        self.sort_and_limit();
        Ok(())
    }

    /// Promotes a staged key for outbound data. The previous outbound key
    /// becomes a receive-only lame duck until the transition window expires.
    /// Returns false when a newer promotion already won the race.
    pub fn promote(
        &mut self,
        key_id: u8,
        sequence: u64,
        now: Instant,
    ) -> Result<bool, DataKeyRingError> {
        validate_soft_reset_key_id(key_id)?;
        if sequence <= self.promoted_sequence {
            return Ok(false);
        }
        let Some(new_index) = self.receive.iter().position(|entry| {
            entry.key_id == key_id && entry.sequence == sequence
        }) else {
            return Err(DataKeyRingError::MissingStagedKey);
        };
        let expiry = now + self.transition_window;
        for entry in &mut self.receive {
            if entry.key_id == self.send_key_id
                && entry.sequence == self.send_sequence
            {
                entry.expires_at = Some(expiry);
            }
        }
        self.receive[new_index].expires_at = None;
        self.send_key_id = key_id;
        self.send_sequence = sequence;
        self.promoted_sequence = sequence;
        self.prune(now);
        Ok(true)
    }

    pub fn discard(&mut self, key_id: u8, sequence: u64) {
        if key_id == self.send_key_id && sequence == self.send_sequence {
            return;
        }
        self.receive.retain(|entry| {
            entry.key_id != key_id || entry.sequence != sequence
        });
    }

    pub fn select_receive(
        &mut self,
        key_id: u8,
        now: Instant,
    ) -> Option<&OpenVpnReceiveKeyState<T>> {
        self.prune(now);
        self.receive.iter().find(|entry| entry.key_id == key_id)
    }

    pub fn retained_key_ids(&mut self, now: Instant) -> Vec<u8> {
        self.prune(now);
        self.receive.iter().map(|entry| entry.key_id).collect()
    }

    pub fn prune(&mut self, now: Instant) {
        self.receive.retain(|entry| {
            entry.expires_at.is_none_or(|expires_at| now < expires_at)
        });
        self.sort_and_limit();
    }

    fn sort_and_limit(&mut self) {
        self.receive.sort_by_key(|entry| entry.sequence);
        if self.receive.len() > self.scan_size {
            let remove = self.receive.len() - self.scan_size;
            self.receive.drain(..remove);
        }
    }
}

fn validate_soft_reset_key_id(key_id: u8) -> Result<(), DataKeyRingError> {
    if (1..=7).contains(&key_id) {
        Ok(())
    } else {
        Err(DataKeyRingError::InvalidSoftResetKeyId(key_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DataKeyRingError {
    #[error("invalid OpenVPN soft-reset key-id: {0}")]
    InvalidSoftResetKeyId(u8),
    #[error("OpenVPN soft-reset key was not staged")]
    MissingStagedKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(key_id: u8) -> Arc<SessionManager> {
        let initial = SessionManager::with_local_id(*b"local-id");
        Arc::new(if key_id == 0 {
            initial
        } else {
            initial.renegotiation(key_id)
        })
    }

    #[test]
    fn promotes_new_send_key_and_keeps_old_receive_key() {
        let now = Instant::now();
        let mut ring = OpenVpnDataKeyRing::with_limits(
            0,
            session(0),
            "initial",
            Duration::from_secs(10),
            3,
        );
        ring.stage(1, 1, session(1), "new", now).unwrap();
        assert_eq!(ring.current_send().unwrap().value, "initial");
        assert!(ring.promote(1, 1, now).unwrap());
        assert_eq!(ring.current_send().unwrap().value, "new");
        assert_eq!(ring.select_receive(0, now).unwrap().value, "initial");
        assert_eq!(ring.select_receive(1, now).unwrap().value, "new");
        assert!(
            ring.select_receive(0, now + Duration::from_secs(10))
                .is_none()
        );
    }

    #[test]
    fn newer_sequence_wins_and_scan_ring_keeps_three_newest() {
        let now = Instant::now();
        let mut ring = OpenVpnDataKeyRing::with_limits(
            0,
            session(0),
            0_u8,
            Duration::from_secs(30),
            3,
        );
        for key_id in 1..=4 {
            ring.stage(key_id, u64::from(key_id), session(key_id), key_id, now)
                .unwrap();
        }
        assert_eq!(ring.retained_key_ids(now), vec![2, 3, 4]);
        assert!(ring.promote(4, 4, now).unwrap());
        assert!(!ring.promote(3, 3, now).unwrap());
        assert_eq!(ring.current_send_key_id(), 4);
        assert_eq!(ring.next_soft_reset_key_id(), 5);
    }

    #[test]
    fn validates_ids_and_replaces_wrapped_key_state() {
        let now = Instant::now();
        let mut ring = OpenVpnDataKeyRing::new(0, session(0), 0_u8);
        assert_eq!(
            ring.stage(0, 1, session(0), 1, now),
            Err(DataKeyRingError::InvalidSoftResetKeyId(0))
        );
        ring.stage(1, 1, session(1), 1, now).unwrap();
        ring.stage(1, 8, session(1), 8, now).unwrap();
        assert_eq!(ring.select_receive(1, now).unwrap().sequence, 8);
    }
}
