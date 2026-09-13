use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use super::{KEY_ID_MAX_VALUE, next_key_id};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftResetStatus {
    Negotiating,
    AwaitingData,
    Active,
    LameDuck,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftResetState {
    pub key_id: u8,
    pub sequence: u64,
    pub initiator: bool,
    pub must_negotiate_by: Instant,
    pub status: SoftResetStatus,
    pub expires_at: Option<Instant>,
    pub peer_data_confirmed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeginSoftReset {
    pub key_id: u8,
    pub sequence: u64,
    pub created: bool,
}

/// Bookkeeping shared by client and server TLS soft-reset implementations.
/// It resolves simultaneous reset races by monotonic sequence, cycles key IDs
/// through 1..7, and retires prior states using OpenVPN's transition window.
#[derive(Debug)]
pub struct SoftResetCoordinator {
    states: HashMap<u8, SoftResetState>,
    active_key_id: u8,
    sequence: u64,
    promoted_sequence: u64,
    handshake_window: Duration,
    transition_window: Duration,
    key_scan_size: usize,
    closed: bool,
}

impl SoftResetCoordinator {
    pub fn new(active_key_id: u8, handshake_window: Duration) -> Self {
        Self::with_limits(
            active_key_id,
            handshake_window,
            super::OPENVPN_TLS_TRANSITION_WINDOW,
            super::OPENVPN_TLS_KEY_SCAN_SIZE,
        )
    }

    pub fn with_limits(
        active_key_id: u8,
        handshake_window: Duration,
        transition_window: Duration,
        key_scan_size: usize,
    ) -> Self {
        Self {
            states: HashMap::new(),
            active_key_id,
            sequence: 0,
            promoted_sequence: 0,
            handshake_window,
            transition_window,
            key_scan_size: key_scan_size.max(1),
            closed: false,
        }
    }

    pub fn active_key_id(&self) -> u8 {
        self.active_key_id
    }

    pub fn state(&self, key_id: u8) -> Option<&SoftResetState> {
        self.states.get(&key_id)
    }

    pub fn begin_local(
        &mut self,
        now: Instant,
    ) -> Result<BeginSoftReset, SoftResetStateError> {
        if let Some(state) = self
            .states
            .values()
            .filter(|state| {
                matches!(
                    state.status,
                    SoftResetStatus::Negotiating
                        | SoftResetStatus::AwaitingData
                )
            })
            .max_by_key(|state| state.sequence)
        {
            return Ok(BeginSoftReset {
                key_id: state.key_id,
                sequence: state.sequence,
                created: false,
            });
        }
        self.begin(next_key_id(self.active_key_id), true, now)
    }

    pub fn begin_remote(
        &mut self,
        key_id: u8,
        now: Instant,
    ) -> Result<BeginSoftReset, SoftResetStateError> {
        self.begin(key_id, false, now)
    }

    pub fn set_awaiting_data(
        &mut self,
        key_id: u8,
        sequence: u64,
        now: Instant,
    ) -> Result<(), SoftResetStateError> {
        let transition_window = self.transition_window;
        let state = self.matching_state_mut(key_id, sequence)?;
        state.status = SoftResetStatus::AwaitingData;
        state.expires_at = Some(now + transition_window);
        Ok(())
    }

    pub fn confirm_peer_data(&mut self, key_id: u8) -> bool {
        let Some(state) = self.states.get_mut(&key_id) else {
            return false;
        };
        state.peer_data_confirmed = true;
        state.status == SoftResetStatus::AwaitingData
    }

    /// Completes a key negotiation. The newest sequence is promoted; a late
    /// success remains receive-only so it cannot roll outbound traffic back.
    pub fn finish_success(
        &mut self,
        key_id: u8,
        sequence: u64,
        now: Instant,
    ) -> Result<bool, SoftResetStateError> {
        self.matching_state(key_id, sequence)?;
        let expiry = now + self.transition_window;
        if sequence <= self.promoted_sequence {
            let state = self.matching_state_mut(key_id, sequence)?;
            state.status = SoftResetStatus::LameDuck;
            state.expires_at = Some(expiry);
            self.prune(now);
            return Ok(false);
        }
        for state in self.states.values_mut() {
            if state.status == SoftResetStatus::Active {
                state.status = SoftResetStatus::LameDuck;
                state.expires_at = Some(expiry);
            }
        }
        let state = self.matching_state_mut(key_id, sequence)?;
        state.status = SoftResetStatus::Active;
        state.expires_at = None;
        self.active_key_id = key_id;
        self.promoted_sequence = sequence;
        self.prune(now);
        Ok(true)
    }

    pub fn finish_failed(
        &mut self,
        key_id: u8,
        sequence: u64,
    ) -> Result<(), SoftResetStateError> {
        let state = self.matching_state_mut(key_id, sequence)?;
        state.status = SoftResetStatus::Failed;
        self.states.remove(&key_id);
        Ok(())
    }

    pub fn prune(&mut self, now: Instant) {
        self.states.retain(|_, state| {
            !matches!(
                state.status,
                SoftResetStatus::LameDuck | SoftResetStatus::AwaitingData
            ) || state.expires_at.is_some_and(|expires_at| now < expires_at)
        });
        let mut completed = self
            .states
            .values()
            .filter(|state| {
                matches!(
                    state.status,
                    SoftResetStatus::Active
                        | SoftResetStatus::LameDuck
                        | SoftResetStatus::AwaitingData
                )
            })
            .map(|state| (state.sequence, state.key_id))
            .collect::<Vec<_>>();
        completed.sort_unstable();
        let remove_count = completed.len().saturating_sub(self.key_scan_size);
        for (_, key_id) in completed.into_iter().take(remove_count) {
            self.states.remove(&key_id);
        }
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.states.clear();
    }

    fn begin(
        &mut self,
        key_id: u8,
        initiator: bool,
        now: Instant,
    ) -> Result<BeginSoftReset, SoftResetStateError> {
        if self.closed {
            return Err(SoftResetStateError::Closed);
        }
        if key_id == 0 || key_id > KEY_ID_MAX_VALUE {
            return Err(SoftResetStateError::InvalidKeyId(key_id));
        }
        if let Some(existing) = self.states.get(&key_id)
            && (matches!(
                existing.status,
                SoftResetStatus::Negotiating | SoftResetStatus::AwaitingData
            ) || self.active_key_id == key_id)
        {
            return Ok(BeginSoftReset {
                key_id,
                sequence: existing.sequence,
                created: false,
            });
        }
        self.states.remove(&key_id);
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        self.states.insert(
            key_id,
            SoftResetState {
                key_id,
                sequence,
                initiator,
                must_negotiate_by: now + self.handshake_window,
                status: SoftResetStatus::Negotiating,
                expires_at: None,
                peer_data_confirmed: false,
            },
        );
        Ok(BeginSoftReset {
            key_id,
            sequence,
            created: true,
        })
    }

    fn matching_state(
        &self,
        key_id: u8,
        sequence: u64,
    ) -> Result<&SoftResetState, SoftResetStateError> {
        self.states
            .get(&key_id)
            .filter(|state| state.sequence == sequence)
            .ok_or(SoftResetStateError::StaleState)
    }

    fn matching_state_mut(
        &mut self,
        key_id: u8,
        sequence: u64,
    ) -> Result<&mut SoftResetState, SoftResetStateError> {
        self.states
            .get_mut(&key_id)
            .filter(|state| state.sequence == sequence)
            .ok_or(SoftResetStateError::StaleState)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SoftResetStateError {
    #[error("OpenVPN soft-reset coordinator is closed")]
    Closed,
    #[error("invalid OpenVPN soft-reset key-id: {0}")]
    InvalidKeyId(u8),
    #[error("stale or missing OpenVPN soft-reset state")]
    StaleState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_reset_is_deduplicated_and_cycles_key_ids() {
        let now = Instant::now();
        let mut state = SoftResetCoordinator::new(7, Duration::from_secs(60));
        let first = state.begin_local(now).unwrap();
        assert_eq!(first.key_id, 1);
        assert!(first.created);
        assert_eq!(
            state.begin_local(now).unwrap(),
            BeginSoftReset {
                created: false,
                ..first
            }
        );
    }

    #[test]
    fn newest_completed_reset_wins_simultaneous_race() {
        let now = Instant::now();
        let mut state = SoftResetCoordinator::new(0, Duration::from_secs(60));
        let local = state.begin_local(now).unwrap();
        let remote = state.begin_remote(2, now).unwrap();
        assert!(
            state
                .finish_success(remote.key_id, remote.sequence, now)
                .unwrap()
        );
        assert!(
            !state
                .finish_success(local.key_id, local.sequence, now)
                .unwrap()
        );
        assert_eq!(state.active_key_id(), 2);
        assert_eq!(state.state(1).unwrap().status, SoftResetStatus::LameDuck);
    }

    #[test]
    fn expires_lame_ducks_and_awaiting_data_states() {
        let now = Instant::now();
        let mut state = SoftResetCoordinator::with_limits(
            0,
            Duration::from_secs(5),
            Duration::from_secs(10),
            3,
        );
        let reset = state.begin_local(now).unwrap();
        state
            .set_awaiting_data(reset.key_id, reset.sequence, now)
            .unwrap();
        assert!(state.confirm_peer_data(reset.key_id));
        state.prune(now + Duration::from_secs(10));
        assert!(state.state(reset.key_id).is_none());
    }

    #[test]
    fn rejects_invalid_or_stale_states_and_closes_all() {
        let now = Instant::now();
        let mut state = SoftResetCoordinator::new(0, Duration::from_secs(60));
        assert_eq!(
            state.begin_remote(0, now),
            Err(SoftResetStateError::InvalidKeyId(0))
        );
        let reset = state.begin_remote(1, now).unwrap();
        assert_eq!(
            state.finish_failed(1, reset.sequence + 1),
            Err(SoftResetStateError::StaleState)
        );
        state.close();
        assert_eq!(state.begin_local(now), Err(SoftResetStateError::Closed));
    }
}
