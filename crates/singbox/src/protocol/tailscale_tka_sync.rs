//! Automatic tailnet-lock authority synchronization over TS2021 control RPCs.

use std::{io, sync::Arc};

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::{
    tailscale_control::TailscaleControlError,
    tailscale_control_supervisor::{
        TailscaleControlSession, TailscaleTkaSynchronizer,
    },
    tailscale_control_types::{
        TailscaleMapRequest, TailscaleTkaBootstrapRequest, TailscaleTkaInfo,
        TailscaleTkaSyncOfferRequest, TailscaleTkaSyncSendRequest,
    },
    tailscale_state::{TailscaleNodeStateStore, TailscaleTkaState},
    tailscale_tka_authority::{
        TailscaleTkaAuthority, TailscaleTkaAuthorityError,
        TailscaleTkaCompactionOptions, TailscaleTkaSyncOffer,
    },
};

pub struct TailscalePersistentTkaSynchronizer {
    store: TailscaleNodeStateStore,
    state: Arc<Mutex<TailscaleTkaState>>,
}

impl TailscalePersistentTkaSynchronizer {
    pub fn new(
        store: TailscaleNodeStateStore,
        state: TailscaleTkaState,
    ) -> Self {
        Self {
            store,
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn state(&self) -> Arc<Mutex<TailscaleTkaState>> {
        self.state.clone()
    }

    async fn persist(
        &self,
        state: &mut TailscaleTkaState,
        authority: Option<&TailscaleTkaAuthority>,
    ) -> Result<(), TailscaleControlError> {
        let mut candidate = state.clone();
        candidate.set_authority(authority).map_err(control_error)?;
        self.store
            .save_tka(&candidate)
            .await
            .map_err(control_error)?;
        *state = candidate;
        Ok(())
    }

    async fn bootstrap(
        &self,
        session: &mut dyn TailscaleControlSession,
        map: &TailscaleMapRequest,
        local_head: String,
    ) -> Result<
        super::tailscale_control_types::TailscaleTkaBootstrapResponse,
        TailscaleControlError,
    > {
        session
            .tka_bootstrap(&TailscaleTkaBootstrapRequest {
                version: map.version,
                node_key: map.node_key,
                head: local_head,
            })
            .await
    }

    async fn synchronize_enabled(
        &self,
        session: &mut dyn TailscaleControlSession,
        map: &TailscaleMapRequest,
        authority: &mut TailscaleTkaAuthority,
        force_send: bool,
    ) -> Result<(), TailscaleControlError> {
        let local_offer = authority.sync_offer().map_err(control_error)?;
        let (head, ancestors) = local_offer.to_wire();
        let response = session
            .tka_sync_offer(&TailscaleTkaSyncOfferRequest {
                version: map.version,
                node_key: map.node_key,
                head,
                ancestors,
            })
            .await?;
        let remote_offer = TailscaleTkaSyncOffer::from_wire(
            &response.head,
            &response.ancestors,
        )
        .map_err(control_error)?;
        if remote_offer.head == local_offer.head && !force_send {
            return Ok(());
        }
        // Compute our outbound delta before applying remote updates, matching
        // Tailscale's holdback-safe synchronization ordering.
        let to_send = authority
            .missing_aums(&remote_offer)
            .or_else(|error| {
                if matches!(error, TailscaleTkaAuthorityError::NoIntersection)
                    && !response.missing_aums.is_empty()
                {
                    Ok(Vec::new())
                } else {
                    Err(error)
                }
            })
            .map_err(control_error)?;
        if !response.missing_aums.is_empty() {
            authority
                .inform(&response.missing_aums)
                .map_err(control_error)?;
        }
        let response = session
            .tka_sync_send(&TailscaleTkaSyncSendRequest {
                version: map.version,
                node_key: map.node_key,
                head: authority.head().to_string(),
                missing_aums: to_send,
                interactive: false,
            })
            .await?;
        // A differing head is logged by upstream and retried on the next map;
        // it is not a reason to discard a cryptographically valid local state.
        let _remote_consensus = response.head;
        Ok(())
    }
}

#[async_trait]
impl TailscaleTkaSynchronizer for TailscalePersistentTkaSynchronizer {
    async fn synchronize(
        &self,
        session: &mut dyn TailscaleControlSession,
        control: &TailscaleTkaInfo,
        map: &mut TailscaleMapRequest,
    ) -> Result<bool, TailscaleControlError> {
        let previous_map_head = map.tka_head.clone();
        let mut persistent = self.state.lock().await;
        let mut authority = persistent.authority().map_err(control_error)?;

        if control.disabled {
            if let Some(local) = authority.as_ref() {
                let response = self
                    .bootstrap(session, map, local.head().to_string())
                    .await?;
                if response.disablement_secret.is_empty()
                    || !local
                        .valid_disablement(&response.disablement_secret)
                        .map_err(control_error)?
                {
                    return Err(control_error_message(
                        "control supplied an invalid TKA disablement secret",
                    ));
                }
                self.persist(&mut persistent, None).await?;
            }
            map.tka_head.clear();
            return Ok(previous_map_head != map.tka_head);
        }

        if control.head.is_empty() {
            return Err(control_error_message(
                "enabled TKAInfo is missing its head",
            ));
        }

        let just_enabled = authority.is_none();
        if authority.is_none() {
            let response = self.bootstrap(session, map, String::new()).await?;
            if response.genesis_aum.is_empty() {
                return Err(control_error_message(
                    "TKA bootstrap response is missing GenesisAUM",
                ));
            }
            authority = Some(
                TailscaleTkaAuthority::bootstrap(&response.genesis_aum)
                    .map_err(control_error)?,
            );
        }

        let authority = authority.as_mut().expect("authority was bootstrapped");
        let mut changed = false;
        if authority.head().to_string() != control.head || just_enabled {
            self.synchronize_enabled(session, map, authority, just_enabled)
                .await?;
            changed = true;
        }
        if authority
            .compact(TailscaleTkaCompactionOptions::default())
            .map_err(control_error)?
            > 0
        {
            changed = true;
        }
        if changed {
            self.persist(&mut persistent, Some(authority)).await?;
        }
        map.tka_head = authority.head().to_string();
        Ok(previous_map_head != map.tka_head)
    }
}

fn control_error(error: impl std::fmt::Display) -> TailscaleControlError {
    control_error_message(error.to_string())
}

fn control_error_message(message: impl Into<String>) -> TailscaleControlError {
    TailscaleControlError::Io(io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        tailscale_control_supervisor::TailscaleControlMapStream,
        tailscale_control_types::{
            TailscaleNodePublicKey, TailscaleRegisterRequest,
            TailscaleRegisterResponse, TailscaleTkaBootstrapResponse,
            TailscaleTkaSyncOfferResponse, TailscaleTkaSyncSendResponse,
        },
        tailscale_tka::TailscaleNetworkLockPrivateKey,
    };

    const GENESIS: &str = "a4010502f605a501f60281582000000000000000000000000000000000000000000000000000000000000000000381a40101020103582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80ca1646e616d65666f7261636c65040105021781a201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80258400a07edc0140dee672fe5c01abd2cf92e9ba69bb726468c4526adf2eb68302692573e2da04bb6b40157cf99e11dda2cedc851f7bc3e85c21c189a08fa7315f90b";
    const UPDATE: &str = "a50104025820ecae136341da94facb86e712681ceb0054edb504fcd5751d6a5c56c6f1604dab04582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b806021781a201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8025840f16e910e578e7f3a96b880fce1037211c3a9d07abc23e11884830bd19e012c630e0f09d88d7fb33d8f464d38506788a9770125acde4ad371df10363b421cf300";
    const GENESIS_HASH: &str =
        "5SXBGY2B3KKPVS4G44JGQHHLABKO3NIE7TKXKHLKLRLMN4LAJWVQ";
    const UPDATE_HASH: &str =
        "LTFXYENVU53J3LTTCFGSFJVCXOJBMB7XQWTGSJ6SYHHXUUIPAXTQ";

    struct SyncSession {
        bootstrap: Option<TailscaleTkaBootstrapResponse>,
        offer: Option<TailscaleTkaSyncOfferResponse>,
        sent: Vec<TailscaleTkaSyncSendRequest>,
    }

    #[async_trait]
    impl TailscaleControlSession for SyncSession {
        async fn register(
            &mut self,
            _request: &TailscaleRegisterRequest,
        ) -> Result<TailscaleRegisterResponse, TailscaleControlError> {
            unreachable!()
        }

        async fn start_map(
            &mut self,
            _request: &TailscaleMapRequest,
        ) -> Result<Box<dyn TailscaleControlMapStream>, TailscaleControlError>
        {
            unreachable!()
        }

        async fn tka_bootstrap(
            &mut self,
            _request: &TailscaleTkaBootstrapRequest,
        ) -> Result<TailscaleTkaBootstrapResponse, TailscaleControlError>
        {
            Ok(self.bootstrap.take().unwrap())
        }

        async fn tka_sync_offer(
            &mut self,
            _request: &TailscaleTkaSyncOfferRequest,
        ) -> Result<TailscaleTkaSyncOfferResponse, TailscaleControlError>
        {
            Ok(self.offer.take().unwrap())
        }

        async fn tka_sync_send(
            &mut self,
            request: &TailscaleTkaSyncSendRequest,
        ) -> Result<TailscaleTkaSyncSendResponse, TailscaleControlError>
        {
            self.sent.push(request.clone());
            Ok(TailscaleTkaSyncSendResponse {
                head: request.head.clone(),
            })
        }
    }

    fn map() -> TailscaleMapRequest {
        TailscaleMapRequest {
            version: 142,
            node_key: TailscaleNodePublicKey::from_bytes([9; 32]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn bootstrap_and_incremental_sync_are_verified_and_persisted() {
        let temporary = tempfile::tempdir().unwrap();
        let store = TailscaleNodeStateStore::from_directory(temporary.path());
        let state = TailscaleTkaState {
            network_lock_key: TailscaleNetworkLockPrivateKey::generate()
                .unwrap(),
            authority_aums: Vec::new(),
            authority_aum_created_unix: Default::default(),
        };
        let synchronizer =
            TailscalePersistentTkaSynchronizer::new(store.clone(), state);
        let mut session = SyncSession {
            bootstrap: Some(TailscaleTkaBootstrapResponse {
                genesis_aum: hex::decode(GENESIS).unwrap(),
                disablement_secret: Vec::new(),
            }),
            offer: Some(TailscaleTkaSyncOfferResponse {
                head: GENESIS_HASH.into(),
                ancestors: vec![GENESIS_HASH.into()],
                missing_aums: Vec::new(),
            }),
            sent: Vec::new(),
        };
        let mut map = map();
        assert!(
            synchronizer
                .synchronize(
                    &mut session,
                    &TailscaleTkaInfo {
                        head: GENESIS_HASH.into(),
                        disabled: false,
                    },
                    &mut map,
                )
                .await
                .unwrap()
        );
        assert_eq!(map.tka_head, GENESIS_HASH);
        assert_eq!(session.sent.len(), 1);
        assert_eq!(
            store
                .load_or_create_tka()
                .await
                .unwrap()
                .authority()
                .unwrap()
                .unwrap()
                .head()
                .to_string(),
            GENESIS_HASH
        );

        session.offer = Some(TailscaleTkaSyncOfferResponse {
            head: UPDATE_HASH.into(),
            ancestors: vec![GENESIS_HASH.into()],
            missing_aums: vec![hex::decode(UPDATE).unwrap()],
        });
        assert!(
            synchronizer
                .synchronize(
                    &mut session,
                    &TailscaleTkaInfo {
                        head: UPDATE_HASH.into(),
                        disabled: false,
                    },
                    &mut map,
                )
                .await
                .unwrap()
        );
        assert_eq!(map.tka_head, UPDATE_HASH);
        assert_eq!(session.sent.last().unwrap().head, UPDATE_HASH);
        let persisted = store.load_or_create_tka().await.unwrap();
        assert_eq!(
            persisted.authority_aum_created_unix.len(),
            persisted.authority_aums.len()
        );
        let authority = persisted.authority().unwrap().unwrap();
        assert_eq!(authority.head().to_string(), UPDATE_HASH);
        assert_eq!(authority.state().keys[0].votes, 2);

        let mut legacy = serde_json::to_value(&persisted).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("authority_aum_created_unix");
        tokio::fs::write(
            store.tka_path(),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .await
        .unwrap();
        let migrated = store.load_or_create_tka().await.unwrap();
        assert_eq!(
            migrated.authority_aum_created_unix.len(),
            migrated.authority_aums.len()
        );
        let migrated_on_disk: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(store.tka_path()).await.unwrap(),
        )
        .unwrap();
        assert!(migrated_on_disk.get("authority_aum_created_unix").is_some());
    }
}
