//! Tailnet-lock Authority Update Message (AUM) verification and sync.
//!
//! This is the reusable-library counterpart of Tailscale's `tka.Authority`.
//! AUMs received from control are never trusted as opaque bytes: canonical
//! CBOR is decoded, signatures are verified against the parent state, and the
//! deterministic fork rules are applied before the active head changes.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2s256, Digest as _};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder, data::Type};
use thiserror::Error;

const MAX_DISABLEMENT_VALUES: usize = 32;
const MAX_KEYS: usize = 512;
const MAX_META_BYTES: usize = 512;
const MAX_SYNC_ITERATIONS: usize = 2_000;
const MAX_SYNC_HEAD_INTERSECTION_ITERATIONS: usize = 400;
const ANCESTORS_SKIP_START: usize = 4;
const ANCESTORS_SKIP_SHIFT: usize = 2;
const RETAIN_ACTIVE: u8 = 1 << 0;
const RETAIN_YOUNG: u8 = 1 << 1;
const RETAIN_LEAF: u8 = 1 << 2;
const RETAIN_ANCESTOR: u8 = 1 << 3;
const RETAIN_CANDIDATE: u8 = 1 << 4;
const RETAIN_MASK: u8 =
    RETAIN_ACTIVE | RETAIN_YOUNG | RETAIN_LEAF | RETAIN_ANCESTOR;

pub const TAILSCALE_TKA_COMPACTION_MIN_CHAIN: usize = 24;
pub const TAILSCALE_TKA_COMPACTION_MIN_AGE: Duration =
    Duration::from_secs(14 * 24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailscaleTkaCompactionOptions {
    pub min_chain: usize,
    pub min_age: Duration,
}

impl Default for TailscaleTkaCompactionOptions {
    fn default() -> Self {
        Self {
            min_chain: TAILSCALE_TKA_COMPACTION_MIN_CHAIN,
            min_age: TAILSCALE_TKA_COMPACTION_MIN_AGE,
        }
    }
}

#[derive(Debug, Error)]
pub enum TailscaleTkaAuthorityError {
    #[error("invalid Tailscale AUM hash")]
    InvalidHash,
    #[error("Tailscale AUM CBOR failed: {0}")]
    Cbor(String),
    #[error("Tailscale AUM is not canonical CBOR")]
    NonCanonicalCbor,
    #[error("invalid Tailscale AUM: {0}")]
    InvalidAum(String),
    #[error("Tailscale AUM signature is invalid")]
    InvalidSignature,
    #[error("Tailscale AUM parent is unknown")]
    UnknownParent,
    #[error("Tailscale AUM sync offer has no intersection")]
    NoIntersection,
    #[error("Tailscale AUM iteration limit exceeded")]
    IterationLimit,
    #[error("invalid Tailscale AUM compaction options")]
    InvalidCompactionOptions,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TailscaleAumHash([u8; 32]);

impl TailscaleAumHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TailscaleAumHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for TailscaleAumHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&BASE32_NOPAD.encode(&self.0))
    }
}

impl FromStr for TailscaleAumHash {
    type Err = TailscaleTkaAuthorityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let decoded = BASE32_NOPAD
            .decode(value.as_bytes())
            .map_err(|_| TailscaleTkaAuthorityError::InvalidHash)?;
        let bytes = decoded
            .try_into()
            .map_err(|_| TailscaleTkaAuthorityError::InvalidHash)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleTkaKey {
    pub kind: u8,
    pub votes: u64,
    pub public: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleAumSignature {
    pub key_id: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleTkaAuthorityState {
    pub last_aum_hash: Option<TailscaleAumHash>,
    pub disablement_values: Vec<Vec<u8>>,
    pub keys: Vec<TailscaleTkaKey>,
    pub state_id_1: u64,
    pub state_id_2: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleAum {
    pub kind: u8,
    pub previous: Option<TailscaleAumHash>,
    pub key: Option<TailscaleTkaKey>,
    pub key_id: Option<Vec<u8>>,
    pub state: Option<TailscaleTkaAuthorityState>,
    pub votes: Option<u64>,
    pub metadata: Option<BTreeMap<String, String>>,
    pub signatures: Vec<TailscaleAumSignature>,
}

impl TailscaleAum {
    pub const KIND_ADD_KEY: u8 = 1;
    pub const KIND_REMOVE_KEY: u8 = 2;
    pub const KIND_NO_OP: u8 = 3;
    pub const KIND_UPDATE_KEY: u8 = 4;
    pub const KIND_CHECKPOINT: u8 = 5;

    pub fn decode(bytes: &[u8]) -> Result<Self, TailscaleTkaAuthorityError> {
        let mut decoder = Decoder::new(bytes);
        let value = decode_aum(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(TailscaleTkaAuthorityError::Cbor(
                "trailing bytes".into(),
            ));
        }
        value.static_validate()?;
        if value.encode()? != bytes {
            return Err(TailscaleTkaAuthorityError::NonCanonicalCbor);
        }
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, TailscaleTkaAuthorityError> {
        let mut bytes = Vec::with_capacity(256);
        let mut encoder = Encoder::new(&mut bytes);
        encode_aum(&mut encoder, self).map_err(cbor_encode_error)?;
        Ok(bytes)
    }

    pub fn hash(&self) -> Result<TailscaleAumHash, TailscaleTkaAuthorityError> {
        Ok(TailscaleAumHash(Blake2s256::digest(self.encode()?).into()))
    }

    pub fn signature_hash(
        &self,
    ) -> Result<[u8; 32], TailscaleTkaAuthorityError> {
        let mut unsigned = self.clone();
        unsigned.signatures.clear();
        Ok(Blake2s256::digest(unsigned.encode()?).into())
    }

    fn static_validate(&self) -> Result<(), TailscaleTkaAuthorityError> {
        if let Some(key) = &self.key {
            validate_key(key)?;
        }
        for signature in &self.signatures {
            if signature.key_id.len() != 32 || signature.signature.len() != 64 {
                return invalid("signature has malformed key ID or body");
            }
        }
        if let Some(state) = &self.state {
            validate_checkpoint_state(state)?;
        }
        match self.kind {
            Self::KIND_ADD_KEY => {
                if self.key.is_none()
                    || self.key_id.is_some()
                    || self.state.is_some()
                    || self.votes.is_some()
                    || self.metadata.is_some()
                {
                    return invalid("AddKey may only specify Key");
                }
            }
            Self::KIND_REMOVE_KEY => {
                if self.key_id.as_ref().is_none_or(Vec::is_empty)
                    || self.key.is_some()
                    || self.state.is_some()
                    || self.votes.is_some()
                    || self.metadata.is_some()
                {
                    return invalid("RemoveKey may only specify KeyID");
                }
            }
            Self::KIND_UPDATE_KEY => {
                if self.key_id.as_ref().is_none_or(Vec::is_empty)
                    || (self.votes.is_none() && self.metadata.is_none())
                    || self.key.is_some()
                    || self.state.is_some()
                {
                    return invalid("UpdateKey requires KeyID and an update");
                }
            }
            Self::KIND_CHECKPOINT
                if self.state.is_none()
                    || self.key.is_some()
                    || self.key_id.is_some()
                    || self.votes.is_some()
                    || self.metadata.is_some() =>
            {
                return invalid("Checkpoint may only specify State");
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleTkaSyncOffer {
    pub head: TailscaleAumHash,
    pub ancestors: Vec<TailscaleAumHash>,
}

impl TailscaleTkaSyncOffer {
    pub fn from_wire(
        head: &str,
        ancestors: &[String],
    ) -> Result<Self, TailscaleTkaAuthorityError> {
        Ok(Self {
            head: head.parse()?,
            ancestors: ancestors
                .iter()
                .map(|value| value.parse())
                .collect::<Result<_, _>>()?,
        })
    }

    pub fn to_wire(&self) -> (String, Vec<String>) {
        (
            self.head.to_string(),
            self.ancestors.iter().map(ToString::to_string).collect(),
        )
    }
}

/// An in-memory verified authority. Persistence is deliberately kept outside
/// this type so the endpoint can atomically commit the complete authority and
/// node identity in one state-store transaction.
#[derive(Debug, Clone)]
pub struct TailscaleTkaAuthority {
    aums: BTreeMap<TailscaleAumHash, TailscaleAum>,
    commit_times: BTreeMap<TailscaleAumHash, SystemTime>,
    oldest: TailscaleAumHash,
    head: TailscaleAumHash,
    state: TailscaleTkaAuthorityState,
}

impl TailscaleTkaAuthority {
    pub fn bootstrap(bytes: &[u8]) -> Result<Self, TailscaleTkaAuthorityError> {
        let aum = TailscaleAum::decode(bytes)?;
        if aum.kind != TailscaleAum::KIND_CHECKPOINT || aum.previous.is_some() {
            return invalid("bootstrap must be a genesis Checkpoint");
        }
        let checkpoint = aum.state.clone().ok_or_else(|| {
            TailscaleTkaAuthorityError::InvalidAum(
                "checkpoint state missing".into(),
            )
        })?;
        verify_aum_signatures(&aum, &checkpoint)?;
        let hash = aum.hash()?;
        let mut state = checkpoint;
        state.last_aum_hash = Some(hash);
        let mut aums = BTreeMap::new();
        aums.insert(hash, aum);
        let commit_times = BTreeMap::from([(hash, SystemTime::now())]);
        Ok(Self {
            aums,
            commit_times,
            oldest: hash,
            head: hash,
            state,
        })
    }

    pub const fn head(&self) -> TailscaleAumHash {
        self.head
    }

    pub fn state(&self) -> &TailscaleTkaAuthorityState {
        &self.state
    }

    pub fn from_archive(
        encoded: &[Vec<u8>],
    ) -> Result<Self, TailscaleTkaAuthorityError> {
        Self::from_archive_with_commit_times(encoded, &BTreeMap::new())
    }

    pub fn from_archive_with_commit_times(
        encoded: &[Vec<u8>],
        commit_times_unix: &BTreeMap<String, i64>,
    ) -> Result<Self, TailscaleTkaAuthorityError> {
        let decoded = encoded
            .iter()
            .map(|bytes| TailscaleAum::decode(bytes).map(|aum| (bytes, aum)))
            .collect::<Result<Vec<_>, _>>()?;
        let hashes = decoded
            .iter()
            .map(|(_, aum)| aum.hash())
            .collect::<Result<BTreeSet<_>, _>>()?;
        let roots = decoded
            .iter()
            .filter(|(_, aum)| {
                aum.kind == TailscaleAum::KIND_CHECKPOINT
                    && aum
                        .previous
                        .is_none_or(|parent| !hashes.contains(&parent))
            })
            .collect::<Vec<_>>();
        if roots.len() != 1 {
            return invalid(
                "authority archive must contain one root checkpoint",
            );
        }
        let root = roots[0].1.clone();
        let root_hash = root.hash()?;
        let mut root_state = root.state.clone().ok_or_else(|| {
            TailscaleTkaAuthorityError::InvalidAum(
                "checkpoint state missing".into(),
            )
        })?;
        if root.previous.is_none() {
            verify_aum_signatures(&root, &root_state)?;
        }
        root_state.last_aum_hash = Some(root_hash);
        let now = SystemTime::now();
        let mut authority = Self {
            aums: BTreeMap::from([(root_hash, root)]),
            commit_times: BTreeMap::from([(
                root_hash,
                archive_commit_time(root_hash, commit_times_unix, now),
            )]),
            oldest: root_hash,
            head: root_hash,
            state: root_state,
        };
        let mut pending = decoded
            .into_iter()
            .filter(|(_, aum)| aum.hash().ok() != Some(root_hash))
            .map(|(bytes, aum)| aum.hash().map(|hash| (bytes.clone(), hash)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut pending = pending
            .drain(..)
            .map(|(bytes, hash)| {
                (bytes, archive_commit_time(hash, commit_times_unix, now))
            })
            .collect::<Vec<_>>();
        for _ in 0..MAX_SYNC_ITERATIONS {
            if pending.is_empty() {
                return Ok(authority);
            }
            let before = pending.len();
            let mut deferred = Vec::new();
            for (bytes, committed_at) in pending {
                match authority
                    .inform_at(std::slice::from_ref(&bytes), committed_at)
                {
                    Ok(()) => {}
                    Err(TailscaleTkaAuthorityError::UnknownParent) => {
                        deferred.push((bytes, committed_at))
                    }
                    Err(error) => return Err(error),
                }
            }
            if deferred.len() == before {
                return Err(TailscaleTkaAuthorityError::UnknownParent);
            }
            pending = deferred;
        }
        Err(TailscaleTkaAuthorityError::IterationLimit)
    }

    pub fn archive(&self) -> Result<Vec<Vec<u8>>, TailscaleTkaAuthorityError> {
        self.aums.values().map(TailscaleAum::encode).collect()
    }

    pub fn commit_times_unix(&self) -> BTreeMap<String, i64> {
        self.commit_times
            .iter()
            .map(|(hash, committed_at)| {
                (
                    hash.to_string(),
                    committed_at
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                )
            })
            .collect()
    }

    /// Verify the upstream Argon2id disablement-secret construction.
    pub fn valid_disablement(
        &self,
        secret: &[u8],
    ) -> Result<bool, TailscaleTkaAuthorityError> {
        let params = Params::new(16 * 1024, 4, 4, Some(32))
            .map_err(|error| invalid_error(error.to_string()))?;
        let mut derived = [0_u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(
                secret,
                b"tailscale network-lock disablement salt",
                &mut derived,
            )
            .map_err(|error| invalid_error(error.to_string()))?;
        Ok(self
            .state
            .disablement_values
            .iter()
            .any(|candidate| constant_time_equal(candidate, &derived)))
    }

    pub fn sync_offer(
        &self,
    ) -> Result<TailscaleTkaSyncOffer, TailscaleTkaAuthorityError> {
        let chain = self.active_chain()?;
        let mut ancestors = Vec::with_capacity(6);
        let mut skip = ANCESTORS_SKIP_START;
        for (index, hash) in chain
            .iter()
            .rev()
            .enumerate()
            .take(MAX_SYNC_HEAD_INTERSECTION_ITERATIONS)
        {
            if index > 0 && index % skip == 0 && *hash != self.oldest {
                ancestors.push(*hash);
                skip <<= ANCESTORS_SKIP_SHIFT;
            }
        }
        ancestors.push(self.oldest);
        Ok(TailscaleTkaSyncOffer {
            head: self.head,
            ancestors,
        })
    }

    pub fn missing_aums(
        &self,
        remote: &TailscaleTkaSyncOffer,
    ) -> Result<Vec<Vec<u8>>, TailscaleTkaAuthorityError> {
        if remote.head == self.head {
            return Ok(Vec::new());
        }
        let chain = self.active_chain()?;
        let intersection = chain
            .iter()
            .position(|hash| *hash == remote.head)
            .or_else(|| {
                remote.ancestors.iter().find_map(|ancestor| {
                    chain.iter().position(|hash| hash == ancestor)
                })
            })
            .ok_or(TailscaleTkaAuthorityError::NoIntersection)?;
        chain[intersection + 1..]
            .iter()
            .map(|hash| self.aums[hash].encode())
            .collect()
    }

    /// Verify and atomically apply a batch of AUMs ordered oldest to newest.
    pub fn inform(
        &mut self,
        encoded: &[Vec<u8>],
    ) -> Result<(), TailscaleTkaAuthorityError> {
        self.inform_at(encoded, SystemTime::now())
    }

    fn inform_at(
        &mut self,
        encoded: &[Vec<u8>],
        committed_at: SystemTime,
    ) -> Result<(), TailscaleTkaAuthorityError> {
        let mut candidate = self.clone();
        for bytes in encoded {
            let aum = TailscaleAum::decode(bytes)?;
            let hash = aum.hash()?;
            if candidate.aums.contains_key(&hash) {
                continue;
            }
            let parent = aum
                .previous
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
            if !candidate.aums.contains_key(&parent) {
                return Err(TailscaleTkaAuthorityError::UnknownParent);
            }
            let parent_state = candidate.state_at(parent)?;
            verify_aum_signatures(&aum, &parent_state)?;
            apply_aum(&parent_state, &aum)?;
            candidate.aums.insert(hash, aum);
            candidate.commit_times.insert(hash, committed_at);
        }
        let (head, state) = candidate.compute_active_head()?;
        candidate.head = head;
        candidate.state = state;
        *self = candidate;
        Ok(())
    }

    /// Delete historical AUMs using Tailscale's default retention policy.
    pub fn compact(
        &mut self,
        options: TailscaleTkaCompactionOptions,
    ) -> Result<usize, TailscaleTkaAuthorityError> {
        self.compact_at(options, SystemTime::now())
    }

    /// Clock-injected compaction entry point for deterministic hosts/tests.
    pub fn compact_at(
        &mut self,
        options: TailscaleTkaCompactionOptions,
        now: SystemTime,
    ) -> Result<usize, TailscaleTkaAuthorityError> {
        if options.min_chain == 0 || options.min_age.is_zero() {
            return Err(TailscaleTkaAuthorityError::InvalidCompactionOptions);
        }
        let cutoff = now.checked_sub(options.min_age).unwrap_or(UNIX_EPOCH);
        let mut verdict = self
            .aums
            .keys()
            .copied()
            .map(|hash| (hash, 0_u8))
            .collect::<BTreeMap<_, _>>();
        for (hash, committed_at) in &self.commit_times {
            if *committed_at > cutoff
                && let Some(state) = verdict.get_mut(hash)
            {
                *state |= RETAIN_YOUNG;
            }
        }

        let mut cursor = self.head;
        let mut candidate_ancestor = None;
        for _ in 0..options.min_chain {
            *verdict
                .get_mut(&cursor)
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)? |=
                RETAIN_ACTIVE;
            let Some(parent) = self.logical_parent(cursor)? else {
                candidate_ancestor = Some(cursor);
                break;
            };
            cursor = parent;
        }

        let mut candidate_ancestor = match candidate_ancestor {
            Some(candidate) => candidate,
            None => loop {
                let aum = self
                    .aums
                    .get(&cursor)
                    .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
                let state = verdict
                    .get_mut(&cursor)
                    .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
                *state |= RETAIN_ACTIVE;
                let parent = self.logical_parent(cursor)?;
                if aum.kind == TailscaleAum::KIND_CHECKPOINT
                    && (*state & RETAIN_YOUNG == 0 || parent.is_none())
                {
                    break cursor;
                }
                cursor = parent.ok_or_else(|| {
                    invalid_error("oldest retained AUM is not a checkpoint")
                })?;
            },
        };

        while let Some(parent) = self.logical_parent(cursor)? {
            let Some(state) = verdict.get_mut(&parent) else {
                break;
            };
            *state |= RETAIN_CANDIDATE;
            cursor = parent;
        }

        self.mark_compaction_descendants(&mut verdict)?;
        candidate_ancestor = self
            .mark_compaction_intersections(&mut verdict, candidate_ancestor)?;
        self.finish_compaction(candidate_ancestor, verdict)
    }

    fn logical_parent(
        &self,
        hash: TailscaleAumHash,
    ) -> Result<Option<TailscaleAumHash>, TailscaleTkaAuthorityError> {
        if hash == self.oldest {
            return Ok(None);
        }
        self.aums
            .get(&hash)
            .ok_or(TailscaleTkaAuthorityError::UnknownParent)
            .map(|aum| aum.previous)
    }

    fn mark_compaction_descendants(
        &self,
        verdict: &mut BTreeMap<TailscaleAumHash, u8>,
    ) -> Result<(), TailscaleTkaAuthorityError> {
        let mut queue = verdict
            .iter()
            .filter_map(|(hash, state)| {
                (*state & RETAIN_MASK != 0).then_some(*hash)
            })
            .collect::<VecDeque<_>>();
        let mut iterations = 0_usize;
        while let Some(hash) = queue.pop_front() {
            let state = verdict
                .get_mut(&hash)
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
            if *state & RETAIN_LEAF != 0 {
                continue;
            }
            iterations += 1;
            if iterations > MAX_SYNC_ITERATIONS {
                return Err(TailscaleTkaAuthorityError::IterationLimit);
            }
            *state |= RETAIN_LEAF;
            queue.extend(self.aums.iter().filter_map(|(child, aum)| {
                (aum.previous == Some(hash)).then_some(*child)
            }));
        }
        Ok(())
    }

    fn mark_compaction_intersections(
        &self,
        verdict: &mut BTreeMap<TailscaleAumHash, u8>,
        mut candidate: TailscaleAumHash,
    ) -> Result<TailscaleAumHash, TailscaleTkaAuthorityError> {
        let mut queue = verdict
            .iter()
            .filter_map(|(hash, state)| {
                (*hash != candidate && *state & RETAIN_MASK != 0)
                    .then_some(*hash)
            })
            .collect::<VecDeque<_>>();
        let mut adjusted = false;
        let mut iterations = 0_usize;
        while let Some(hash) = queue.pop_front() {
            let state = verdict
                .get_mut(&hash)
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
            if *state & RETAIN_ANCESTOR != 0 {
                continue;
            }
            iterations += 1;
            if iterations > MAX_SYNC_ITERATIONS {
                return Err(TailscaleTkaAuthorityError::IterationLimit);
            }
            *state |= RETAIN_ANCESTOR;
            let parent = self.logical_parent(hash)?.ok_or_else(|| {
                invalid_error(
                    "retained AUM does not intersect compaction ancestor",
                )
            })?;
            let parent_state = *verdict
                .get(&parent)
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
            if parent_state & RETAIN_MASK != 0 {
                continue;
            }
            if parent_state & RETAIN_CANDIDATE != 0 {
                candidate = parent;
                adjusted = true;
                *verdict.get_mut(&parent).expect("known parent") |=
                    RETAIN_ANCESTOR;
                let mut next = parent;
                loop {
                    let child = self.aums.iter().find_map(|(hash, aum)| {
                        let state = verdict.get(hash).copied().unwrap_or(0);
                        (aum.previous == Some(next)
                            && state & RETAIN_CANDIDATE != 0
                            && state & RETAIN_ACTIVE == 0)
                            .then_some(*hash)
                    });
                    let Some(child) = child else { break };
                    *verdict.get_mut(&child).expect("known child") |=
                        RETAIN_ANCESTOR;
                    next = child;
                }
            }
            queue.push_back(parent);
        }

        if adjusted {
            let mut cursor = candidate;
            loop {
                let aum = self
                    .aums
                    .get(&cursor)
                    .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
                *verdict.get_mut(&cursor).expect("known AUM") |= RETAIN_ACTIVE;
                if aum.kind == TailscaleAum::KIND_CHECKPOINT {
                    candidate = cursor;
                    break;
                }
                cursor = self.logical_parent(cursor)?.ok_or_else(|| {
                    invalid_error(
                        "no checkpoint before compaction intersection",
                    )
                })?;
            }
        }
        Ok(candidate)
    }

    fn finish_compaction(
        &mut self,
        oldest: TailscaleAumHash,
        verdict: BTreeMap<TailscaleAumHash, u8>,
    ) -> Result<usize, TailscaleTkaAuthorityError> {
        let to_delete = verdict
            .into_iter()
            .filter_map(|(hash, state)| {
                (state & RETAIN_MASK == 0).then_some(hash)
            })
            .collect::<Vec<_>>();
        if !self.aums.contains_key(&oldest) {
            return Err(TailscaleTkaAuthorityError::UnknownParent);
        }
        for hash in &to_delete {
            self.aums.remove(hash);
            self.commit_times.remove(hash);
        }
        self.oldest = oldest;
        Ok(to_delete.len())
    }

    fn active_chain(
        &self,
    ) -> Result<Vec<TailscaleAumHash>, TailscaleTkaAuthorityError> {
        let mut reverse = Vec::new();
        let mut cursor = self.head;
        for _ in 0..MAX_SYNC_ITERATIONS {
            reverse.push(cursor);
            if cursor == self.oldest {
                reverse.reverse();
                return Ok(reverse);
            }
            cursor = self.aums[&cursor]
                .previous
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
        }
        Err(TailscaleTkaAuthorityError::IterationLimit)
    }

    fn state_at(
        &self,
        hash: TailscaleAumHash,
    ) -> Result<TailscaleTkaAuthorityState, TailscaleTkaAuthorityError> {
        let mut path = Vec::new();
        let mut cursor = hash;
        for _ in 0..MAX_SYNC_ITERATIONS {
            let aum = self
                .aums
                .get(&cursor)
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
            path.push(aum);
            if aum.kind == TailscaleAum::KIND_CHECKPOINT {
                let mut state = aum.state.clone().ok_or_else(|| {
                    TailscaleTkaAuthorityError::InvalidAum(
                        "checkpoint state missing".into(),
                    )
                })?;
                state.last_aum_hash = Some(aum.hash()?);
                for update in path[..path.len() - 1].iter().rev() {
                    state = apply_aum(&state, update)?;
                }
                return Ok(state);
            }
            cursor = aum
                .previous
                .ok_or(TailscaleTkaAuthorityError::UnknownParent)?;
        }
        Err(TailscaleTkaAuthorityError::IterationLimit)
    }

    fn compute_active_head(
        &self,
    ) -> Result<
        (TailscaleAumHash, TailscaleTkaAuthorityState),
        TailscaleTkaAuthorityError,
    > {
        let mut cursor = self.oldest;
        let mut state = self.state_at(cursor)?;
        for _ in 0..MAX_SYNC_ITERATIONS {
            let mut children = self
                .aums
                .iter()
                .filter(|(_, aum)| aum.previous == Some(cursor))
                .collect::<Vec<_>>();
            if children.is_empty() {
                return Ok((cursor, state));
            }
            children.sort_by(|(left_hash, left), (right_hash, right)| {
                compare_fork_candidates(
                    &state, left_hash, left, right_hash, right,
                )
            });
            let (next_hash, next) = children[0];
            state = apply_aum(&state, next)?;
            cursor = *next_hash;
        }
        Err(TailscaleTkaAuthorityError::IterationLimit)
    }
}

fn compare_fork_candidates(
    state: &TailscaleTkaAuthorityState,
    left_hash: &TailscaleAumHash,
    left: &TailscaleAum,
    right_hash: &TailscaleAumHash,
    right: &TailscaleAum,
) -> Ordering {
    let left_weight = signature_weight(state, left);
    let right_weight = signature_weight(state, right);
    right_weight
        .cmp(&left_weight)
        .then_with(|| {
            (right.kind == TailscaleAum::KIND_REMOVE_KEY)
                .cmp(&(left.kind == TailscaleAum::KIND_REMOVE_KEY))
        })
        .then_with(|| left_hash.cmp(right_hash))
}

fn archive_commit_time(
    hash: TailscaleAumHash,
    commit_times_unix: &BTreeMap<String, i64>,
    fallback: SystemTime,
) -> SystemTime {
    commit_times_unix
        .get(&hash.to_string())
        .and_then(|seconds| u64::try_from(*seconds).ok())
        .and_then(|seconds| {
            UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
        })
        .unwrap_or(fallback)
}

fn signature_weight(
    state: &TailscaleTkaAuthorityState,
    aum: &TailscaleAum,
) -> u64 {
    let mut seen = BTreeMap::<Vec<u8>, ()>::new();
    aum.signatures
        .iter()
        .filter_map(|signature| {
            if seen.insert(signature.key_id.clone(), ()).is_some() {
                return None;
            }
            state
                .keys
                .iter()
                .find(|key| key.public == signature.key_id)
                .map(|key| key.votes)
        })
        .sum()
}

fn verify_aum_signatures(
    aum: &TailscaleAum,
    state: &TailscaleTkaAuthorityState,
) -> Result<(), TailscaleTkaAuthorityError> {
    if aum.signatures.is_empty() {
        return invalid("unsigned AUM");
    }
    let digest = aum.signature_hash()?;
    for signature in &aum.signatures {
        let key = state
            .keys
            .iter()
            .find(|key| key.public == signature.key_id)
            .ok_or(TailscaleTkaAuthorityError::InvalidSignature)?;
        let verifying = VerifyingKey::from_bytes(
            key.public
                .as_slice()
                .try_into()
                .map_err(|_| TailscaleTkaAuthorityError::InvalidSignature)?,
        )
        .map_err(|_| TailscaleTkaAuthorityError::InvalidSignature)?;
        let signature = Signature::from_slice(&signature.signature)
            .map_err(|_| TailscaleTkaAuthorityError::InvalidSignature)?;
        verifying
            .verify_strict(&digest, &signature)
            .map_err(|_| TailscaleTkaAuthorityError::InvalidSignature)?;
    }
    if aum.kind == TailscaleAum::KIND_REMOVE_KEY
        && state.keys.len() == 1
        && aum.key_id.as_deref() == Some(state.keys[0].public.as_slice())
    {
        return invalid("cannot remove the final key");
    }
    Ok(())
}

fn apply_aum(
    state: &TailscaleTkaAuthorityState,
    aum: &TailscaleAum,
) -> Result<TailscaleTkaAuthorityState, TailscaleTkaAuthorityError> {
    if state.last_aum_hash != aum.previous {
        return invalid("parent AUM hash mismatch");
    }
    let mut next = state.clone();
    match aum.kind {
        TailscaleAum::KIND_CHECKPOINT => {
            let checkpoint = aum.state.clone().ok_or_else(|| {
                TailscaleTkaAuthorityError::InvalidAum(
                    "checkpoint state missing".into(),
                )
            })?;
            if checkpoint.state_id_1 != state.state_id_1
                || checkpoint.state_id_2 != state.state_id_2
            {
                return invalid("checkpoint has incorrect state ID");
            }
            next = checkpoint;
        }
        TailscaleAum::KIND_ADD_KEY => {
            let key = aum.key.clone().ok_or_else(|| {
                TailscaleTkaAuthorityError::InvalidAum("key missing".into())
            })?;
            if next
                .keys
                .iter()
                .any(|existing| existing.public == key.public)
            {
                return invalid("key already exists");
            }
            next.keys.push(key);
        }
        TailscaleAum::KIND_REMOVE_KEY => {
            let id = aum.key_id.as_deref().unwrap_or_default();
            let index = next
                .keys
                .iter()
                .position(|key| key.public == id)
                .ok_or_else(|| {
                    TailscaleTkaAuthorityError::InvalidAum(
                        "key not found".into(),
                    )
                })?;
            next.keys.remove(index);
        }
        TailscaleAum::KIND_UPDATE_KEY => {
            let id = aum.key_id.as_deref().unwrap_or_default();
            let key = next
                .keys
                .iter_mut()
                .find(|key| key.public == id)
                .ok_or_else(|| {
                    TailscaleTkaAuthorityError::InvalidAum(
                        "key not found".into(),
                    )
                })?;
            if let Some(votes) = aum.votes {
                key.votes = votes;
            }
            if let Some(metadata) = &aum.metadata {
                key.metadata.clone_from(metadata);
            }
            validate_key(key)?;
        }
        _ => {}
    }
    next.last_aum_hash = Some(aum.hash()?);
    Ok(next)
}

fn validate_key(
    key: &TailscaleTkaKey,
) -> Result<(), TailscaleTkaAuthorityError> {
    if key.kind != 1 || key.public.len() != 32 {
        return invalid("unrecognized or malformed key");
    }
    if key.votes == 0 || key.votes > 4096 {
        return invalid("key votes out of range");
    }
    if key
        .metadata
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum::<usize>()
        > MAX_META_BYTES
    {
        return invalid("key metadata too large");
    }
    Ok(())
}

fn validate_checkpoint_state(
    state: &TailscaleTkaAuthorityState,
) -> Result<(), TailscaleTkaAuthorityError> {
    if state.last_aum_hash.is_some() {
        return invalid("checkpoint cannot specify a parent");
    }
    if state.disablement_values.is_empty()
        || state.disablement_values.len() > MAX_DISABLEMENT_VALUES
        || state
            .disablement_values
            .iter()
            .any(|value| value.len() != 32)
    {
        return invalid("invalid checkpoint disablement values");
    }
    if state.keys.is_empty() || state.keys.len() > MAX_KEYS {
        return invalid("invalid checkpoint key count");
    }
    for key in &state.keys {
        validate_key(key)?;
    }
    for (index, key) in state.keys.iter().enumerate() {
        if state.keys[index + 1..]
            .iter()
            .any(|other| other.public == key.public)
        {
            return invalid("duplicate checkpoint key");
        }
    }
    Ok(())
}

fn invalid<T>(
    message: impl Into<String>,
) -> Result<T, TailscaleTkaAuthorityError> {
    Err(TailscaleTkaAuthorityError::InvalidAum(message.into()))
}

fn invalid_error(message: impl Into<String>) -> TailscaleTkaAuthorityError {
    TailscaleTkaAuthorityError::InvalidAum(message.into())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn cbor_decode_error(
    error: minicbor::decode::Error,
) -> TailscaleTkaAuthorityError {
    TailscaleTkaAuthorityError::Cbor(error.to_string())
}

fn cbor_encode_error<E: fmt::Display>(
    error: minicbor::encode::Error<E>,
) -> TailscaleTkaAuthorityError {
    TailscaleTkaAuthorityError::Cbor(error.to_string())
}

fn definite_map(
    decoder: &mut Decoder<'_>,
) -> Result<u64, TailscaleTkaAuthorityError> {
    decoder.map().map_err(cbor_decode_error)?.ok_or_else(|| {
        TailscaleTkaAuthorityError::Cbor("indefinite map".into())
    })
}

fn definite_array(
    decoder: &mut Decoder<'_>,
) -> Result<u64, TailscaleTkaAuthorityError> {
    decoder.array().map_err(cbor_decode_error)?.ok_or_else(|| {
        TailscaleTkaAuthorityError::Cbor("indefinite array".into())
    })
}

fn decode_aum(
    decoder: &mut Decoder<'_>,
) -> Result<TailscaleAum, TailscaleTkaAuthorityError> {
    let length = definite_map(decoder)?;
    let mut out = TailscaleAum {
        kind: 0,
        previous: None,
        key: None,
        key_id: None,
        state: None,
        votes: None,
        metadata: None,
        signatures: Vec::new(),
    };
    for _ in 0..length {
        match decoder.u8().map_err(cbor_decode_error)? {
            1 => out.kind = decoder.u8().map_err(cbor_decode_error)?,
            2 => out.previous = decode_optional_hash(decoder)?,
            3 => out.key = Some(decode_key(decoder)?),
            4 => {
                out.key_id =
                    Some(decoder.bytes().map_err(cbor_decode_error)?.to_vec())
            }
            5 => out.state = Some(decode_state(decoder)?),
            6 => out.votes = Some(decoder.u64().map_err(cbor_decode_error)?),
            7 => out.metadata = Some(decode_metadata(decoder)?),
            23 => out.signatures = decode_signatures(decoder)?,
            _ => decoder.skip().map_err(cbor_decode_error)?,
        }
    }
    Ok(out)
}

fn decode_optional_hash(
    decoder: &mut Decoder<'_>,
) -> Result<Option<TailscaleAumHash>, TailscaleTkaAuthorityError> {
    if decoder.datatype().map_err(cbor_decode_error)? == Type::Null {
        decoder.null().map_err(cbor_decode_error)?;
        return Ok(None);
    }
    let bytes: [u8; 32] = decoder
        .bytes()
        .map_err(cbor_decode_error)?
        .try_into()
        .map_err(|_| TailscaleTkaAuthorityError::InvalidHash)?;
    Ok(Some(TailscaleAumHash(bytes)))
}

fn decode_key(
    decoder: &mut Decoder<'_>,
) -> Result<TailscaleTkaKey, TailscaleTkaAuthorityError> {
    let length = definite_map(decoder)?;
    let mut out = TailscaleTkaKey {
        kind: 0,
        votes: 0,
        public: Vec::new(),
        metadata: BTreeMap::new(),
    };
    for _ in 0..length {
        match decoder.u8().map_err(cbor_decode_error)? {
            1 => out.kind = decoder.u8().map_err(cbor_decode_error)?,
            2 => out.votes = decoder.u64().map_err(cbor_decode_error)?,
            3 => {
                out.public =
                    decoder.bytes().map_err(cbor_decode_error)?.to_vec()
            }
            12 => out.metadata = decode_metadata(decoder)?,
            _ => decoder.skip().map_err(cbor_decode_error)?,
        }
    }
    Ok(out)
}

fn decode_state(
    decoder: &mut Decoder<'_>,
) -> Result<TailscaleTkaAuthorityState, TailscaleTkaAuthorityError> {
    let length = definite_map(decoder)?;
    let mut out = TailscaleTkaAuthorityState::default();
    for _ in 0..length {
        match decoder.u8().map_err(cbor_decode_error)? {
            1 => out.last_aum_hash = decode_optional_hash(decoder)?,
            2 => out.disablement_values = decode_byte_arrays(decoder)?,
            3 => {
                let count = definite_array(decoder)?;
                for _ in 0..count {
                    out.keys.push(decode_key(decoder)?);
                }
            }
            4 => out.state_id_1 = decoder.u64().map_err(cbor_decode_error)?,
            5 => out.state_id_2 = decoder.u64().map_err(cbor_decode_error)?,
            _ => decoder.skip().map_err(cbor_decode_error)?,
        }
    }
    Ok(out)
}

fn decode_byte_arrays(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<Vec<u8>>, TailscaleTkaAuthorityError> {
    let count = definite_array(decoder)?;
    (0..count)
        .map(|_| {
            decoder
                .bytes()
                .map(|bytes| bytes.to_vec())
                .map_err(cbor_decode_error)
        })
        .collect()
}

fn decode_metadata(
    decoder: &mut Decoder<'_>,
) -> Result<BTreeMap<String, String>, TailscaleTkaAuthorityError> {
    let count = definite_map(decoder)?;
    (0..count)
        .map(|_| {
            Ok((
                decoder.str().map_err(cbor_decode_error)?.to_owned(),
                decoder.str().map_err(cbor_decode_error)?.to_owned(),
            ))
        })
        .collect()
}

fn decode_signatures(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<TailscaleAumSignature>, TailscaleTkaAuthorityError> {
    let count = definite_array(decoder)?;
    let mut signatures = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let fields = definite_map(decoder)?;
        let mut signature = TailscaleAumSignature {
            key_id: Vec::new(),
            signature: Vec::new(),
        };
        for _ in 0..fields {
            match decoder.u8().map_err(cbor_decode_error)? {
                1 => {
                    signature.key_id =
                        decoder.bytes().map_err(cbor_decode_error)?.to_vec()
                }
                2 => {
                    signature.signature =
                        decoder.bytes().map_err(cbor_decode_error)?.to_vec()
                }
                _ => decoder.skip().map_err(cbor_decode_error)?,
            }
        }
        signatures.push(signature);
    }
    Ok(signatures)
}

fn encode_aum<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    aum: &TailscaleAum,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    let fields = 2
        + usize::from(aum.key.is_some())
        + usize::from(aum.key_id.is_some())
        + usize::from(aum.state.is_some())
        + usize::from(aum.votes.is_some())
        + usize::from(aum.metadata.is_some())
        + usize::from(!aum.signatures.is_empty());
    encoder.map(fields as u64)?.u8(1)?.u8(aum.kind)?.u8(2)?;
    if let Some(previous) = aum.previous {
        encoder.bytes(previous.as_bytes())?;
    } else {
        encoder.null()?;
    }
    if let Some(key) = &aum.key {
        encoder.u8(3)?;
        encode_key(encoder, key)?;
    }
    if let Some(key_id) = &aum.key_id {
        encoder.u8(4)?.bytes(key_id)?;
    }
    if let Some(state) = &aum.state {
        encoder.u8(5)?;
        encode_state(encoder, state)?;
    }
    if let Some(votes) = aum.votes {
        encoder.u8(6)?.u64(votes)?;
    }
    if let Some(metadata) = &aum.metadata {
        encoder.u8(7)?;
        encode_metadata(encoder, metadata)?;
    }
    if !aum.signatures.is_empty() {
        encoder.u8(23)?.array(aum.signatures.len() as u64)?;
        for signature in &aum.signatures {
            encoder
                .map(2)?
                .u8(1)?
                .bytes(&signature.key_id)?
                .u8(2)?
                .bytes(&signature.signature)?;
        }
    }
    Ok(())
}

fn encode_key<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    key: &TailscaleTkaKey,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    encoder
        .map(3 + u64::from(!key.metadata.is_empty()))?
        .u8(1)?
        .u8(key.kind)?
        .u8(2)?
        .u64(key.votes)?
        .u8(3)?
        .bytes(&key.public)?;
    if !key.metadata.is_empty() {
        encoder.u8(12)?;
        encode_metadata(encoder, &key.metadata)?;
    }
    Ok(())
}

fn encode_state<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    state: &TailscaleTkaAuthorityState,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    encoder
        .map(
            3 + u64::from(state.state_id_1 != 0)
                + u64::from(state.state_id_2 != 0),
        )?
        .u8(1)?;
    if let Some(hash) = state.last_aum_hash {
        encoder.bytes(hash.as_bytes())?;
    } else {
        encoder.null()?;
    }
    encoder
        .u8(2)?
        .array(state.disablement_values.len() as u64)?;
    for value in &state.disablement_values {
        encoder.bytes(value)?;
    }
    encoder.u8(3)?.array(state.keys.len() as u64)?;
    for key in &state.keys {
        encode_key(encoder, key)?;
    }
    if state.state_id_1 != 0 {
        encoder.u8(4)?.u64(state.state_id_1)?;
    }
    if state.state_id_2 != 0 {
        encoder.u8(5)?.u64(state.state_id_2)?;
    }
    Ok(())
}

fn encode_metadata<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    metadata: &BTreeMap<String, String>,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    let mut entries = metadata.iter().collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    encoder.map(entries.len() as u64)?;
    for (key, value) in entries {
        encoder.str(key)?.str(value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    const GENESIS: &str = "a4010502f605a501f60281582000000000000000000000000000000000000000000000000000000000000000000381a40101020103582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80ca1646e616d65666f7261636c65040105021781a201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80258400a07edc0140dee672fe5c01abd2cf92e9ba69bb726468c4526adf2eb68302692573e2da04bb6b40157cf99e11dda2cedc851f7bc3e85c21c189a08fa7315f90b";
    const UPDATE: &str = "a50104025820ecae136341da94facb86e712681ceb0054edb504fcd5751d6a5c56c6f1604dab04582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b806021781a201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8025840f16e910e578e7f3a96b880fce1037211c3a9d07abc23e11884830bd19e012c630e0f09d88d7fb33d8f464d38506788a9770125acde4ad371df10363b421cf300";
    const GENESIS_HASH: &str =
        "5SXBGY2B3KKPVS4G44JGQHHLABKO3NIE7TKXKHLKLRLMN4LAJWVQ";
    const UPDATE_HASH: &str =
        "LTFXYENVU53J3LTTCFGSFJVCXOJBMB7XQWTGSJ6SYHHXUUIPAXTQ";

    fn wire(value: &str) -> Vec<u8> {
        hex::decode(value).unwrap()
    }

    fn sign_aum(mut aum: TailscaleAum, key: &SigningKey) -> Vec<u8> {
        let digest = aum.signature_hash().unwrap();
        aum.signatures.push(TailscaleAumSignature {
            key_id: key.verifying_key().to_bytes().to_vec(),
            signature: key.sign(&digest).to_bytes().to_vec(),
        });
        aum.encode().unwrap()
    }

    fn test_authority() -> (TailscaleTkaAuthority, SigningKey) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let state = TailscaleTkaAuthorityState {
            last_aum_hash: None,
            disablement_values: vec![vec![9; 32]],
            keys: vec![TailscaleTkaKey {
                kind: 1,
                votes: 1,
                public: key.verifying_key().to_bytes().to_vec(),
                metadata: BTreeMap::new(),
            }],
            state_id_1: 11,
            state_id_2: 22,
        };
        let genesis = sign_aum(
            TailscaleAum {
                kind: TailscaleAum::KIND_CHECKPOINT,
                previous: None,
                key: None,
                key_id: None,
                state: Some(state),
                votes: None,
                metadata: None,
                signatures: Vec::new(),
            },
            &key,
        );
        (TailscaleTkaAuthority::bootstrap(&genesis).unwrap(), key)
    }

    #[test]
    fn go_oracle_aum_encoding_hash_verification_and_sync_match() {
        let genesis = wire(GENESIS);
        let decoded = TailscaleAum::decode(&genesis).unwrap();
        assert_eq!(decoded.encode().unwrap(), genesis);
        assert_eq!(decoded.hash().unwrap().to_string(), GENESIS_HASH);

        let mut authority = TailscaleTkaAuthority::bootstrap(&genesis).unwrap();
        assert_eq!(authority.head().to_string(), GENESIS_HASH);
        let remote_before = authority.sync_offer().unwrap();

        let update = wire(UPDATE);
        let decoded = TailscaleAum::decode(&update).unwrap();
        assert_eq!(decoded.encode().unwrap(), update);
        assert_eq!(decoded.hash().unwrap().to_string(), UPDATE_HASH);
        authority.inform(std::slice::from_ref(&update)).unwrap();
        assert_eq!(authority.head().to_string(), UPDATE_HASH);
        assert_eq!(authority.state().keys[0].votes, 2);

        let offer = authority.sync_offer().unwrap();
        assert_eq!(offer.head.to_string(), UPDATE_HASH);
        assert_eq!(offer.ancestors, vec![GENESIS_HASH.parse().unwrap()]);
        assert_eq!(
            authority.missing_aums(&remote_before).unwrap(),
            vec![update]
        );
        let restored =
            TailscaleTkaAuthority::from_archive(&authority.archive().unwrap())
                .unwrap();
        assert_eq!(restored.head(), authority.head());
        assert_eq!(restored.state(), authority.state());
    }

    #[test]
    fn inform_is_atomic_when_signature_is_tampered() {
        let genesis = wire(GENESIS);
        let mut authority = TailscaleTkaAuthority::bootstrap(&genesis).unwrap();
        let original = authority.head();
        let mut update = wire(UPDATE);
        *update.last_mut().unwrap() ^= 1;
        assert!(authority.inform(&[update]).is_err());
        assert_eq!(authority.head(), original);
        assert_eq!(authority.state().keys[0].votes, 1);
    }

    #[test]
    fn aum_hash_text_requires_exact_base32_length() {
        let hash: TailscaleAumHash = GENESIS_HASH.parse().unwrap();
        assert_eq!(hash.to_string(), GENESIS_HASH);
        assert!("AAAA".parse::<TailscaleAumHash>().is_err());
    }

    #[test]
    fn compaction_keeps_checkpoint_tail_and_restores_archive() {
        let (mut authority, key) = test_authority();
        let now = UNIX_EPOCH + Duration::from_secs(100 * 24 * 60 * 60);
        let old = now - Duration::from_secs(30 * 24 * 60 * 60);
        authority.commit_times.insert(authority.head(), old);
        let mut chain = vec![authority.head()];
        let mut checkpoints = Vec::new();
        for index in 1..=30 {
            let previous = authority.head();
            let (kind, state) = if index % 5 == 0 {
                let mut state = authority.state().clone();
                state.last_aum_hash = None;
                (TailscaleAum::KIND_CHECKPOINT, Some(state))
            } else {
                (TailscaleAum::KIND_NO_OP, None)
            };
            let encoded = sign_aum(
                TailscaleAum {
                    kind,
                    previous: Some(previous),
                    key: None,
                    key_id: None,
                    state,
                    votes: None,
                    metadata: None,
                    signatures: Vec::new(),
                },
                &key,
            );
            authority.inform_at(&[encoded], old).unwrap();
            chain.push(authority.head());
            if index % 5 == 0 {
                checkpoints.push(authority.head());
            }
        }
        let head = authority.head();
        assert_eq!(authority.archive().unwrap().len(), 31);
        let mut branched = authority.clone();
        let branch_parent = chain[12];
        let mut branch_state = branched.state_at(branch_parent).unwrap();
        branch_state.last_aum_hash = None;
        let branch = TailscaleAum::decode(&sign_aum(
            TailscaleAum {
                kind: TailscaleAum::KIND_CHECKPOINT,
                previous: Some(branch_parent),
                key: None,
                key_id: None,
                state: Some(branch_state),
                votes: None,
                metadata: None,
                signatures: Vec::new(),
            },
            &key,
        ))
        .unwrap();
        let branch_hash = branch.hash().unwrap();
        branched.aums.insert(branch_hash, branch);
        branched
            .commit_times
            .insert(branch_hash, now - Duration::from_secs(24 * 60 * 60));

        let removed = authority
            .compact_at(
                TailscaleTkaCompactionOptions {
                    min_chain: 4,
                    min_age: Duration::from_secs(14 * 24 * 60 * 60),
                },
                now,
            )
            .unwrap();
        assert_eq!(removed, 25);
        assert_eq!(authority.oldest, checkpoints[4]);
        assert_eq!(authority.head(), head);
        assert_eq!(authority.active_chain().unwrap().len(), 6);

        let archive = authority.archive().unwrap();
        let restored = TailscaleTkaAuthority::from_archive_with_commit_times(
            &archive,
            &authority.commit_times_unix(),
        )
        .unwrap();
        assert_eq!(restored.oldest, authority.oldest);
        assert_eq!(restored.head(), authority.head());
        assert_eq!(restored.state(), authority.state());
        assert_eq!(restored.archive().unwrap(), archive);
        assert_eq!(
            restored.sync_offer().unwrap().ancestors.last(),
            Some(&authority.oldest)
        );

        assert_eq!(
            branched
                .compact_at(
                    TailscaleTkaCompactionOptions {
                        min_chain: 4,
                        min_age: Duration::from_secs(14 * 24 * 60 * 60),
                    },
                    now,
                )
                .unwrap(),
            10
        );
        assert_eq!(branched.oldest, checkpoints[1]);
        assert!(branched.aums.contains_key(&branch_hash));
        assert_eq!(branched.archive().unwrap().len(), 22);
        assert!(matches!(
            authority.compact_at(
                TailscaleTkaCompactionOptions {
                    min_chain: 0,
                    min_age: Duration::from_secs(1),
                },
                now,
            ),
            Err(TailscaleTkaAuthorityError::InvalidCompactionOptions)
        ));
    }
}
