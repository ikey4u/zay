//! Deterministic Snell v6 default-mode traffic profile.

use blake2::{
    Blake2bVar,
    digest::{Update as _, VariableOutput as _},
};

use super::snell::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, SALT_LEN};

const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const NAMESPACE_ADD: u64 = 0xa076_1d64_78bd_642f;
const COEF_B: u64 = 0x5899_65cc_7537_4cc3;
const ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
const COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
const ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;
const MAX_EXTRA_PADDING: usize = 0x02da;
const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;

const LABEL_PADDING: u32 = 0;
const LABEL_BIT_PERCENT: u32 = 1;
const LABEL_MOTIF: u32 = 2;
const LABEL_MIX_OFFSET: u32 = 3;
const LABEL_SALT: u32 = 3;
const LABEL_PROFILE_ID: u32 = 5;
const LABEL_GENERATOR: u32 = 6;
const LABEL_PAD_MIN: u32 = 7;
const LABEL_PAD_MAX: u32 = 8;
const LABEL_PAD_COUNT: u32 = 9;
const LABEL_PAD_INTERVAL: u32 = 10;
const LABEL_SMALL_LIMIT: u32 = 11;
const LABEL_BIT_MIN: u32 = 12;
const LABEL_BIT_MAX: u32 = 13;
const LABEL_PREFIX_MIN: u32 = 14;
const LABEL_PREFIX_MAX: u32 = 15;
const LABEL_MIX_MODE: u32 = 16;
const LABEL_MIX_ROUNDS: u32 = 17;
const LABEL_MIX_STRIDE: u32 = 18;
const LABEL_MIX_OFFSET_BASE: u32 = 19;
const LABEL_MIX_BLOCK: u32 = 20;
const LABEL_CHUNK_POLICY: u32 = 21;
const LABEL_CHUNK_INITIAL: u32 = 22;
const LABEL_CHUNK_FIRST_CAP: u32 = 22;
const LABEL_CHUNK_MAX: u32 = 23;
const LABEL_CHUNK_STEP: u32 = 24;
const LABEL_CHUNK_JITTER: u32 = 25;
const LABEL_CHUNK_BUCKET: u32 = 26;
const LABEL_IDLE_RESET: u32 = 27;
const LABEL_WRITE_POLICY: u32 = 28;
const LABEL_WRITE_FIRST: u32 = 29;
const LABEL_WRITE_BUCKET: u32 = 30;
const LABEL_WRITE_SEQ: u32 = 31;
const LABEL_WRITE_JITTER: u32 = 32;
const LABEL_RECORD_PREFIX: u32 = 33;
const LABEL_PAYLOAD_PAD: u32 = 34;
const LABEL_WRITE_TARGET: u32 = 35;
const LABEL_WRITE_JITTER_V: u32 = 36;
const LABEL_WRITE_NEXT: u32 = 37;
const LABEL_CHUNK_SIZE: u32 = 38;
const LABEL_CHUNK_JITTER_V: u32 = 39;

const NS_SEED_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_SEED_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_SEED_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SEED_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_SEED_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_SEED_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_SEED_WRITE: u64 = 0x917b_3c48_e6a2_05d4;
const SALT_NS_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;

const PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94,
    0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

const BIT_ROTATE_TABLE: [u8; 128] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64,
    128, 1, 2, 4, 8, 16, 32, 64, 128, 3, 5, 9, 17, 33, 65, 129, 6, 10, 18, 34,
    66, 130, 12, 24, 36, 7, 11, 19, 35, 67, 131, 13, 25, 49, 97, 193, 14, 28,
    56, 112, 224, 15, 23, 39, 71, 135, 27, 51, 99, 195, 29, 57, 113, 225, 60,
    120, 240, 248, 244, 236, 220, 188, 124, 242, 230, 206, 158, 62, 241, 227,
    199, 143, 31, 252, 250, 246, 238, 222, 190, 126, 249, 245, 237, 221, 189,
    125, 243, 231, 219, 254, 253, 251, 247, 239, 223, 191, 127, 254, 253, 251,
    247, 239, 223, 191, 127,
];

fn splitmix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let value = namespace
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ u64::from(label).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let mixed = splitmix64(value);
    (mixed ^ (mixed >> 32)) as u32
}

fn pick(raw: u32, low: usize, high: usize) -> usize {
    low + raw as usize % (high - low + 1)
}

fn pick_u32(raw: u32, low: u32, high: u32) -> u32 {
    low + raw % (high - low + 1)
}

#[derive(Clone, Copy)]
struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

fn derive_namespace(secret: &[u8; 32], label: u32, seed: u64) -> u64 {
    let word = |offset| {
        u64::from_le_bytes(secret[offset..offset + 8].try_into().unwrap())
    };
    let mixed = u64::from(label).wrapping_mul(DOMAIN_MUL)
        ^ seed.wrapping_add(NAMESPACE_ADD)
        ^ word(0)
        ^ word(8).wrapping_add(GOLDEN_GAMMA)
        ^ word(16).rotate_left(17)
        ^ word(24).rotate_right(11);
    splitmix64(mixed)
}

impl Namespaces {
    fn new(secret: &[u8; 32]) -> Self {
        Self {
            profile: derive_namespace(
                secret,
                LABEL_PROFILE_ID,
                NS_SEED_PROFILE,
            ),
            prefix: derive_namespace(secret, LABEL_PADDING, NS_SEED_PREFIX),
            motif: derive_namespace(secret, LABEL_MOTIF, NS_SEED_MOTIF),
            salt: derive_namespace(secret, LABEL_SALT, NS_SEED_SALT),
            mix: derive_namespace(secret, LABEL_MIX_MODE, NS_SEED_MIX),
            chunk: derive_namespace(secret, LABEL_CHUNK_POLICY, NS_SEED_CHUNK),
            write: derive_namespace(secret, LABEL_WRITE_POLICY, NS_SEED_WRITE),
        }
    }

    fn for_label(self, label: u32) -> u64 {
        match label {
            LABEL_PADDING | LABEL_BIT_PERCENT | LABEL_PREFIX_MIN
            | LABEL_PREFIX_MAX | LABEL_RECORD_PREFIX | LABEL_PAYLOAD_PAD => {
                self.prefix
            }
            LABEL_MOTIF => self.motif,
            LABEL_MIX_OFFSET
            | LABEL_MIX_MODE
            | LABEL_MIX_ROUNDS
            | LABEL_MIX_STRIDE
            | LABEL_MIX_OFFSET_BASE
            | LABEL_MIX_BLOCK => self.mix,
            LABEL_CHUNK_POLICY | LABEL_CHUNK_INITIAL | LABEL_CHUNK_MAX
            | LABEL_CHUNK_STEP | LABEL_CHUNK_JITTER | LABEL_CHUNK_BUCKET
            | LABEL_CHUNK_SIZE | LABEL_CHUNK_JITTER_V => self.chunk,
            LABEL_WRITE_POLICY | LABEL_WRITE_FIRST | LABEL_WRITE_BUCKET
            | LABEL_WRITE_SEQ | LABEL_WRITE_JITTER | LABEL_WRITE_TARGET
            | LABEL_WRITE_JITTER_V | LABEL_WRITE_NEXT => self.write,
            _ => self.profile,
        }
    }

    fn prf32(self, label: u32, a: u32, b: u32) -> u32 {
        prf32_fold(self.for_label(label), label, u64::from(a), u64::from(b))
    }

    fn prf_static(self, label: u32, domain: u32) -> u32 {
        prf32_fold(self.for_label(label), label, 0, u64::from(domain))
    }

    fn prf_bytes(self, label: u32, a: u32, output: &mut [u8]) {
        let mut seed = self.for_label(label)
            ^ u64::from(a)
                .wrapping_mul(DOMAIN_MUL)
                .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ u64::from(label).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (output.len() as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        let mut offset = 0;
        while offset < output.len() {
            seed = seed.wrapping_add(GOLDEN_GAMMA);
            let block = splitmix64(seed).to_le_bytes();
            let size = (output.len() - offset).min(8);
            output[offset..offset + size].copy_from_slice(&block[..size]);
            offset += size;
        }
    }
}

pub(crate) struct Profile {
    ns: Namespaces,
    generator: u32,
    pad_min: usize,
    pad_max: usize,
    pad_count: u32,
    pad_interval: u32,
    small_limit: usize,
    bit_min: u32,
    bit_max: u32,
    prefix_min_record: usize,
    prefix_max_record: usize,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset_base: usize,
    mix_block: usize,
    chunk_policy: u32,
    pub(crate) chunk_initial: usize,
    pub(crate) first_record_cap: usize,
    pub(crate) chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    pub(crate) idle_reset_sec: u64,
    write_policy: u32,
    write_first: u32,
    chunk_buckets: [usize; 8],
    write_buckets: [usize; 8],
    write_seq: [usize; 8],
    write_jitter: usize,
    write_jitter_pct: usize,
    g1: usize,
    g2: usize,
    g3: usize,
    g4: usize,
    g5: usize,
    g6: usize,
    pub(crate) salt_block_len: usize,
    mix_stride_handshake: usize,
    mix_rounds_handshake: u32,
}

impl Profile {
    pub(crate) fn new(psk: &[u8]) -> Self {
        let mut hasher = Blake2bVar::new(32).expect("BLAKE2b-256");
        hasher.update(&PROFILE_SEED);
        hasher.update(psk);
        let mut secret = [0_u8; 32];
        hasher.finalize_variable(&mut secret).expect("fixed output");
        let ns = Namespaces::new(&secret);
        let pad_min = pick(ns.prf_static(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = (pad_min
            + pick(ns.prf_static(LABEL_PAD_MAX, 0), 0xa0, 0x3c0))
        .min(MAX_EXTRA_PADDING);
        let prefix_min_hs = pick(
            ns.prf_static(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let prefix_max_hs = (prefix_min_hs
            + pick(
                ns.prf_static(LABEL_PREFIX_MAX, HANDSHAKE_DOMAIN),
                0x10,
                0xa0,
            ))
        .min(0x80);
        let salt_prefix_len = pick(
            ns.prf_static(LABEL_RECORD_PREFIX, HANDSHAKE_DOMAIN),
            prefix_min_hs.min(prefix_max_hs),
            prefix_max_hs,
        );
        let prefix_min_record =
            pick(ns.prf_static(LABEL_PREFIX_MIN, 0), 8, 0x50);
        let prefix_max_record = (prefix_min_record
            + pick(ns.prf_static(LABEL_PREFIX_MAX, 0), 0x10, 0xa0))
        .min(0x80);
        let chunk_initial =
            pick(ns.prf_static(LABEL_CHUNK_INITIAL, 0), 0x200, 0x5b4)
                .clamp(0x60, 0x5b4);
        let first_record_cap = pick(
            ns.prf_static(LABEL_CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN),
            0x100,
            0x300,
        )
        .clamp(0x100, chunk_initial.min(0x300));
        let chunk_max = pick(ns.prf_static(LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff)
            .max(chunk_initial);
        let mut profile = Self {
            ns,
            generator: ns.prf_static(LABEL_GENERATOR, 0) & 3,
            pad_min,
            pad_max,
            pad_count: pick_u32(ns.prf_static(LABEL_PAD_COUNT, 0), 2, 8),
            pad_interval: pick_u32(ns.prf_static(LABEL_PAD_INTERVAL, 0), 2, 11),
            small_limit: pick(ns.prf_static(LABEL_SMALL_LIMIT, 0), 0x60, 0x300),
            bit_min: pick_u32(ns.prf_static(LABEL_BIT_MIN, 0), 0x18, 0x29),
            bit_max: pick_u32(ns.prf_static(LABEL_BIT_MAX, 0), 0x3a, 0x4c),
            prefix_min_record: prefix_min_record.min(prefix_max_record),
            prefix_max_record,
            mix_mode: ns.prf_static(LABEL_MIX_MODE, 0) % 3,
            mix_rounds: pick_u32(ns.prf_static(LABEL_MIX_ROUNDS, 0), 1, 3),
            mix_stride: pick(ns.prf_static(LABEL_MIX_STRIDE, 0), 2, 13),
            mix_offset_base: pick(
                ns.prf_static(LABEL_MIX_OFFSET_BASE, 0),
                0,
                15,
            ),
            mix_block: pick(ns.prf_static(LABEL_MIX_BLOCK, 0), 8, 0x40),
            chunk_policy: ns.prf_static(LABEL_CHUNK_POLICY, 0) % 3,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: pick(ns.prf_static(LABEL_CHUNK_STEP, 0), 0x400, 0x1000)
                .min(0xb68),
            chunk_jitter: pick(
                ns.prf_static(LABEL_CHUNK_JITTER, 0),
                0x10,
                0xc0,
            )
            .min(0xb6),
            idle_reset_sec: pick(ns.prf_static(LABEL_IDLE_RESET, 0), 12, 90)
                as u64,
            write_policy: ns.prf_static(LABEL_WRITE_POLICY, 0) % 3,
            write_first: pick_u32(ns.prf_static(LABEL_WRITE_FIRST, 0), 4, 8),
            chunk_buckets: [0; 8],
            write_buckets: [0; 8],
            write_seq: [0; 8],
            write_jitter: pick(ns.prf_static(LABEL_WRITE_JITTER, 0), 8, 0x60),
            write_jitter_pct: pick(
                ns.prf_static(LABEL_WRITE_POLICY, 0x504c),
                8,
                0x30,
            ),
            g1: pick(ns.prf_static(LABEL_GENERATOR, 1), 0x18, 0x80),
            g2: pick(ns.prf_static(LABEL_GENERATOR, 2), 0x10, 0x60),
            g3: pick(ns.prf_static(LABEL_GENERATOR, 3), 0x10, 0x60),
            g4: pick(ns.prf_static(LABEL_GENERATOR, 4), 0, 9),
            g5: pick(ns.prf_static(LABEL_GENERATOR, 5), 1, 8),
            g6: pick(ns.prf_static(LABEL_GENERATOR, 6), 7, 0x17),
            salt_block_len: SALT_LEN + salt_prefix_len,
            mix_stride_handshake: pick(
                ns.prf_static(LABEL_MIX_STRIDE, MIX_HANDSHAKE_DOMAIN),
                0x11,
                0xfb,
            ),
            mix_rounds_handshake: pick_u32(
                ns.prf_static(LABEL_MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN),
                1,
                4,
            ),
        };
        for index in 0..8 {
            profile.chunk_buckets[index] = pick(
                ns.prf_static(LABEL_CHUNK_BUCKET, index as u32),
                0x1000,
                chunk_max,
            );
            profile.write_buckets[index] = pick(
                ns.prf_static(LABEL_WRITE_BUCKET, index as u32),
                0x140,
                0x5b4,
            );
            profile.write_seq[index] = pick(
                ns.prf_static(LABEL_WRITE_SEQ, index as u32),
                0x168,
                0x5b4,
            );
        }
        profile
    }

    pub(crate) fn record_prefix_len(&self, seq: u32) -> usize {
        pick(
            self.ns.prf32(LABEL_RECORD_PREFIX, seq, 0),
            self.prefix_min_record,
            self.prefix_max_record,
        )
    }

    pub(crate) fn chunk_payload_limit(
        &self,
        seq: u32,
        mut chunk: usize,
    ) -> usize {
        if chunk == 0 {
            chunk = self.chunk_initial;
        }
        match self.chunk_policy {
            1 => {
                chunk = self.chunk_buckets[self.ns.prf32(
                    LABEL_CHUNK_SIZE,
                    seq,
                    chunk as u32,
                ) as usize
                    % 8]
            }
            2 => {
                let raw = self.ns.prf32(LABEL_CHUNK_JITTER_V, seq, chunk as u32)
                    as usize;
                chunk = chunk
                    .saturating_add(raw % (self.chunk_jitter * 2 + 1))
                    .saturating_sub(self.chunk_jitter);
            }
            _ => {}
        }
        chunk.clamp(0x40, self.chunk_max)
    }

    pub(crate) fn next_chunk_size(&self, chunk: usize) -> usize {
        if chunk == 0 {
            self.chunk_initial
        } else {
            (chunk + self.chunk_step).min(self.chunk_max)
        }
    }

    pub(crate) fn padding_len(
        &self,
        seq: u32,
        payload: usize,
        prefix: usize,
        salt_prefix: usize,
        total: usize,
    ) -> usize {
        let mut padding = if seq < self.pad_count
            || (payload > 0 && payload <= self.small_limit)
            || (self.pad_interval > 0 && seq.is_multiple_of(self.pad_interval))
        {
            pick(
                self.ns.prf32(LABEL_PAYLOAD_PAD, seq, payload as u32),
                self.pad_min,
                self.pad_max,
            )
        } else {
            0
        };
        let tag = usize::from(payload > 0) * AEAD_TAG_LEN;
        let frame =
            total + prefix + HEADER_CIPHER_LEN + padding + payload + tag;
        let target = self.write_target(seq, frame);
        if target > frame {
            padding += (target - frame).min(MAX_EXTRA_PADDING);
        }
        if total > 0 {
            padding = self.first_record_padding_len(
                padding,
                prefix,
                salt_prefix,
                payload,
            );
        }
        padding.min(u16::MAX as usize)
    }

    fn write_target(&self, seq: u32, frame: usize) -> usize {
        if frame > 0x5b3 {
            return frame.min(u16::MAX as usize);
        }
        let mut target = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets[self.ns.prf32(
                LABEL_WRITE_TARGET,
                seq,
                frame as u32,
            ) as usize
                % 8]
        };
        if self.write_policy == 2 {
            let raw = self.ns.prf32(LABEL_WRITE_JITTER_V, seq, 0) as usize;
            target = target
                .saturating_add(raw % (self.write_jitter * 2 + 1))
                .saturating_sub(self.write_jitter)
                .max(1);
        }
        let spread = MAX_EXTRA_PADDING.min(frame * self.write_jitter_pct / 100);
        if self.ns.prf32(LABEL_WRITE_TARGET, seq, spread as u32) & 1 == 0 {
            target = target.saturating_add(spread).min(u16::MAX as usize);
        } else {
            target = target.saturating_sub(spread >> 1);
        }
        while frame > target {
            let mut next = self.write_buckets[self.ns.prf32(
                LABEL_WRITE_NEXT,
                seq,
                target as u32,
            ) as usize
                % 8];
            if next <= target {
                next = target.saturating_add(self.pad_max);
                if next > u16::MAX as usize {
                    return u16::MAX as usize;
                }
            }
            target = next;
        }
        target
    }

    fn first_record_padding_len(
        &self,
        padding: usize,
        prefix: usize,
        salt_prefix: usize,
        payload: usize,
    ) -> usize {
        let overhead = salt_prefix + prefix + padding;
        let input = payload + if payload == 0 { 0x27 } else { 0x37 };
        let threshold = (input * 25).div_ceil(75).max(0xc0);
        if overhead >= threshold {
            return padding;
        }
        let target = threshold
            .saturating_sub(salt_prefix + prefix)
            .min(self.pad_max + MAX_EXTRA_PADDING);
        if target > 0xfffe { padding } else { target }
    }

    pub(crate) fn fill_padding(&self, seq: u32, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }
        self.ns.prf_bytes(LABEL_PADDING, seq, output);
        match self.generator {
            0 => {
                let bits = pick_u32(
                    self.ns.prf32(LABEL_BIT_PERCENT, seq, 0),
                    self.bit_min,
                    self.bit_max,
                );
                let scaled = bits as usize * 8;
                let rotate = if scaled <= 0x31 {
                    1
                } else if scaled <= 0x2ed {
                    (scaled + 0x32) / 100
                } else {
                    7
                };
                for (index, value) in output.iter_mut().enumerate() {
                    let original = *value;
                    let raw = original.wrapping_add(index as u8);
                    let mapped = BIT_ROTATE_TABLE[rotate.max(1) * 16
                        + usize::from((raw ^ original) & 0x0f)];
                    *value = mapped
                        .rotate_left(u32::from((raw ^ (original >> 4)) & 7));
                }
            }
            1 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let original = *value;
                    let bucket =
                        usize::from(original) % (self.g1 + self.g2 + self.g3);
                    *value = if bucket < self.g1 {
                        pick(
                            original.wrapping_add(index as u8).into(),
                            0x20,
                            0x7e,
                        ) as u8
                    } else if bucket < self.g1 + self.g2 {
                        pick((original ^ index as u8).into(), 0x80, 0xbf) as u8
                    } else {
                        pick(
                            original.wrapping_add((index * 7) as u8).into(),
                            0xc0,
                            0xff,
                        ) as u8
                    };
                }
            }
            2 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let low =
                        (usize::from(*value & 0xf) + self.g4 + (index & 1))
                            % 10;
                    let high =
                        (usize::from(*value) + ((index & 3) << 4) + 0x30)
                            & 0xf0;
                    *value = (high | low) as u8;
                }
            }
            3 => {
                let mut motif = [0_u8; 32];
                self.ns.prf_bytes(LABEL_MOTIF, seq, &mut motif);
                let motif_len = (self.g5 * 4).max(4);
                let period = self.g6.max(5);
                for (index, value) in output.iter_mut().enumerate() {
                    let block = index % period;
                    let motif_offset = index % motif_len;
                    if block < period - 3 {
                        *value = ((self.g5 + 3) * index) as u8
                            ^ motif[motif_offset % motif.len()];
                    } else if block < period - 1 {
                        *value = 0x30 | (*value % 10);
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn shuffle_perm(&self, rounds: u32, length: usize) -> Vec<u8> {
        let mut output: Vec<u8> = (0..length as u8).collect();
        for round in 0..rounds.max(1) {
            for index in 0..length {
                let rdx =
                    (index as u64).wrapping_mul(COEF_B).wrapping_add(ADD_B);
                let rdi = self.ns.salt ^ SALT_NS_XOR;
                let rsi = u64::from(MIX_HANDSHAKE_DOMAIN + round)
                    .wrapping_mul(COEF_A)
                    .wrapping_add(ADD_A);
                let mixed = splitmix64((rdx ^ rdi) ^ rsi);
                let raw = (mixed ^ (mixed >> 32)) as u32;
                let next = index + raw as usize % (length - index);
                output.swap(index, next);
            }
        }
        output
    }

    fn salt_mask(&self, index: u32) -> u8 {
        (index as u8).wrapping_mul(self.mix_stride_handshake as u8)
            ^ prf32_fold(
                self.ns.salt,
                LABEL_MOTIF,
                u64::from(MIX_HANDSHAKE_DOMAIN),
                u64::from(index),
            ) as u8
    }

    pub(crate) fn write_salt_block(
        &self,
        salt: &[u8; SALT_LEN],
        block: &mut [u8],
    ) {
        let permutation =
            self.shuffle_perm(self.mix_rounds_handshake, block.len());
        for index in 0..SALT_LEN {
            block[usize::from(permutation[index])] =
                self.salt_mask(index as u32) ^ salt[index];
        }
    }

    pub(crate) fn extract_salt(&self, block: &[u8]) -> [u8; SALT_LEN] {
        let permutation =
            self.shuffle_perm(self.mix_rounds_handshake, block.len());
        let mut salt = [0_u8; SALT_LEN];
        for index in 0..SALT_LEN {
            salt[index] = self.salt_mask(index as u32)
                ^ block[usize::from(permutation[index])];
        }
        salt
    }

    pub(crate) fn mix_padding_payload(
        &self,
        seq: u32,
        padding: &mut [u8],
        payload: &mut [u8],
    ) {
        let count = padding.len().min(payload.len());
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 => {
                    let stride =
                        (self.mix_stride + (round as usize % 3)).max(1);
                    for index in
                        (self.mix_offset_base % stride..count).step_by(stride)
                    {
                        std::mem::swap(
                            &mut padding[index],
                            &mut payload[index],
                        );
                    }
                }
                1 => {
                    let mut offset = (round as usize & 1) * self.mix_block;
                    while offset + self.mix_block <= count {
                        for index in offset..offset + self.mix_block {
                            std::mem::swap(
                                &mut padding[index],
                                &mut payload[index],
                            );
                        }
                        offset += self.mix_block * 2;
                    }
                }
                2 => {
                    let stride =
                        (self.mix_stride + (round as usize % 3)).max(1);
                    let mut offset =
                        (self.ns.prf32(LABEL_MIX_OFFSET, seq, round) as usize
                            + self.mix_offset_base)
                            % stride;
                    while offset < count {
                        std::mem::swap(
                            &mut padding[offset],
                            &mut payload[offset],
                        );
                        offset += stride;
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_mixing_is_self_inverse() {
        let profile = Profile::new(b"secret");
        let mut padding = vec![0x55; 900];
        let mut payload = vec![0xaa; 300];
        let original_padding = padding.clone();
        let original_payload = payload.clone();
        profile.mix_padding_payload(0, &mut padding, &mut payload);
        profile.mix_padding_payload(0, &mut padding, &mut payload);
        assert_eq!(padding, original_padding);
        assert_eq!(payload, original_payload);
    }
}
