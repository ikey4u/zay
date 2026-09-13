pub const OPENVPN_PACKET_ID_WRAP_TRIGGER: u32 = 0xff00_0000;
pub const SWEET32_RENEGOTIATION_BYTES_CLAMP: u64 = 64 * 1024 * 1024;
pub const AES_GCM_USAGE_LIMIT: u64 = (((1_u64 << 36) - 1) / 8) * 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenegotiationDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DirectionUsage {
    highest_packet_id: u32,
    plaintext_blocks: u64,
}

/// Per-key OpenVPN renegotiation accounting. It combines configured transfer
/// limits, the SWEET32 64 MiB clamp, packet-ID exhaustion, and the AEAD usage
/// limit from OpenVPN's `tls_limit_reneg_bytes`/`packet_id` logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRenegotiationBudget {
    bytes_limit: u64,
    packets_limit: u64,
    aead_usage_limit: u64,
    active_key_id: u8,
    bytes_transferred: u64,
    packets_transferred: u64,
    send_usage: DirectionUsage,
    receive_usage: DirectionUsage,
}

impl DataRenegotiationBudget {
    pub fn new(
        cipher_name: &str,
        configured_bytes: u64,
        configured_packets: u64,
        active_key_id: u8,
    ) -> Self {
        let cipher_name = cipher_name.trim().to_ascii_uppercase();
        let bytes_limit = if configured_bytes == 0
            && is_sweet32_vulnerable_cipher(&cipher_name)
        {
            SWEET32_RENEGOTIATION_BYTES_CLAMP
        } else {
            configured_bytes
        };
        let aead_usage_limit = matches!(
            cipher_name.as_str(),
            "AES-128-GCM" | "AES-192-GCM" | "AES-256-GCM"
        )
        .then_some(AES_GCM_USAGE_LIMIT)
        .unwrap_or(0);
        Self {
            bytes_limit,
            packets_limit: configured_packets,
            aead_usage_limit,
            active_key_id,
            bytes_transferred: 0,
            packets_transferred: 0,
            send_usage: DirectionUsage::default(),
            receive_usage: DirectionUsage::default(),
        }
    }

    pub fn active_key_id(&self) -> u8 {
        self.active_key_id
    }

    pub fn bytes_limit(&self) -> u64 {
        self.bytes_limit
    }

    /// Returns true once this packet requires a soft reset.
    pub fn consume_transfer(
        &mut self,
        key_id: u8,
        accounted_bytes: usize,
    ) -> bool {
        if key_id != self.active_key_id {
            return false;
        }
        self.bytes_transferred =
            self.bytes_transferred.wrapping_add(accounted_bytes as u64);
        self.packets_transferred = self.packets_transferred.wrapping_add(1);
        (self.bytes_limit > 0 && self.bytes_transferred >= self.bytes_limit)
            || (self.packets_limit > 0
                && self.packets_transferred >= self.packets_limit)
    }

    /// Account the nonce/packet-ID and plaintext blocks used in one direction.
    /// Returns true once OpenVPN must negotiate a fresh key.
    pub fn consume_usage(
        &mut self,
        key_id: u8,
        direction: RenegotiationDirection,
        packet_id: u32,
        aead_plaintext_bytes: usize,
    ) -> bool {
        if key_id != self.active_key_id {
            return false;
        }
        let usage = match direction {
            RenegotiationDirection::Send => &mut self.send_usage,
            RenegotiationDirection::Receive => &mut self.receive_usage,
        };
        usage.highest_packet_id = usage.highest_packet_id.max(packet_id);
        if aead_plaintext_bytes > 0 {
            usage.plaintext_blocks = usage
                .plaintext_blocks
                .wrapping_add((aead_plaintext_bytes as u64).div_ceil(16));
        }
        (direction == RenegotiationDirection::Send
            && packet_id >= OPENVPN_PACKET_ID_WRAP_TRIGGER)
            || (self.aead_usage_limit > 0
                && usage
                    .plaintext_blocks
                    .wrapping_add(u64::from(usage.highest_packet_id))
                    > self.aead_usage_limit)
    }

    pub fn reset(&mut self, active_key_id: u8) {
        self.active_key_id = active_key_id;
        self.bytes_transferred = 0;
        self.packets_transferred = 0;
        self.send_usage = DirectionUsage::default();
        self.receive_usage = DirectionUsage::default();
    }
}

pub fn is_sweet32_vulnerable_cipher(cipher_name: &str) -> bool {
    matches!(
        cipher_name.trim().to_ascii_uppercase().as_str(),
        "BF-CBC"
            | "BF-CFB"
            | "BF-OFB"
            | "CAST5-CBC"
            | "CAST5-CFB"
            | "CAST5-OFB"
            | "DES-CBC"
            | "DES-CFB"
            | "DES-OFB"
            | "DES-EDE-CBC"
            | "DES-EDE-CFB"
            | "DES-EDE-OFB"
            | "DES-EDE3-CBC"
            | "DES-EDE3-CFB"
            | "DES-EDE3-OFB"
            | "RC2-CBC"
            | "RC2-40-CBC"
            | "RC2-64-CBC"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_explicit_transfer_limits_only_to_the_active_key() {
        let mut budget = DataRenegotiationBudget::new("AES-256-GCM", 100, 3, 2);
        assert!(!budget.consume_transfer(1, 500));
        assert!(!budget.consume_transfer(2, 40));
        assert!(!budget.consume_transfer(2, 40));
        assert!(budget.consume_transfer(2, 20));
        budget.reset(3);
        assert!(!budget.consume_transfer(2, 100));
        assert!(!budget.consume_transfer(3, 1));
    }

    #[test]
    fn applies_sweet32_default_but_preserves_explicit_limit() {
        assert_eq!(
            DataRenegotiationBudget::new(" bf-cbc ", 0, 0, 0).bytes_limit(),
            SWEET32_RENEGOTIATION_BYTES_CLAMP
        );
        assert_eq!(
            DataRenegotiationBudget::new("BF-CBC", 1234, 0, 0).bytes_limit(),
            1234
        );
        assert_eq!(
            DataRenegotiationBudget::new("AES-256-CBC", 0, 0, 0).bytes_limit(),
            0
        );
    }

    #[test]
    fn triggers_before_outgoing_packet_id_wrap_only() {
        let mut budget =
            DataRenegotiationBudget::new("CHACHA20-POLY1305", 0, 0, 4);
        assert!(!budget.consume_usage(
            4,
            RenegotiationDirection::Receive,
            OPENVPN_PACKET_ID_WRAP_TRIGGER,
            0,
        ));
        assert!(budget.consume_usage(
            4,
            RenegotiationDirection::Send,
            OPENVPN_PACKET_ID_WRAP_TRIGGER,
            0,
        ));
    }

    #[test]
    fn tracks_aes_gcm_blocks_and_highest_packet_id_per_direction() {
        let mut budget = DataRenegotiationBudget::new("AES-128-GCM", 0, 0, 1);
        budget.send_usage.plaintext_blocks = AES_GCM_USAGE_LIMIT - 10;
        assert!(!budget.consume_usage(1, RenegotiationDirection::Send, 5, 16));
        assert!(budget.consume_usage(1, RenegotiationDirection::Send, 11, 16));
        assert!(!budget.consume_usage(
            1,
            RenegotiationDirection::Receive,
            11,
            16
        ));
    }
}
