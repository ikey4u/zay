use std::{fmt, net::SocketAddr};

pub const SESSION_ID_LENGTH: usize = 8;
pub const PACKET_ID_LENGTH: usize = 4;

pub type SessionId = [u8; SESSION_ID_LENGTH];
pub type PacketId = u32;
pub type PeerId = [u8; 3];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    ControlHardResetClientV1,
    ControlHardResetServerV1,
    ControlSoftResetV1,
    ControlV1,
    AcknowledgmentV1,
    DataV1,
    ControlHardResetClientV2,
    ControlHardResetServerV2,
    DataV2,
    ControlHardResetClientV3,
    ControlWkcV1,
    Unknown(u8),
}

impl Opcode {
    pub const fn from_wire(value: u8) -> Self {
        match value {
            1 => Self::ControlHardResetClientV1,
            2 => Self::ControlHardResetServerV1,
            3 => Self::ControlSoftResetV1,
            4 => Self::ControlV1,
            5 => Self::AcknowledgmentV1,
            6 => Self::DataV1,
            7 => Self::ControlHardResetClientV2,
            8 => Self::ControlHardResetServerV2,
            9 => Self::DataV2,
            10 => Self::ControlHardResetClientV3,
            11 => Self::ControlWkcV1,
            value => Self::Unknown(value),
        }
    }

    pub const fn wire_value(self) -> u8 {
        match self {
            Self::ControlHardResetClientV1 => 1,
            Self::ControlHardResetServerV1 => 2,
            Self::ControlSoftResetV1 => 3,
            Self::ControlV1 => 4,
            Self::AcknowledgmentV1 => 5,
            Self::DataV1 => 6,
            Self::ControlHardResetClientV2 => 7,
            Self::ControlHardResetServerV2 => 8,
            Self::DataV2 => 9,
            Self::ControlHardResetClientV3 => 10,
            Self::ControlWkcV1 => 11,
            Self::Unknown(value) => value,
        }
    }

    pub const fn is_control(self) -> bool {
        matches!(
            self,
            Self::ControlHardResetClientV1
                | Self::ControlHardResetServerV1
                | Self::ControlSoftResetV1
                | Self::ControlV1
                | Self::ControlHardResetClientV2
                | Self::ControlHardResetServerV2
                | Self::ControlHardResetClientV3
                | Self::ControlWkcV1
        )
    }

    pub const fn is_data(self) -> bool {
        matches!(self, Self::DataV1 | Self::DataV2)
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ControlHardResetClientV1 => "P_CONTROL_HARD_RESET_CLIENT_V1",
            Self::ControlHardResetServerV1 => "P_CONTROL_HARD_RESET_SERVER_V1",
            Self::ControlSoftResetV1 => "P_CONTROL_SOFT_RESET_V1",
            Self::ControlV1 => "P_CONTROL_V1",
            Self::AcknowledgmentV1 => "P_ACK_V1",
            Self::DataV1 => "P_DATA_V1",
            Self::ControlHardResetClientV2 => "P_CONTROL_HARD_RESET_CLIENT_V2",
            Self::ControlHardResetServerV2 => "P_CONTROL_HARD_RESET_SERVER_V2",
            Self::DataV2 => "P_DATA_V2",
            Self::ControlHardResetClientV3 => "P_CONTROL_HARD_RESET_CLIENT_V3",
            Self::ControlWkcV1 => "P_CONTROL_WKC_V1",
            Self::Unknown(_) => "P_UNKNOWN",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub opcode: Opcode,
    pub key_id: u8,
    pub peer_id: PeerId,
    pub local_session_id: SessionId,
    pub acknowledgment_ids: Vec<PacketId>,
    pub remote_session_id: SessionId,
    pub id: PacketId,
    pub payload: Vec<u8>,
    /// Link-layer source associated with an inbound datagram. This metadata
    /// is never serialized onto the OpenVPN wire; the UDP server keeps it on
    /// the parsed packet until data-channel authentication has succeeded.
    pub(crate) link_source: Option<SocketAddr>,
}

impl Packet {
    pub fn new(
        opcode: Opcode,
        key_id: u8,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            opcode,
            key_id: key_id & 0x07,
            peer_id: [0; 3],
            local_session_id: [0; SESSION_ID_LENGTH],
            acknowledgment_ids: Vec::new(),
            remote_session_id: [0; SESSION_ID_LENGTH],
            id: 0,
            payload: payload.into(),
            link_source: None,
        }
    }

    pub fn link_source(&self) -> Option<SocketAddr> {
        self.link_source
    }

    pub(crate) fn set_link_source(&mut self, source: Option<SocketAddr>) {
        self.link_source = source;
    }

    pub fn parse(input: &[u8]) -> Result<Self, PacketError> {
        let (&header, mut body) =
            input.split_first().ok_or(PacketError::TooShort)?;
        let opcode = Opcode::from_wire(header >> 3);
        let mut packet = Self::new(opcode, header & 0x07, Vec::new());
        if opcode == Opcode::DataV2 {
            packet.peer_id.copy_from_slice(take(&mut body, 3)?);
        }
        if opcode.is_control() || opcode == Opcode::AcknowledgmentV1 {
            packet.local_session_id.copy_from_slice(take(&mut body, 8)?);
            let acknowledgment_count = take(&mut body, 1)?[0] as usize;
            packet.acknowledgment_ids.reserve(acknowledgment_count);
            for _ in 0..acknowledgment_count {
                packet.acknowledgment_ids.push(u32::from_be_bytes(
                    take(&mut body, 4)?.try_into().unwrap(),
                ));
            }
            if acknowledgment_count > 0 {
                packet
                    .remote_session_id
                    .copy_from_slice(take(&mut body, 8)?);
            }
            if opcode != Opcode::AcknowledgmentV1 {
                packet.id =
                    u32::from_be_bytes(take(&mut body, 4)?.try_into().unwrap());
            }
        }
        packet.payload.extend_from_slice(body);
        Ok(packet)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        let mut output = Vec::with_capacity(1 + self.payload.len() + 32);
        output.push((self.opcode.wire_value() << 3) | (self.key_id & 0x07));
        if self.opcode == Opcode::DataV2 {
            output.extend_from_slice(&self.peer_id);
        } else if self.opcode.is_control()
            || self.opcode == Opcode::AcknowledgmentV1
        {
            output.extend_from_slice(&self.local_session_id);
            let count = u8::try_from(self.acknowledgment_ids.len())
                .map_err(|_| PacketError::TooManyAcknowledgments)?;
            output.push(count);
            for id in &self.acknowledgment_ids {
                output.extend_from_slice(&id.to_be_bytes());
            }
            if count > 0 {
                output.extend_from_slice(&self.remote_session_id);
            }
            if self.opcode != Opcode::AcknowledgmentV1 {
                output.extend_from_slice(&self.id.to_be_bytes());
            }
        }
        output.extend_from_slice(&self.payload);
        Ok(output)
    }
}

fn take<'a>(
    input: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], PacketError> {
    if input.len() < length {
        return Err(PacketError::TooShort);
    }
    let (value, remaining) = input.split_at(length);
    *input = remaining;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("OpenVPN packet too short")]
    TooShort,
    #[error("too many OpenVPN acknowledgments")]
    TooManyAcknowledgments,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_packet_shapes_round_trip() {
        let mut control =
            Packet::new(Opcode::ControlV1, 7, b"control".to_vec());
        control.local_session_id = *b"local-id";
        control.remote_session_id = *b"remoteid";
        control.acknowledgment_ids = vec![1, u32::MAX];
        control.id = 42;
        assert_eq!(Packet::parse(&control.encode().unwrap()).unwrap(), control);

        let mut ack = Packet::new(Opcode::AcknowledgmentV1, 2, Vec::new());
        ack.local_session_id = *b"local-id";
        ack.remote_session_id = *b"remoteid";
        ack.acknowledgment_ids = vec![17];
        assert_eq!(Packet::parse(&ack.encode().unwrap()).unwrap(), ack);

        let mut data = Packet::new(Opcode::DataV2, 9, b"ip packet".to_vec());
        data.peer_id = [0x01, 0x02, 0x03];
        let encoded = data.encode().unwrap();
        assert_eq!(encoded[0] & 7, 1, "key id is restricted to three bits");
        data.key_id = 1;
        assert_eq!(Packet::parse(&encoded).unwrap(), data);
    }

    #[test]
    fn rejects_truncated_and_unknown_packets() {
        assert_eq!(Packet::parse(&[]), Err(PacketError::TooShort));
        let unknown = Packet::parse(&[31 << 3, 1, 2]).unwrap();
        assert_eq!(unknown.opcode, Opcode::Unknown(31));
        assert_eq!(unknown.payload, [1, 2]);
        let input = [Opcode::ControlV1.wire_value() << 3, 0, 1];
        assert_eq!(Packet::parse(&input), Err(PacketError::TooShort));
    }
}
