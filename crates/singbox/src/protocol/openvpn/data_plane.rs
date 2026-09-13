use std::sync::Arc;

use super::{
    CompressionError, DataChannelFraming, OPENVPN_DATA_CHANNEL_PING_PAYLOAD,
    OPENVPN_OCC_EXIT, OPENVPN_OCC_MAGIC, OPENVPN_OCC_REQUEST, Opcode,
    OpenVpnDataCodec, OpenVpnDataCodecError, Packet, PacketError, SessionError,
    SessionManager, build_occ_response_for_incoming, occ_opcode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingDataEvent {
    Payload(Vec<u8>),
    Ping,
    Exit,
    OccResponse(Vec<u8>),
    FragmentPending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedDataPacket {
    pub raw_packet: Vec<u8>,
    pub key_id: u8,
    pub packet_id: u32,
    /// OpenVPN's AEAD usage accounting includes the encrypted payload and the
    /// authenticated Data-v2 header prefix.
    pub aead_block_bytes: usize,
    pub accounted_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedDataEvent {
    pub event: IncomingDataEvent,
    pub key_id: u8,
    pub packet_id: u32,
    /// Plaintext length immediately after decryption and before framing.
    pub aead_plaintext_bytes: usize,
    pub accounted_bytes: usize,
}

pub struct TlsDataPlane {
    session: Arc<SessionManager>,
    codec: Box<dyn OpenVpnDataCodec>,
    framing: Option<DataChannelFraming>,
    peer_id: Option<u32>,
    local_options_string: String,
}

impl TlsDataPlane {
    pub fn new(
        session: Arc<SessionManager>,
        codec: Box<dyn OpenVpnDataCodec>,
        framing: Option<DataChannelFraming>,
        peer_id: Option<u32>,
        local_options_string: String,
    ) -> Self {
        Self {
            session,
            codec,
            framing,
            peer_id: peer_id.map(|value| value & 0x00ff_ffff),
            local_options_string,
        }
    }

    pub fn peer_id(&self) -> Option<u32> {
        self.peer_id
    }

    pub fn session(&self) -> &Arc<SessionManager> {
        &self.session
    }

    pub fn set_peer_id(&mut self, peer_id: Option<u32>) {
        self.peer_id = peer_id.map(|value| value & 0x00ff_ffff);
    }

    pub fn encode_payload(
        &self,
        payload: &[u8],
        fragment_size: usize,
    ) -> Result<Vec<Vec<u8>>, DataPlaneError> {
        Ok(self
            .encode_payload_with_metadata(payload, fragment_size)?
            .into_iter()
            .map(|packet| packet.raw_packet)
            .collect())
    }

    pub fn encode_payload_with_metadata(
        &self,
        payload: &[u8],
        fragment_size: usize,
    ) -> Result<Vec<EncodedDataPacket>, DataPlaneError> {
        let framed = match &self.framing {
            Some(framing) => framing.encode(payload, fragment_size)?,
            None => vec![payload.to_vec()],
        };
        let opcode = if self.peer_id.is_some() {
            Opcode::DataV2
        } else {
            Opcode::DataV1
        };
        let packet_ids =
            self.session.new_data_packet_ids(opcode, framed.len())?;
        framed
            .into_iter()
            .zip(packet_ids)
            .map(|(payload, packet_id)| {
                let key_id = self.session.current_key_id();
                let mut packet = Packet::new(opcode, key_id, Vec::new());
                if let Some(peer_id) = self.peer_id {
                    packet.peer_id.copy_from_slice(&peer_id.to_be_bytes()[1..]);
                }
                let aad = data_v2_aad(&packet);
                packet.payload =
                    self.codec.encode(packet_id, &aad, &payload)?;
                let aead_block_bytes = packet.payload.len() + aad.len();
                let raw_packet = packet.encode()?;
                let accounted_bytes = raw_packet.len();
                Ok(EncodedDataPacket {
                    raw_packet,
                    key_id,
                    packet_id,
                    aead_block_bytes,
                    accounted_bytes,
                })
            })
            .collect()
    }

    pub fn decode_packet(
        &self,
        packet: &Packet,
    ) -> Result<IncomingDataEvent, DataPlaneError> {
        Ok(self.decode_packet_with_metadata(packet)?.event)
    }

    pub fn decode_packet_with_metadata(
        &self,
        packet: &Packet,
    ) -> Result<DecodedDataEvent, DataPlaneError> {
        if !packet.opcode.is_data()
            || packet.key_id != self.session.current_key_id()
        {
            return Err(DataPlaneError::WrongKeyState);
        }
        if packet.opcode == Opcode::DataV2
            && self.peer_id.is_some_and(|peer_id| {
                peer_id.to_be_bytes()[1..] != packet.peer_id
            })
        {
            return Err(DataPlaneError::WrongPeerId);
        }
        let aad = data_v2_aad(packet);
        let (packet_id, decrypted) =
            self.codec.decode(&aad, &packet.payload)?;
        let aead_plaintext_bytes = decrypted.len();
        let payload = match &self.framing {
            Some(framing) => match framing.decode(&decrypted)? {
                Some(payload) => payload,
                None => {
                    return Ok(DecodedDataEvent {
                        event: IncomingDataEvent::FragmentPending,
                        key_id: packet.key_id,
                        packet_id,
                        aead_plaintext_bytes,
                        accounted_bytes: packet.payload.len(),
                    });
                }
            },
            None => decrypted,
        };
        let event = if payload == OPENVPN_DATA_CHANNEL_PING_PAYLOAD {
            IncomingDataEvent::Ping
        } else if occ_opcode(&payload) == Some(OPENVPN_OCC_EXIT) {
            IncomingDataEvent::Exit
        } else if payload.starts_with(&OPENVPN_OCC_MAGIC)
            && occ_opcode(&payload) == Some(OPENVPN_OCC_REQUEST)
            && let Some(response) = build_occ_response_for_incoming(
                &payload,
                &self.local_options_string,
            )
        {
            IncomingDataEvent::OccResponse(response)
        } else {
            IncomingDataEvent::Payload(payload)
        };
        Ok(DecodedDataEvent {
            event,
            key_id: packet.key_id,
            packet_id,
            aead_plaintext_bytes,
            accounted_bytes: packet.payload.len(),
        })
    }

    pub fn decode_raw_packet(
        &self,
        raw_packet: &[u8],
    ) -> Result<IncomingDataEvent, DataPlaneError> {
        self.decode_packet(&Packet::parse(raw_packet)?)
    }
}

fn data_v2_aad(packet: &Packet) -> Vec<u8> {
    if packet.opcode != Opcode::DataV2 {
        return Vec::new();
    }
    vec![
        (packet.opcode.wire_value() << 3) | (packet.key_id & 0x07),
        packet.peer_id[0],
        packet.peer_id[1],
        packet.peer_id[2],
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum DataPlaneError {
    #[error(transparent)]
    Codec(#[from] OpenVpnDataCodecError),
    #[error(transparent)]
    Framing(#[from] CompressionError),
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("OpenVPN data packet belongs to another key-state")]
    WrongKeyState,
    #[error("OpenVPN data-v2 packet has the wrong peer-id")]
    WrongPeerId,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::protocol::openvpn::{
        AllowCompressionPolicy, CompressionAlgorithm, CompressionSettings,
        new_tls_data_codec,
    };

    fn planes(peer_id: Option<u32>) -> (TlsDataPlane, TlsDataPlane) {
        let key_material: Vec<u8> = (0..=255).collect();
        let client_session =
            Arc::new(SessionManager::with_local_id(*b"clientid"));
        let server_session =
            Arc::new(SessionManager::with_local_id(*b"serverid"));
        let framing = || {
            DataChannelFraming::new(
                CompressionSettings {
                    algorithm: CompressionAlgorithm::StubV2,
                    ..CompressionSettings::default()
                },
                64,
                AllowCompressionPolicy::StubOnly,
            )
        };
        (
            TlsDataPlane::new(
                client_session,
                new_tls_data_codec(
                    &key_material,
                    false,
                    "AES-256-GCM",
                    "SHA1",
                    64,
                    Duration::from_secs(15),
                )
                .unwrap(),
                framing(),
                peer_id,
                "client-options".into(),
            ),
            TlsDataPlane::new(
                server_session,
                new_tls_data_codec(
                    &key_material,
                    true,
                    "AES-256-GCM",
                    "SHA1",
                    64,
                    Duration::from_secs(15),
                )
                .unwrap(),
                framing(),
                peer_id,
                "server-options".into(),
            ),
        )
    }

    #[test]
    fn data_v2_round_trips_encryption_peer_id_and_fragmentation() {
        let (client, server) = planes(Some(0x76_70_6e));
        let payload = vec![0x45; 300];
        let packets = client.encode_payload(&payload, 80).unwrap();
        assert!(packets.len() > 1);
        let mut final_event = IncomingDataEvent::FragmentPending;
        for raw in packets {
            final_event = server.decode_raw_packet(&raw).unwrap();
        }
        assert_eq!(final_event, IncomingDataEvent::Payload(payload));
    }

    #[test]
    fn handles_ping_exit_and_occ_request_after_data_framing() {
        let (client, server) = planes(None);
        let ping = client
            .encode_payload(&OPENVPN_DATA_CHANNEL_PING_PAYLOAD, 1500)
            .unwrap();
        assert_eq!(
            server.decode_raw_packet(&ping[0]).unwrap(),
            IncomingDataEvent::Ping
        );
        let mut exit = OPENVPN_OCC_MAGIC.to_vec();
        exit.push(OPENVPN_OCC_EXIT);
        let exit = client.encode_payload(&exit, 1500).unwrap();
        assert_eq!(
            server.decode_raw_packet(&exit[0]).unwrap(),
            IncomingDataEvent::Exit
        );
        let mut request = OPENVPN_OCC_MAGIC.to_vec();
        request.push(OPENVPN_OCC_REQUEST);
        request.extend_from_slice(b"peer-options\0");
        let request = client.encode_payload(&request, 1500).unwrap();
        assert!(matches!(
            server.decode_raw_packet(&request[0]).unwrap(),
            IncomingDataEvent::OccResponse(_)
        ));
    }

    #[test]
    fn rejects_wrong_data_v2_peer_id_before_decryption() {
        let (client, server) = planes(Some(1));
        let mut packet =
            Packet::parse(&client.encode_payload(b"payload", 1500).unwrap()[0])
                .unwrap();
        packet.peer_id = [0, 0, 2];
        assert!(matches!(
            server.decode_packet(&packet),
            Err(DataPlaneError::WrongPeerId)
        ));
    }

    #[test]
    fn exposes_wire_accounting_and_packet_ids_for_renegotiation() {
        let (client, server) = planes(Some(0x76_70_6e));
        let encoded =
            client.encode_payload_with_metadata(b"hello", 1500).unwrap();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0].key_id, 0);
        assert_eq!(encoded[0].packet_id, 1);
        assert_eq!(encoded[0].accounted_bytes, encoded[0].raw_packet.len());
        assert!(encoded[0].aead_block_bytes > 5);

        let packet = Packet::parse(&encoded[0].raw_packet).unwrap();
        let decoded = server.decode_packet_with_metadata(&packet).unwrap();
        assert_eq!(
            decoded.event,
            IncomingDataEvent::Payload(b"hello".to_vec())
        );
        assert_eq!(decoded.key_id, 0);
        assert_eq!(decoded.packet_id, 1);
        assert!(decoded.aead_plaintext_bytes >= 5);
        assert_eq!(decoded.accounted_bytes, packet.payload.len());
    }
}
