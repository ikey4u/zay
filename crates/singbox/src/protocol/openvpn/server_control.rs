use super::{
    CipherNegotiationError, LEGACY_PULL_REQUEST_PAYLOAD, PUSH_REQUEST_PAYLOAD,
    PushedOptions, ServerPushAssignment, TlsControlDirective,
    build_auth_failed_payload, build_server_push_reply_payloads,
    classify_tls_control_directive, normalize_tls_control_message,
    tls_control_string_payload,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerControlOptions {
    pub peer_info: String,
    pub selected_cipher: String,
    pub pushed_options: PushedOptions,
    pub assignment: ServerPushAssignment,
    pub authentication_failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerControlEvent {
    Ignored,
    PushReply {
        payloads: Vec<Vec<u8>>,
        first_connection: bool,
    },
    AuthenticationRejected {
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct ServerControlMachine {
    options: ServerControlOptions,
    connected: bool,
}

impl ServerControlMachine {
    pub fn new(options: ServerControlOptions) -> Self {
        Self {
            options,
            connected: false,
        }
    }

    pub fn connected(&self) -> bool {
        self.connected
    }

    pub fn accept_record(
        &mut self,
        control_record: &[u8],
    ) -> Result<ServerControlEvent, ServerControlError> {
        if classify_tls_control_directive(control_record)
            == TlsControlDirective::Exit
        {
            return Err(ServerControlError::PeerExit);
        }
        let message = normalize_tls_control_message(control_record);
        if !message.eq_ignore_ascii_case(PUSH_REQUEST_PAYLOAD)
            && !message.eq_ignore_ascii_case(LEGACY_PULL_REQUEST_PAYLOAD)
        {
            return Ok(ServerControlEvent::Ignored);
        }
        if let Some(reason) = &self.options.authentication_failure {
            return Ok(ServerControlEvent::AuthenticationRejected {
                payload: tls_control_string_payload(
                    &build_auth_failed_payload(reason),
                ),
            });
        }
        let payloads = build_server_push_reply_payloads(
            &self.options.pushed_options,
            &self.options.peer_info,
            &self.options.selected_cipher,
            &self.options.assignment,
        )?
        .into_iter()
        .map(|payload| tls_control_string_payload(&payload))
        .collect();
        let first_connection = !self.connected;
        self.connected = true;
        Ok(ServerControlEvent::PushReply {
            payloads,
            first_connection,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerControlError {
    #[error("OpenVPN peer exited")]
    PeerExit,
    #[error(transparent)]
    PushReply(#[from] CipherNegotiationError),
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use super::*;
    use crate::protocol::openvpn::{
        OpenVpnIpPrefix, PushedLocalAddress, TLS_IV_PROTO_CC_EXIT_NOTIFY,
        TLS_IV_PROTO_DATA_V2, TLS_IV_PROTO_TLS_KEY_EXPORT,
        decode_push_reply_payload_with_filters,
    };

    fn options() -> ServerControlOptions {
        ServerControlOptions {
            peer_info: format!(
                "IV_CIPHERS=AES-128-GCM:AES-256-GCM\nIV_MTU=1500\nIV_PROTO={}\n",
                TLS_IV_PROTO_DATA_V2
                    | TLS_IV_PROTO_CC_EXIT_NOTIFY
                    | TLS_IV_PROTO_TLS_KEY_EXPORT
            ),
            selected_cipher: "AES-128-GCM".into(),
            pushed_options: PushedOptions {
                tun_mtu: 1400,
                ping_interval: Duration::from_secs(10),
                ping_interval_enabled: true,
                ..PushedOptions::default()
            },
            assignment: ServerPushAssignment {
                local_address_ipv4: Some(PushedLocalAddress {
                    prefix: OpenVpnIpPrefix {
                        address: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
                        prefix_len: 24,
                    },
                    peer: None,
                    raw: String::new(),
                }),
                ipv4_topology: "subnet".into(),
                server_ipv4: Some(Ipv4Addr::new(10, 8, 0, 1)),
                peer_id: Some(7),
                ..ServerPushAssignment::default()
            },
            authentication_failure: None,
        }
    }

    #[test]
    fn answers_modern_and_legacy_pull_requests() {
        let mut machine = ServerControlMachine::new(options());
        for (index, request) in
            [b"PUSH_REQUEST\0".as_slice(), b"pull_request\0"]
                .into_iter()
                .enumerate()
        {
            let ServerControlEvent::PushReply {
                payloads,
                first_connection,
            } = machine.accept_record(request).unwrap()
            else {
                panic!("expected push reply");
            };
            assert_eq!(first_connection, index == 0);
            assert_eq!(payloads.len(), 1);
            let (pushed, _) =
                decode_push_reply_payload_with_filters(&payloads[0], None, &[])
                    .unwrap();
            assert_eq!(pushed.selected_cipher, "AES-128-GCM");
            assert_eq!(pushed.peer_id, Some(7));
            assert_eq!(pushed.route_gateway, Some("10.8.0.1".parse().unwrap()));
            assert_eq!(pushed.protocol_flags, vec!["cc-exit", "tls-ekm"]);
        }
        assert!(machine.connected());
    }

    #[test]
    fn delays_auth_failure_until_the_push_request() {
        let mut options = options();
        options.authentication_failure = Some("invalid credentials".into());
        let mut machine = ServerControlMachine::new(options);
        assert_eq!(
            machine.accept_record(b"INFO,message\0").unwrap(),
            ServerControlEvent::Ignored
        );
        assert_eq!(
            machine.accept_record(b"PUSH_REQUEST\0").unwrap(),
            ServerControlEvent::AuthenticationRejected {
                payload: b"AUTH_FAILED,invalid credentials\0".to_vec()
            }
        );
        assert!(!machine.connected());
    }

    #[test]
    fn reports_peer_exit() {
        assert_eq!(
            ServerControlMachine::new(options())
                .accept_record(b"EXIT\0")
                .unwrap_err(),
            ServerControlError::PeerExit
        );
    }
}
