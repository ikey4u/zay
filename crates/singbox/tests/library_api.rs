use std::{
    fs,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::Message,
    rr::{Name, RData, Record, rdata::A},
};
use singbox::{
    ConfigLoader, NeighborResolver, ProcessInfo, ProcessResolver, Runtime,
    RuntimeHost,
    common::{
        certificate_store::CertificateStore,
        keygen::{
            generate_ech_keypair, generate_reality_keypair,
            generate_tls_keypair, generate_vapid_keypair,
            generate_wireguard_keypair,
        },
        network::Network,
        ntp::{NtpClock, NtpSample, SystemClockWriter},
        tls::{
            EchConfigRecord, EchConfigResolver, build_client_config_with_clock,
            build_client_config_with_ech_resolver,
        },
    },
    dns::tailscale::{TailscaleNetmapProvider, TailscaleResolver},
    dns_response_addresses,
    endpoint::tailscale::{
        TAILSCALE_CAPABILITY_VERSION, TailscaleEndpointDialer,
        TailscaleEndpointEvent, TailscaleEndpointHandle,
        TailscaleEndpointPhase, TailscaleEndpointService,
        TailscaleEndpointStatus, TailscaleUserspaceDialer,
        TailscaleUserspaceNetwork, TailscaleUserspaceNetworkConfig,
    },
    option::{
        CertificateOptions, CertificateStoreKind, CloudflaredInboundOptions,
        DirectOutboundOptions, HttpClientOptions, InboundTlsOptions, Listable,
        Options, OutboundEchOptions, OutboundTlsOptions, RouteOptions,
        TailscaleCertificateProviderOptions, TailscaleEndpointOptions,
    },
    outbound::OutboundManager,
    protocol::{
        cloudflared::{
            CLOUDFLARED_DATA_STREAM_SIGNATURE,
            CLOUDFLARED_DEFAULT_DATAGRAM_VERSION, CLOUDFLARED_PROTOCOL_VERSION,
            CloudflaredConfigurationApplier, CloudflaredConfigurationUpdate,
            CloudflaredIncomingDatagramVersion, CloudflaredIncomingRpcServer,
            CloudflaredProtocolSelection, CloudflaredRegistrationClient,
            CloudflaredRegistrationOptions, CloudflaredRegistrationResult,
            CloudflaredRpcSystem, CloudflaredTransportProtocol,
            CloudflaredUdpRegistration, CloudflaredUdpSessionHandler,
            cloudflared_data_stream_prefix, cloudflared_incoming_rpc,
            cloudflared_registration_rpc, parse_cloudflared_token,
        },
        cloudflared_access::{
            CLOUDFLARED_ACCESS_JWKS_PATH,
            CLOUDFLARED_ACCESS_JWT_ASSERTION_HEADER,
            CLOUDFLARED_ACCESS_MAX_JWKS_SIZE, CloudflaredAccessValidator,
            cloudflared_access_issuer_url, cloudflared_access_validator_key,
        },
        cloudflared_datagram::{
            CLOUDFLARED_DATAGRAM_V2_QUEUE_SIZE,
            CLOUDFLARED_DATAGRAM_V3_QUEUE_SIZE,
            CLOUDFLARED_V3_RESPONSE_DESTINATION_UNREACHABLE,
            CLOUDFLARED_V3_RESPONSE_ERROR_WITH_MESSAGE,
            CLOUDFLARED_V3_RESPONSE_OK,
            CLOUDFLARED_V3_RESPONSE_TOO_MANY_ACTIVE_FLOWS,
            CLOUDFLARED_V3_RESPONSE_UNABLE_TO_BIND_SOCKET,
            CloudflaredDatagramService, CloudflaredDatagramTransport,
        },
        cloudflared_factory::{
            CLOUDFLARED_EDGE_TLS_HANDSHAKE_TIMEOUT,
            CLOUDFLARED_POST_QUANTUM_FEATURE, CLOUDFLARED_ROOT_CA_PEM,
            CloudflaredEdgeConnectionFactory, CloudflaredEdgeTlsConfigs,
            cloudflared_edge_tls_configs,
        },
        cloudflared_http2::{
            CLOUDFLARED_H2_CONTENT_TYPE_GRPC,
            CLOUDFLARED_H2_CONTENT_TYPE_NDJSON,
            CLOUDFLARED_H2_CONTENT_TYPE_SSE, CLOUDFLARED_H2_RESPONSE_META_EDGE,
            CloudflaredHttp2Connection, CloudflaredHttp2Handler,
            CloudflaredHttp2RequestKind, CloudflaredHttp2ResponseHead,
            CloudflaredHttp2ResponseWriter, CloudflaredHttp2Stream,
            classify_cloudflared_http2_request,
            cloudflared_http2_method_is_bodyless,
            cloudflared_http2_should_flush_headers,
            decode_cloudflared_http2_configuration,
            decode_cloudflared_http2_connect_request,
            encode_cloudflared_http2_configuration_response,
            encode_cloudflared_http2_response_head,
        },
        cloudflared_icmp::{
            CLOUDFLARED_ICMP_FLOW_TIMEOUT,
            CLOUDFLARED_ICMP_IPV4_TTL_QUOTE_LENGTH,
            CLOUDFLARED_ICMP_IPV6_TTL_QUOTE_LENGTH,
            CLOUDFLARED_ICMP_MAX_PAYLOAD_LENGTH,
            CLOUDFLARED_ICMP_TRACE_IDENTITY_LENGTH, CloudflaredIcmpBridge,
            CloudflaredIcmpPacket, parse_cloudflared_icmp_packet,
        },
        cloudflared_ingress::{
            CLOUDFLARED_DEFAULT_HTTP_CONNECT_TIMEOUT,
            CLOUDFLARED_DEFAULT_KEEP_ALIVE_CONNECTIONS,
            CLOUDFLARED_DEFAULT_WARP_CONNECT_TIMEOUT, CloudflaredAccessConfig,
            CloudflaredConfigManager, CloudflaredIngressRule,
            CloudflaredIpRule, CloudflaredIpRulePolicy,
            CloudflaredLocalIngressRule, CloudflaredOriginRequestConfig,
            CloudflaredResolvedService, CloudflaredResolvedServiceKind,
            CloudflaredRuntimeConfig, CloudflaredWarpRoutingConfig,
            build_cloudflared_remote_config, compile_cloudflared_ingress_rules,
            match_cloudflared_ingress_host, match_cloudflared_ingress_rule,
            parse_cloudflared_resolved_service,
        },
        cloudflared_origin::CloudflaredOriginService,
        cloudflared_quic::{
            CLOUDFLARED_QUIC_HANDSHAKE_IDLE_TIMEOUT,
            CLOUDFLARED_QUIC_KEEP_ALIVE_INTERVAL,
            CLOUDFLARED_QUIC_MAX_IDLE_TIMEOUT,
            CLOUDFLARED_REGISTRATION_TIMEOUT, CloudflaredQuicDatagramSender,
            CloudflaredQuicEdge, CloudflaredQuicEvent, CloudflaredQuicHandler,
            CloudflaredQuicSession, CloudflaredQuicStream,
            cloudflared_quic_initial_packet_size,
            cloudflared_quic_transport_config,
        },
        cloudflared_supervisor::{
            CLOUDFLARED_FIRST_CONNECTION_READY_TIMEOUT,
            CLOUDFLARED_PROTOCOL_RETRY_LIMIT, CLOUDFLARED_RETRY_BASE,
            CLOUDFLARED_RETRY_MAX, CloudflaredConnectionAttempt,
            CloudflaredConnectionFactory, CloudflaredHaSupervisor,
            CloudflaredManagedConnection, CloudflaredQuicManagedConnection,
            CloudflaredSupervisorEvent, cloudflared_initial_edge_index,
            cloudflared_quic_is_broken, cloudflared_retry_backoff,
            cloudflared_rotate_edge_index,
        },
        direct::DirectOutbound,
        hysteria2_realm::RealmControlClient,
        openconnect::{
            AnyConnectAuthClientIdentity, AnyConnectAuthHttpClient,
            AnyConnectAuthHttpTransport, AnyConnectAuthPrefillOptions,
            AnyConnectAuthRawHttpResponse, AnyConnectAuthenticationProgress,
            AnyConnectAuthenticator, AnyConnectAuthenticatorOptions,
            AnyConnectCredentialCache, AnyConnectDataChannel,
            AnyConnectDtlsChannel, AnyConnectDtlsChannelError,
            AnyConnectDtlsTransport, CertificateDtlsClientOptions,
            FortinetAuthenticator, NetworkConnectTnccIdentity,
            OpenConnectEspAuthentication, OpenConnectEspEncryption,
            OpenConnectEspKeyMaterial, OpenConnectEspKeySet,
            OpenConnectEspKeySetConfig, OpenConnectEspProbe,
            PppDatagramSessionOptions, PppEncapsulation, PppNegotiator,
            PppNegotiatorOptions, PulseChallengeParser,
            PulseConfigurationAccumulator, PulseIftEncoder,
            build_anyconnect_initial_xml, build_fortinet_dtls_connect_request,
            build_globalprotect_hip_check_body, build_globalprotect_hip_token,
            build_network_connect_tncc_initial_message,
            build_pulse_upgrade_request, complete_anyconnect_auth_form,
            encode_network_connect_oncp_authentication_packet,
            encode_network_connect_oncp_kmp, encode_ppp_frame,
            parse_anyconnect_authentication_xml, parse_fortinet_token_info,
            parse_fortinet_xml_configuration,
            parse_network_connect_authentication_document,
            parse_network_connect_oncp_kmp, prepare_anyconnect_auth_form,
        },
        tailscale::{
            TAILSCALE_DERP_FRAME_PING, TailscaleDerpClient,
            TailscaleDerpClientInfo, TailscaleDerpConnectOptions,
            TailscaleDerpFrame, TailscaleDerpReceivedMessage,
            TailscaleDerpSession, build_tailscale_derp_http_upgrade_request,
            encode_tailscale_derp_frame, parse_tailscale_derp_received_message,
            tailscale_node_public_key,
        },
        tailscale_control::{
            TAILSCALE_CONTROL_UPGRADE_PROTOCOL, TailscaleControlHandshake,
            TailscaleControlHttp2Client, TailscaleMapFrameDecoder,
        },
        tailscale_control_supervisor::{
            TailscaleControlBootstrap, TailscaleControlConnector,
            TailscaleControlMapStream, TailscaleControlSession,
            TailscaleControlSupervisor, TailscaleControlSupervisorEvent,
            TailscaleControlSupervisorOptions,
            TailscaleControlSupervisorStatus, TailscaleHttp2ControlSession,
            TailscaleNetmapConsumer, TailscaleTkaSynchronizer,
            TailscaleTs2021DialConnector, bootstrap_tailscale_control,
            build_tailscale_control_connector,
        },
        tailscale_control_types::{
            TAILSCALE_MAP_PATH, TAILSCALE_REGISTER_PATH,
            TAILSCALE_SET_DNS_PATH, TAILSCALE_TKA_BOOTSTRAP_PATH,
            TAILSCALE_TKA_SYNC_OFFER_PATH, TAILSCALE_TKA_SYNC_SEND_PATH,
            TailscaleDnsConfig, TailscaleFilterRule, TailscaleMapRequest,
            TailscaleMapResponse, TailscaleNetmapState, TailscaleNode,
            TailscaleNodePublicKey, TailscaleRegisterRequest,
            TailscaleSetDnsRequest, TailscaleSshPolicy,
            TailscaleTkaBootstrapRequest, TailscaleTkaSyncOfferRequest,
            TailscaleTkaSyncSendRequest,
        },
        tailscale_derp_manager::{
            TAILSCALE_DERP_CLEAN_STALE_INTERVAL,
            TAILSCALE_DERP_INACTIVE_CLEANUP_TIME, TailscaleDerpManager,
            TailscaleDerpManagerEvent, TailscaleDerpManagerOptions,
            TailscaleDerpManagerStatus,
        },
        tailscale_derp_map::{
            TailscaleDerpMapController, TailscaleDerpMapError,
            TailscaleRoutePolicy, build_tailscale_derp_connector,
        },
        tailscale_derp_supervisor::{
            TailscaleDerpConnector, TailscaleDerpRegionEvent,
            TailscaleDerpRegionStatus, TailscaleDerpRegionSupervisor,
            TailscaleDerpRegionSupervisorOptions,
        },
        tailscale_disco::{
            TAILSCALE_DISCO_MAGIC, TailscaleDiscoMessage, TailscaleDiscoPing,
            encode_tailscale_disco_message, tailscale_disco_public_key,
        },
        tailscale_disco_socket::{
            TailscaleDiscoPeer, TailscaleDiscoSocket,
            TailscaleDiscoSocketHandle, TailscaleDiscoSocketOptions,
            TailscaleDiscoSocketStatus, TailscalePacketSendOutcome,
        },
        tailscale_netcheck::{
            TAILSCALE_PORT_MAPPING_LIFETIME, TAILSCALE_PORT_MAPPING_TIMEOUT,
            TAILSCALE_RESTUN_INTERVAL, TAILSCALE_STUN_MAXIMUM_SERVERS,
            TAILSCALE_STUN_PROBE_TIMEOUT, TailscaleDiscoveredEndpoint,
            TailscaleEndpointType, TailscaleNetcheckReport,
            TailscalePortMapping, discover_tailscale_endpoints,
        },
        tailscale_path::{
            TAILSCALE_PATH_TRUST_DURATION, TailscalePathQuality,
            TailscalePeerPathState,
        },
        tailscale_ssh::{
            TAILSCALE_CAPABILITY_SSH_ENVIRONMENT_VARIABLES,
            TAILSCALE_SSH_DELEGATE_RESPONSE_LIMIT,
            TAILSCALE_SSH_DELEGATION_TIMEOUT, TAILSCALE_SSH_HOST_KEY_FILE_NAME,
            TAILSCALE_SSH_MAXIMUM_DELEGATION_HOPS, TailscaleSshAuthorization,
            TailscaleSshConnectionHandler, TailscaleSshControlDelegateClient,
            TailscaleSshCurrentUserProcessBackend, TailscaleSshDelegateClient,
            TailscaleSshDelegateContext, TailscaleSshDelegationError,
            TailscaleSshHostKeyError, TailscaleSshPeerIdentity,
            TailscaleSshPolicyDecision, TailscaleSshPolicyError,
            TailscaleSshPtyRequest, TailscaleSshRecordingNotifier,
            TailscaleSshServerIdentity, TailscaleSshSessionBackend,
            TailscaleSshSessionEvent, TailscaleSshSessionKind,
            TailscaleSshSessionRequest, clamp_tailscale_ssh_window_dimension,
            evaluate_tailscale_ssh_policy, expand_tailscale_ssh_delegate_url,
            is_dangerous_tailscale_ssh_environment,
            load_or_generate_tailscale_ssh_server_identity,
            match_tailscale_ssh_user, resolve_tailscale_ssh_delegation,
            serve_tailscale_ssh_connection, tailscale_ssh_environment_accepted,
            tailscale_ssh_peer_identity, tailscale_ssh_sftp_server_path,
        },
        tailscale_ssh_recording::{
            TAILSCALE_SSH_RECORDER_ACK_TIMEOUT,
            TAILSCALE_SSH_RECORDER_ALL_ATTEMPTS_TIMEOUT,
            TAILSCALE_SSH_RECORDER_DIAL_TIMEOUT,
            TAILSCALE_SSH_RECORDER_V2_PROBE_TIMEOUT, TailscaleSshCastHeader,
            TailscaleSshOutputRecording, TailscaleSshRecordingAttempt,
            TailscaleSshRecordingError, TailscaleSshRecordingEventType,
            TailscaleSshRecordingNotification, TailscaleSshRecordingUpload,
            connect_tailscale_ssh_recorder,
        },
        tailscale_state::{
            TAILSCALE_DEFAULT_CONTROL_URL, TAILSCALE_NODE_FILE_NAME,
            TAILSCALE_TKA_FILE_NAME, TailscaleNodeFile,
            TailscaleNodeKeyRotation, TailscaleNodeStateStore,
            TailscalePrivateKey, TailscaleStateError, TailscaleTkaState,
        },
        tailscale_taildrop::{
            TAILSCALE_PEER_CAPABILITY_FILE_SHARING_SEND,
            TAILSCALE_TAILDROP_BLOCK_SIZE, TAILSCALE_TAILDROP_DELETE_DELAY,
            TAILSCALE_TAILDROP_DELETED_SUFFIX,
            TAILSCALE_TAILDROP_NOTIFICATION_TYPE_ID,
            TAILSCALE_TAILDROP_PARTIAL_SUFFIX, TailscaleTaildropBlockChecksum,
            TailscaleTaildropError, TailscaleTaildropEvent,
            TailscaleTaildropFile, TailscaleTaildropInbox,
            TailscaleTaildropPeerAccess, TailscaleTaildropReceiver,
            TailscaleTaildropReceivingFile, TailscaleTaildropTarget,
            handle_tailscale_taildrop_request, send_tailscale_taildrop_file,
            tailscale_taildrop_targets, validate_tailscale_taildrop_file_name,
        },
        tailscale_tka::{
            TailscaleNetworkLockPrivateKey, TailscaleNodeKeySignature,
            TailscaleTkaError, resign_tailscale_node_key_signature,
        },
        tailscale_tka_authority::{
            TAILSCALE_TKA_COMPACTION_MIN_AGE,
            TAILSCALE_TKA_COMPACTION_MIN_CHAIN, TailscaleAum, TailscaleAumHash,
            TailscaleTkaAuthority, TailscaleTkaAuthorityError,
            TailscaleTkaAuthorityState, TailscaleTkaCompactionOptions,
            TailscaleTkaSyncOffer,
        },
        tailscale_tka_sync::TailscalePersistentTkaSynchronizer,
        tailscale_wireguard::{
            TailscaleWireGuardEngine, TailscaleWireGuardEvent,
            TailscaleWireGuardOptions, TailscaleWireGuardPeer,
            TailscaleWireGuardStatus,
        },
    },
    route::{
        Router, RuleSetMetadata, RuleSetUpdate, RuleSetUpdateValidator,
        SourceRuleSet,
        adguard::{
            convert_rule_set as convert_adguard_rule_set,
            export_rule_set as export_adguard_rule_set,
        },
        compile_rule_set, decompile_rule_set, merge_rule_sets,
    },
    schema::UPSTREAM_SCHEMA_JSON,
};
#[cfg(target_os = "macos")]
use singbox::{
    PlatformNetworkInterface, PlatformNetworkProvider, PlatformSocket,
};

#[cfg(target_os = "macos")]
struct MacosPlatformNetworkProvider;

#[cfg(target_os = "macos")]
impl PlatformNetworkProvider for MacosPlatformNetworkProvider {
    fn network_interfaces(&self) -> io::Result<Vec<PlatformNetworkInterface>> {
        Ok(Vec::new())
    }

    fn bind_socket(
        &self,
        _socket: PlatformSocket,
        _interface: &PlatformNetworkInterface,
    ) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_platform_network_bridge_is_public_library_api() {
    let host = RuntimeHost {
        platform_network_provider: Some(Arc::new(MacosPlatformNetworkProvider)),
        ..RuntimeHost::default()
    };
    assert!(host.platform_network_provider.is_some());
}

#[test]
fn dns_response_addresses_is_public_library_api() {
    let mut response = Message::query();
    response.add_answer(Record::from_rdata(
        Name::from_ascii("example.com.").unwrap(),
        60,
        RData::A(A::new(192, 0, 2, 1)),
    ));
    assert_eq!(
        dns_response_addresses(&response),
        [IpAddr::from([192, 0, 2, 1])]
    );
}

#[test]
fn rule_set_update_surface_is_public_library_api() {
    let router = Router::from_json_with_rule_sets(
        &[],
        "direct",
        &[serde_json::json!({
            "type":"inline",
            "tag":"private",
            "rules":[{"ip_cidr":"10.0.0.0/8"}]
        })],
        std::path::Path::new("."),
    )
    .unwrap();
    let rule_set = router.rule_set("private").unwrap();
    let metadata: RuleSetMetadata = rule_set.metadata();
    assert!(metadata.contains_ip_cidr_rule);
    let updates = rule_set.subscribe();
    let update: RuleSetUpdate = *updates.borrow();
    assert_eq!(update.generation, 0);
    assert_eq!(update.metadata, metadata);

    let validator: std::sync::Arc<dyn RuleSetUpdateValidator> =
        std::sync::Arc::new(|_tag: &str, candidate: RuleSetMetadata| {
            if candidate.contains_dns_query_type_rule {
                Err("query-type mode change rejected".into())
            } else {
                Ok(())
            }
        });
    rule_set.add_update_validator(validator);
    let error = rule_set
        .reload("source", br#"{"version":5,"rules":[{"query_type":"A"}]}"#)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("query-type mode change rejected")
    );
    assert_eq!(rule_set.generation(), 0);

    rule_set
        .reload(
            "source",
            br#"{"version":5,"rules":[{"ip_cidr":"192.0.2.0/24"}]}"#,
        )
        .unwrap();
    assert_eq!(rule_set.generation(), 1);
    assert!(rule_set.metadata().contains_ip_cidr_rule);
}

#[test]
fn tailscale_node_state_is_public_library_api() {
    assert_eq!(
        TAILSCALE_DEFAULT_CONTROL_URL,
        "https://controlplane.tailscale.com"
    );
    assert_eq!(TAILSCALE_NODE_FILE_NAME, "tailscale-node.json");
    assert_eq!(TAILSCALE_TKA_FILE_NAME, "tailscale-tka.json");
    assert_eq!(TAILSCALE_TKA_BOOTSTRAP_PATH, "/machine/tka/bootstrap");
    assert_eq!(TAILSCALE_TKA_SYNC_OFFER_PATH, "/machine/tka/sync/offer");
    assert_eq!(TAILSCALE_TKA_SYNC_SEND_PATH, "/machine/tka/sync/send");
    let private = TailscalePrivateKey::from_bytes([7; 32]).unwrap();
    assert_ne!(private.public_bytes().unwrap(), [0; 32]);
    assert!(std::mem::size_of::<TailscaleNodeFile>() > 0);
    assert!(std::mem::size_of::<TailscaleNodeKeyRotation>() > 0);
    assert!(std::mem::size_of::<TailscaleNodeStateStore>() > 0);
    assert!(std::mem::size_of::<TailscaleStateError>() > 0);
    assert!(std::mem::size_of::<TailscaleTkaState>() > 0);
    assert!(std::mem::size_of::<TailscaleNetworkLockPrivateKey>() > 0);
    assert!(std::mem::size_of::<TailscaleNodeKeySignature>() > 0);
    assert!(std::mem::size_of::<TailscaleTkaError>() > 0);
    assert!(std::mem::size_of::<TailscaleTkaAuthority>() > 0);
    assert!(std::mem::size_of::<TailscaleAum>() > 0);
    assert!(std::mem::size_of::<TailscaleAumHash>() > 0);
    assert!(std::mem::size_of::<TailscaleTkaAuthorityState>() > 0);
    assert!(std::mem::size_of::<TailscaleTkaSyncOffer>() > 0);
    assert!(std::mem::size_of::<TailscaleTkaAuthorityError>() > 0);
    assert_eq!(TAILSCALE_TKA_COMPACTION_MIN_CHAIN, 24);
    assert_eq!(
        TAILSCALE_TKA_COMPACTION_MIN_AGE,
        Duration::from_secs(14 * 24 * 60 * 60)
    );
    let _ = TailscaleTkaCompactionOptions::default();
    assert!(std::mem::size_of::<TailscalePersistentTkaSynchronizer>() > 0);
    assert_eq!(TAILSCALE_SSH_MAXIMUM_DELEGATION_HOPS, 10);
    assert_eq!(TAILSCALE_SSH_DELEGATION_TIMEOUT.as_secs(), 1800);
    assert_eq!(
        TAILSCALE_CAPABILITY_SSH_ENVIRONMENT_VARIABLES,
        "ssh-env-vars"
    );
    assert!(std::mem::size_of::<TailscaleSshPeerIdentity>() > 0);
    assert!(std::mem::size_of::<TailscaleSshAuthorization>() > 0);
    assert!(std::mem::size_of::<TailscaleSshPolicyDecision>() > 0);
    assert!(std::mem::size_of::<TailscaleSshPolicyError>() > 0);
    assert!(std::mem::size_of::<TailscaleSshDelegateContext<'_>>() > 0);
    assert!(std::mem::size_of::<TailscaleSshConnectionHandler>() > 0);
    assert!(std::mem::size_of::<TailscaleSshControlDelegateClient>() > 0);
    assert!(std::mem::size_of::<TailscaleSshServerIdentity>() > 0);
    assert!(std::mem::size_of::<TailscaleSshHostKeyError>() > 0);
    assert!(std::mem::size_of::<TailscaleSshDelegationError>() > 0);
    assert!(std::mem::size_of::<TailscaleSshPtyRequest>() > 0);
    assert!(std::mem::size_of::<TailscaleSshSessionRequest>() > 0);
    assert!(std::mem::size_of::<TailscaleSshSessionKind>() > 0);
    assert!(std::mem::size_of::<TailscaleSshSessionEvent>() > 0);
    assert!(std::mem::size_of::<TailscaleSshCurrentUserProcessBackend>() == 0);
    assert_eq!(TAILSCALE_SSH_DELEGATE_RESPONSE_LIMIT, 1024 * 1024);
    fn accepts_delegate_trait<T: TailscaleSshDelegateClient + ?Sized>() {}
    accepts_delegate_trait::<dyn TailscaleSshDelegateClient>();
    fn accepts_session_trait<T: TailscaleSshSessionBackend + ?Sized>() {}
    accepts_session_trait::<dyn TailscaleSshSessionBackend>();
    fn accepts_recording_notifier<T: TailscaleSshRecordingNotifier + ?Sized>() {
    }
    accepts_recording_notifier::<dyn TailscaleSshRecordingNotifier>();
    assert_eq!(TAILSCALE_SSH_RECORDER_DIAL_TIMEOUT.as_secs(), 5);
    assert_eq!(TAILSCALE_SSH_RECORDER_V2_PROBE_TIMEOUT.as_secs(), 10);
    assert_eq!(TAILSCALE_SSH_RECORDER_ALL_ATTEMPTS_TIMEOUT.as_secs(), 30);
    assert_eq!(TAILSCALE_SSH_RECORDER_ACK_TIMEOUT.as_secs(), 30);
    assert!(std::mem::size_of::<TailscaleSshCastHeader>() > 0);
    assert!(std::mem::size_of::<TailscaleSshRecordingAttempt>() > 0);
    assert!(std::mem::size_of::<TailscaleSshRecordingError>() > 0);
    assert!(std::mem::size_of::<TailscaleSshRecordingEventType>() > 0);
    assert!(std::mem::size_of::<TailscaleSshRecordingNotification>() > 0);
    assert!(std::mem::size_of::<TailscaleSshRecordingUpload>() > 0);
    assert!(std::mem::size_of::<TailscaleSshOutputRecording>() > 0);
    let _ = connect_tailscale_ssh_recorder;
    assert_eq!(TAILSCALE_SSH_HOST_KEY_FILE_NAME, "ssh_host_ed25519_key");
    let _ = evaluate_tailscale_ssh_policy;
    let _ = match_tailscale_ssh_user;
    let _ = tailscale_ssh_environment_accepted;
    let _ = is_dangerous_tailscale_ssh_environment;
    let _ = expand_tailscale_ssh_delegate_url;
    let _ = tailscale_ssh_peer_identity;
    let _ = load_or_generate_tailscale_ssh_server_identity;
    let _ = resolve_tailscale_ssh_delegation;
    let _ = tailscale_ssh_sftp_server_path;
    assert_eq!(clamp_tailscale_ssh_window_dimension(u32::MAX), u16::MAX);
    let _ = serve_tailscale_ssh_connection::<tokio::io::DuplexStream>;
    assert_eq!(TAILSCALE_TAILDROP_BLOCK_SIZE, 64 << 10);
    assert_eq!(TAILSCALE_TAILDROP_PARTIAL_SUFFIX, ".partial");
    assert_eq!(TAILSCALE_TAILDROP_DELETED_SUFFIX, ".deleted");
    assert_eq!(TAILSCALE_TAILDROP_DELETE_DELAY.as_secs(), 3600);
    assert_eq!(
        TAILSCALE_PEER_CAPABILITY_FILE_SHARING_SEND,
        "https://tailscale.com/cap/file-send"
    );
    assert!(std::mem::size_of::<TailscaleTaildropBlockChecksum>() > 0);
    assert!(std::mem::size_of::<TailscaleTaildropError>() > 0);
    assert!(std::mem::size_of::<TailscaleTaildropEvent>() > 0);
    assert_eq!(TAILSCALE_TAILDROP_NOTIFICATION_TYPE_ID, 11);
    assert!(std::mem::size_of::<TailscaleTaildropTarget>() > 0);
    assert!(std::mem::size_of::<TailscaleTaildropFile>() > 0);
    assert!(std::mem::size_of::<TailscaleTaildropReceivingFile>() > 0);
    assert!(std::mem::size_of::<TailscaleTaildropInbox>() > 0);
    assert!(std::mem::size_of::<TailscaleTaildropReceiver>() > 0);
    assert!(std::mem::size_of::<TailscaleTaildropPeerAccess>() > 0);
    let _ = validate_tailscale_taildrop_file_name;
    let _ = tailscale_taildrop_targets;
    let _ = send_tailscale_taildrop_file::<std::io::Cursor<Vec<u8>>>;
    let _ =
        handle_tailscale_taildrop_request::<http_body_util::Full<bytes::Bytes>>;
    let _: Option<&dyn TailscaleTkaSynchronizer> = None;
    let _ = std::mem::size_of::<TailscaleTkaBootstrapRequest>();
    let _ = std::mem::size_of::<TailscaleTkaSyncOfferRequest>();
    let _ = std::mem::size_of::<TailscaleTkaSyncSendRequest>();
    let _resign = resign_tailscale_node_key_signature;
    let _connector_builder = build_tailscale_control_connector;
}

#[test]
fn tailscale_derp_map_is_public_library_api() {
    let _connector_builder = build_tailscale_derp_connector;
    assert!(std::mem::size_of::<TailscaleDerpMapController>() > 0);
    assert!(std::mem::size_of::<TailscaleDerpMapError>() > 0);
    assert!(!TailscaleRoutePolicy::default().accept_routes);
}

#[test]
fn tailscale_netcheck_is_public_library_api() {
    assert_eq!(TAILSCALE_STUN_MAXIMUM_SERVERS, 3);
    assert!(!TAILSCALE_STUN_PROBE_TIMEOUT.is_zero());
    assert_eq!(
        TAILSCALE_RESTUN_INTERVAL,
        std::time::Duration::from_secs(23)
    );
    assert!(!TAILSCALE_PORT_MAPPING_TIMEOUT.is_zero());
    assert!(TAILSCALE_PORT_MAPPING_LIFETIME > TAILSCALE_PORT_MAPPING_TIMEOUT);
    assert_eq!(TailscaleEndpointType::Stun as i32, 2);
    assert!(std::mem::size_of::<TailscaleDiscoveredEndpoint>() > 0);
    assert!(std::mem::size_of::<TailscaleNetcheckReport>() > 0);
    assert!(std::mem::size_of::<TailscalePortMapping>() > 0);
    assert!(std::mem::size_of::<TailscaleDiscoSocketHandle>() > 0);
    let _discover = discover_tailscale_endpoints;
}

#[test]
fn tailscale_configuration_is_public_library_api() {
    let options: TailscaleEndpointOptions =
        serde_json::from_value(serde_json::json!({
            "auth_key": "tskey-auth-test",
            "hostname": "embedded-node",
            "advertise_routes": ["10.0.0.0/8"],
            "ssh_server": true
        }))
        .unwrap();
    options.validate().unwrap();
    assert_eq!(options.hostname, "embedded-node");
    assert!(options.ssh_server.unwrap().enabled);
    let certificate: TailscaleCertificateProviderOptions =
        serde_json::from_value(serde_json::json!({"endpoint": "tailnet"}))
            .unwrap();
    assert_eq!(certificate.endpoint, "tailnet");
}

#[test]
fn tailscale_runtime_endpoint_is_public_library_api() {
    assert_eq!(TAILSCALE_CAPABILITY_VERSION, 142);
    assert_eq!(
        TailscaleEndpointPhase::default(),
        TailscaleEndpointPhase::Stopped
    );
    assert!(std::mem::size_of::<TailscaleEndpointDialer>() > 0);
    assert!(std::mem::size_of::<TailscaleEndpointHandle>() > 0);
    assert!(std::mem::size_of::<TailscaleEndpointService>() > 0);
    assert!(std::mem::size_of::<TailscaleEndpointEvent>() > 0);
    assert!(std::mem::size_of::<TailscaleResolver>() > 0);
    assert_eq!(TailscaleEndpointStatus::default().peers, 0);
    assert!(!TailscaleEndpointStatus::default().node_key_expired);

    fn assert_netmap_provider<T: TailscaleNetmapProvider>() {}
    assert_netmap_provider::<TailscaleEndpointHandle>();

    let _runtime_accessor = Runtime::tailscale_endpoint;
    let _certificate_domains = TailscaleEndpointHandle::certificate_domains;
}

#[test]
fn tailscale_derp_wire_is_public_library_api() {
    assert_eq!(
        encode_tailscale_derp_frame(TAILSCALE_DERP_FRAME_PING, b"12345678", 8,)
            .unwrap(),
        b"\x12\x00\x00\x00\x0812345678"
    );
}

#[test]
fn tailscale_derp_authenticated_session_is_public_library_api() {
    let mut options = TailscaleDerpConnectOptions::new("derp.example:443");
    options.client_info = TailscaleDerpClientInfo {
        can_ack_pings: true,
        ..Default::default()
    };
    assert!(
        build_tailscale_derp_http_upgrade_request(&options, false)
            .unwrap()
            .contains("Upgrade: DERP\r\n")
    );
    assert_ne!(tailscale_node_public_key([1; 32]).unwrap(), [0; 32]);
    assert!(
        std::mem::size_of::<TailscaleDerpClient<tokio::io::DuplexStream>>() > 0
    );
    assert!(std::mem::size_of::<TailscaleDerpSession>() > 0);
    assert_eq!(
        parse_tailscale_derp_received_message(
            [1; 32],
            tailscale_node_public_key([2; 32]).unwrap(),
            TailscaleDerpFrame {
                frame_type: singbox::protocol::tailscale::TAILSCALE_DERP_FRAME_KEEP_ALIVE,
                payload: Vec::new(),
            },
        )
        .unwrap(),
        Some(TailscaleDerpReceivedMessage::KeepAlive)
    );
}

#[test]
fn tailscale_peer_path_state_is_public_library_api() {
    let now = Instant::now();
    let endpoint = "203.0.113.8:41641".parse().unwrap();
    let mut paths = TailscalePeerPathState::new(Some(7));
    paths.update_netmap_endpoints(&[endpoint], now);
    paths.begin_ping(
        [1; 12],
        TailscalePathQuality::direct(endpoint, Duration::ZERO, 1_360),
        now,
    );
    paths
        .record_pong(
            [1; 12],
            endpoint,
            endpoint,
            false,
            now + Duration::from_millis(3),
        )
        .unwrap();
    assert_eq!(
        paths.send_path(now + Duration::from_secs(1)).derp_region,
        None
    );
    assert_eq!(
        paths
            .send_path(
                now + Duration::from_millis(3) + TAILSCALE_PATH_TRUST_DURATION,
            )
            .derp_region,
        Some(7)
    );
}

#[test]
fn tailscale_direct_disco_actor_is_public_library_api() {
    let options = TailscaleDiscoSocketOptions::new([1; 32], [2; 32]);
    assert_eq!(options.heartbeat_interval, Duration::from_secs(3));
    let peer = TailscaleDiscoPeer {
        node_key: [3; 32],
        disco_key: tailscale_disco_public_key([4; 32]).unwrap(),
        home_derp_region: Some(7),
        endpoints: vec!["127.0.0.1:41641".parse().unwrap()],
    };
    assert_eq!(peer.home_derp_region, Some(7));
    assert!(std::mem::size_of::<TailscaleDiscoSocket>() > 0);
    assert_eq!(TailscaleDiscoSocketStatus::default().peers, 0);
    assert_eq!(TailscalePacketSendOutcome::default().derp_region, None);
}

#[test]
fn tailscale_dynamic_wireguard_engine_is_public_library_api() {
    let options = TailscaleWireGuardOptions::new([1; 32]);
    assert_eq!(options.mtu, 1280);
    assert!(std::mem::size_of::<TailscaleWireGuardEngine>() > 0);
    assert_eq!(TailscaleWireGuardStatus::default().peers, 0);
    assert!(std::mem::size_of::<TailscaleWireGuardEvent>() > 0);

    let node = TailscaleNode {
        id: 9,
        key: TailscaleNodePublicKey::from_bytes([2; 32]),
        disco_key: singbox::protocol::tailscale_control_types::TailscaleDiscoPublicKey::from_bytes([3; 32]),
        allowed_ips: vec!["100.64.0.9/32".into()],
        endpoints: vec!["192.0.2.9:41641".into()],
        ..Default::default()
    };
    let peer = TailscaleWireGuardPeer::from_node(&node).unwrap().unwrap();
    assert_eq!(peer.node_key, [2; 32]);
    let network = TailscaleUserspaceNetworkConfig::new(vec![
        "100.64.0.1/32".parse().unwrap(),
    ]);
    assert_eq!(network.mtu, 1280);
    assert!(std::mem::size_of::<TailscaleUserspaceNetwork>() > 0);
    assert!(std::mem::size_of::<TailscaleUserspaceDialer>() > 0);
}

#[test]
fn tailscale_control_supervisor_is_public_library_api() {
    let options = TailscaleControlSupervisorOptions::default();
    assert!(options.maximum_backoff >= options.initial_backoff);
    assert_eq!(TailscaleControlSupervisorStatus::default().generation, 0);
    assert!(std::mem::size_of::<TailscaleControlSupervisor>() > 0);
    assert!(std::mem::size_of::<TailscaleControlSupervisorEvent>() > 0);
    assert!(std::mem::size_of::<TailscaleHttp2ControlSession>() > 0);
    assert!(std::mem::size_of::<TailscaleTs2021DialConnector>() > 0);
    assert!(std::mem::size_of::<TailscaleControlBootstrap>() > 0);

    fn assert_connector<T: TailscaleControlConnector>() {}
    fn assert_session<T: TailscaleControlSession>() {}
    fn assert_map<T: TailscaleControlMapStream>() {}
    fn assert_consumer<T: TailscaleNetmapConsumer>() {}
    let _ = assert_connector::<TailscaleTs2021DialConnector>;
    let _ = assert_session::<TailscaleHttp2ControlSession>;
    let _ = assert_map::<NeverMapStream>;
    let _ = assert_consumer::<
        singbox::protocol::tailscale_wireguard::TailscaleWireGuardHandle,
    >;
    let _ = bootstrap_tailscale_control;
}

struct NeverMapStream;

#[async_trait::async_trait]
impl TailscaleControlMapStream for NeverMapStream {
    async fn next_chunk(
        &mut self,
    ) -> Result<
        Option<Vec<u8>>,
        singbox::protocol::tailscale_control::TailscaleControlError,
    > {
        Ok(None)
    }
}

#[test]
fn tailscale_ts2021_noise_is_public_library_api() {
    let control_public = tailscale_node_public_key([2; 32]).unwrap();
    let handshake =
        TailscaleControlHandshake::start([1; 32], control_public, 138).unwrap();
    assert_eq!(handshake.initial_message().len(), 101);
    assert!(
        handshake
            .http_upgrade_request("control.example:443")
            .unwrap()
            .contains(TAILSCALE_CONTROL_UPGRADE_PROTOCOL)
    );
    assert!(std::mem::size_of::<TailscaleControlHttp2Client>() > 0);
    let decoder = TailscaleMapFrameDecoder::new(1 << 20, 1 << 20);
    assert_eq!(decoder.buffered_len(), 0);
}

#[test]
fn tailscale_control_models_are_public_library_api() {
    assert_eq!(TAILSCALE_REGISTER_PATH, "/machine/register");
    assert_eq!(TAILSCALE_MAP_PATH, "/machine/map");
    assert_eq!(TAILSCALE_SET_DNS_PATH, "/machine/set-dns");
    let register = TailscaleRegisterRequest {
        version: 138,
        node_key: TailscaleNodePublicKey::from_bytes([1; 32]),
        ..Default::default()
    };
    assert_eq!(register.node_key.as_bytes(), &[1; 32]);
    let map = TailscaleMapRequest {
        version: 138,
        node_key: register.node_key,
        stream: true,
        compress: "zstd".into(),
        ..Default::default()
    };
    assert!(map.stream);
    let mut decoder = TailscaleMapFrameDecoder::new(1 << 20, 1 << 20);
    let decoded: Vec<TailscaleMapResponse> = decoder.push_typed(&[]).unwrap();
    assert!(decoded.is_empty());
    let mut state = TailscaleNetmapState::default();
    state.apply(
        TailscaleMapResponse {
            peers: Some(vec![TailscaleNode {
                id: 7,
                ..Default::default()
            }]),
            ..Default::default()
        },
        "2026-09-02T00:00:00Z",
    );
    assert!(state.peers.contains_key(&7));
    assert!(TailscaleDnsConfig::default().resolvers.is_empty());
    assert!(TailscaleFilterRule::default().source_ips.is_empty());
    assert!(TailscaleSshPolicy::default().rules.is_empty());
    let set_dns = TailscaleSetDnsRequest {
        version: 142,
        node_key: register.node_key,
        name: "_acme-challenge.node.tail.ts.net".into(),
        record_type: "TXT".into(),
        value: "challenge".into(),
    };
    assert_eq!(set_dns.record_type, "TXT");
}

#[test]
fn tailscale_disco_is_public_library_api() {
    assert_eq!(TAILSCALE_DISCO_MAGIC, b"TS\xf0\x9f\x92\xac");
    assert_ne!(tailscale_disco_public_key([1; 32]).unwrap(), [0; 32]);
    let encoded = encode_tailscale_disco_message(&TailscaleDiscoMessage::Ping(
        TailscaleDiscoPing {
            transaction_id: [2; 12],
            node_key: None,
            padding: 0,
        },
    ))
    .unwrap();
    assert_eq!(&encoded[..2], &[1, 0]);
}

#[test]
fn tailscale_derp_region_supervisor_is_public_library_api() {
    fn accepts_connector(_connector: &dyn TailscaleDerpConnector) {}
    let _ = accepts_connector;
    let options = TailscaleDerpRegionSupervisorOptions::default();
    assert!(options.maximum_backoff >= options.initial_backoff);
    assert!(!TailscaleDerpRegionStatus::default().connected);
    assert!(std::mem::size_of::<TailscaleDerpRegionSupervisor>() > 0);
    assert!(std::mem::size_of::<TailscaleDerpRegionEvent>() > 0);
}

#[test]
fn tailscale_derp_manager_is_public_library_api() {
    let options = TailscaleDerpManagerOptions::default();
    assert_eq!(
        options.inactive_cleanup_time,
        TAILSCALE_DERP_INACTIVE_CLEANUP_TIME
    );
    assert_eq!(
        options.clean_stale_interval,
        TAILSCALE_DERP_CLEAN_STALE_INTERVAL
    );
    assert!(std::mem::size_of::<TailscaleDerpManager>() > 0);
    assert!(std::mem::size_of::<TailscaleDerpManagerEvent>() > 0);
    assert_eq!(TailscaleDerpManagerStatus::default().active_regions, 0);
}

#[test]
fn unified_openconnect_dtls_channel_is_public_library_api() {
    assert!(std::mem::size_of::<AnyConnectDataChannel>() > 0);
    assert!(std::mem::size_of::<AnyConnectDtlsChannel>() > 0);
    assert!(std::mem::size_of::<AnyConnectDtlsTransport>() > 0);
    assert_eq!(
        AnyConnectDtlsChannelError::MissingPsk.to_string(),
        "standard PSK DTLS negotiation did not provide an exporter secret"
    );
}

#[test]
fn globalprotect_hip_is_public_library_api() {
    let token = build_globalprotect_hip_token(
        "authcookie=secret&user=alice&domain=example",
    )
    .unwrap();
    assert_eq!(token.identity.user, "alice");
    assert_eq!(token.identity.domain, "example");
    let body = build_globalprotect_hip_check_body(
        "authcookie=secret&user=alice&domain=example",
        Some("10.0.0.2".parse().unwrap()),
        None,
        &token.md5,
    );
    assert!(body.contains("client-ip=10.0.0.2"));
    assert!(body.ends_with(&format!("md5={}", token.md5)));
}

#[test]
fn globalprotect_esp_is_public_library_api() {
    let client = OpenConnectEspKeyMaterial {
        spi: 1,
        encryption_key: vec![1; 16],
        authentication_key: vec![2; 20],
    };
    let server = OpenConnectEspKeyMaterial {
        spi: 2,
        encryption_key: vec![3; 16],
        authentication_key: vec![4; 20],
    };
    let config = |outbound, inbound| OpenConnectEspKeySetConfig {
        encryption: OpenConnectEspEncryption::Aes128Cbc,
        authentication: OpenConnectEspAuthentication::HmacSha1_96,
        outbound,
        inbound,
        disable_replay_protection: false,
    };
    let sender =
        OpenConnectEspKeySet::new(&config(client.clone(), server.clone()))
            .unwrap();
    let receiver = OpenConnectEspKeySet::new(&config(server, client)).unwrap();
    let packet = sender.seal(&[0x45, 0, 0, 20], None).unwrap();
    assert_eq!(receiver.open(&packet).unwrap().0, [0x45, 0, 0, 20]);
}

#[test]
fn pulse_protocol_is_public_library_api() {
    assert!(std::mem::size_of::<PulseChallengeParser>() > 0);
    assert!(std::mem::size_of::<PulseConfigurationAccumulator>() > 0);
    assert!(std::mem::size_of::<PulseIftEncoder>() > 0);
    assert_eq!(OpenConnectEspProbe::Pulse, OpenConnectEspProbe::Pulse);
    let request = build_pulse_upgrade_request(
        &url::Url::parse("https://vpn.example/pulse").unwrap(),
        "zay",
        &[("DSID".into(), "session".into())],
    )
    .unwrap();
    assert!(request.starts_with(b"GET /pulse HTTP/1.1\r\n"));
}

#[test]
fn network_connect_protocol_is_public_library_api() {
    let form = parse_network_connect_authentication_document(
        br#"<form name="frmLogin" method="post"><input type="text" name="username"></form>"#,
    )
    .unwrap()
    .unwrap();
    assert_eq!(form.id, "frmLogin");
    assert_eq!(
        encode_network_connect_oncp_authentication_packet("zay").unwrap()[..2],
        [16, 0]
    );
    let message = encode_network_connect_oncp_kmp(300, b"packet").unwrap();
    assert_eq!(
        parse_network_connect_oncp_kmp(&message, true).unwrap().1,
        b"packet"
    );
    let tncc = build_network_connect_tncc_initial_message(
        &NetworkConnectTnccIdentity::default(),
    )
    .unwrap();
    assert!(!tncc.is_empty());
}

#[test]
fn fortinet_configuration_is_public_library_api() {
    assert!(std::mem::size_of::<FortinetAuthenticator>() > 0);
    assert!(std::mem::size_of::<CertificateDtlsClientOptions>() > 0);
    assert!(std::mem::size_of::<PppDatagramSessionOptions>() > 0);
    let configuration = parse_fortinet_xml_configuration(
        br#"<sslvpn-tunnel dtls="1"><ipv4><assigned-addr ipv4="10.0.0.2"/><split-dns domains="corp.example" dnsserver1="10.0.0.53"/></ipv4></sslvpn-tunnel>"#,
        std::time::SystemTime::UNIX_EPOCH,
    )
    .unwrap();
    assert!(configuration.dtls_enabled);
    assert_eq!(
        configuration.configuration.routes[0].prefix.to_string(),
        "0.0.0.0/0"
    );
    assert_eq!(
        configuration.configuration.split_dns_rules[0].domains,
        ["corp.example"]
    );
    assert_eq!(
        configuration.configuration.split_dns_rules[0].servers,
        ["10.0.0.53".parse::<std::net::IpAddr>().unwrap()]
    );
    let hello = build_fortinet_dtls_connect_request("cookie").unwrap();
    assert_eq!(
        usize::from(u16::from_be_bytes([hello[0], hello[1]])),
        hello.len()
    );
    let challenge = parse_fortinet_token_info(
        b"ret=2,tokeninfo=ftm_push,reqid=opaque",
        "alice",
    )
    .unwrap();
    assert!(challenge.ftm_push);
    assert_eq!(challenge.fields[0].value, "alice");
    assert_eq!(
        encode_ppp_frame(PppEncapsulation::Fortinet, b"packet", 0).unwrap(),
        b"\0\x0cPP\0\x06packet"
    );
    let mut ppp = PppNegotiator::new(
        PppNegotiatorOptions {
            want_ipv6: false,
            ..Default::default()
        },
        std::time::Instant::now(),
    )
    .unwrap();
    assert_eq!(ppp.start(std::time::Instant::now()).unwrap().len(), 1);
}

#[test]
fn openconnect_runtime_endpoint_is_embedding_library_api() {
    let options: Options = serde_json::from_value(serde_json::json!({
        "dns": {"servers": [{"type": "hosts", "tag": "hosts"}]},
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "endpoints": [
            {
                "type": "openconnect",
                "tag": "vpn",
                "server": "vpn.example",
                "cookie": "webvpn=session",
                "no_udp": true,
                "tls": {"insecure": true}
            },
            {
                "type": "openconnect",
                "tag": "fortinet",
                "flavor": "fortinet",
                "server": "fortinet.example",
                "cookie": "SVPNCOOKIE=session",
                "no_udp": true,
                "tls": {"insecure": true}
            },
            {
                "type": "openconnect",
                "tag": "pulse",
                "flavor": "pulse",
                "server": "pulse.example",
                "cookie": "session",
                "no_udp": true,
                "tls": {"insecure": true}
            },
            {
                "type": "openconnect",
                "tag": "network-connect",
                "flavor": "nc",
                "server": "nc.example",
                "cookie": "DSID=session",
                "no_udp": true,
                "tls": {"insecure": true}
            }
        ]
    }))
    .unwrap();
    let runtime = Runtime::from_options(options).unwrap();
    let endpoint = runtime.openconnect_endpoint("vpn").unwrap();
    assert!(endpoint.tunnel_configuration().is_none());
    assert!(!endpoint.dtls_active());
    assert_eq!(endpoint.successful_reconnections(), 0);
    assert_eq!(endpoint.userspace_stack_generation(), 0);
    assert!(endpoint.challenge_manager().pending().is_none());
    assert!(runtime.openconnect_endpoint("fortinet").is_some());
    assert!(runtime.openconnect_endpoint("pulse").is_some());
    assert!(runtime.openconnect_endpoint("network-connect").is_some());
}

#[test]
fn openvpn_dynamic_dns_is_embedding_library_api() {
    let options: Options = serde_json::from_value(serde_json::json!({
        "certificate": {"store": "none"},
        "dns": {
            "servers": [{
                "type": "openvpn",
                "tag": "vpn-dns",
                "endpoint": "vpn",
                "accept_default_resolvers": true,
                "accept_search_domain": true
            }],
            "final": "vpn-dns"
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "endpoints": [{
            "type": "openvpn-client",
            "tag": "vpn",
            "server": "127.0.0.1",
            "server_port": 1194,
            "network": "udp",
            "tls": {
                "peer_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }]
    }))
    .unwrap();
    let runtime = Runtime::from_options(options).unwrap();
    assert!(runtime.outbounds().dns().resolver("vpn-dns").is_some());
    assert_eq!(runtime.outbounds().default_tag(), "direct");
}

struct LibraryEchResolver(Vec<u8>);

struct LibraryNeighborResolver;

impl NeighborResolver for LibraryNeighborResolver {
    fn lookup_addresses(&self, hostname: &str) -> Vec<IpAddr> {
        if hostname == "printer" {
            vec!["192.0.2.81".parse().unwrap()]
        } else {
            Vec::new()
        }
    }
}

struct LibraryProcessResolver;

impl ProcessResolver for LibraryProcessResolver {
    fn lookup(
        &self,
        _network: Network,
        _source: SocketAddr,
        _destination: Option<SocketAddr>,
    ) -> Option<ProcessInfo> {
        None
    }
}

struct NoopAuthTransport;

#[async_trait::async_trait]
impl AnyConnectAuthHttpTransport for NoopAuthTransport {
    async fn execute(
        &self,
        _request: http::Request<Vec<u8>>,
    ) -> io::Result<AnyConnectAuthRawHttpResponse> {
        Err(io::Error::other(
            "direct-cookie authentication must not dial",
        ))
    }
}

impl EchConfigResolver for LibraryEchResolver {
    fn resolve_ech<'a>(
        &'a self,
        server_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<EchConfigRecord>> + Send + 'a>>
    {
        Box::pin(async move {
            assert_eq!(server_name, "discovery.example");
            Ok(EchConfigRecord {
                config_list: self.0.clone(),
                ttl: Duration::from_secs(60),
            })
        })
    }
}

#[test]
fn configuration_api_accepts_valid_and_rejects_invalid_runtime_graphs() {
    let directory = tempfile::tempdir().unwrap();
    let valid = directory.path().join("valid.json");
    fs::write(
        &valid,
        r#"{
          // Extended JSON comments are supported.
          "dns": {"servers":[{"type":"hosts","tag":"hosts"}]},
          "inbounds": [{"type":"socks","listen":"127.0.0.1","listen_port":1080}],
          "outbounds": [{"type":"direct","tag":"direct"}]
        }"#,
    )
    .unwrap();
    let options = ConfigLoader::new().path(&valid).read_and_merge().unwrap();
    Runtime::from_options(options).unwrap();

    let invalid = directory.path().join("invalid.json");
    fs::write(&invalid, r#"{"outbounds":[{"type":"unknown"}]}"#).unwrap();
    let error = ConfigLoader::new()
        .path(&invalid)
        .read_and_merge()
        .unwrap_err();
    assert!(error.to_string().contains("unknown"));

    let bridge = directory.path().join("bridge.json");
    fs::write(
        &bridge,
        r#"{
          "dns":{"servers":[{"type":"hosts","tag":"hosts"}]},
          "outbounds":[{"type":"bridge","tag":"layer-three"}]
        }"#,
    )
    .unwrap();
    let options = ConfigLoader::new().path(&bridge).read_and_merge().unwrap();
    let runtime = Runtime::from_options(options).unwrap();
    assert_eq!(
        runtime.outbounds().kind_owned("layer-three").as_deref(),
        Some("bridge")
    );
    assert!(
        runtime
            .outbounds()
            .outbound("layer-three")
            .and_then(|outbound| outbound.packet_port())
            .is_some()
    );
}

#[tokio::test]
async fn runtime_host_exposes_neighbor_domain_to_local_dns() {
    let options: Options = serde_json::from_value(serde_json::json!({
        "certificate": {"store": "none"},
        "dns": {
            "servers": [{
                "type": "local",
                "tag": "local",
                "neighbor_domain": ".lan"
            }]
        },
        "outbounds": [{"type": "direct", "tag": "direct"}]
    }))
    .unwrap();
    let runtime = Runtime::from_options_with_host(
        options,
        RuntimeHost {
            neighbor_resolver: Some(Arc::new(LibraryNeighborResolver)),
            process_resolver: Some(Arc::new(LibraryProcessResolver)),
            ..RuntimeHost::default()
        },
    )
    .unwrap();
    let addresses = runtime
        .outbounds()
        .dns()
        .resolver("local")
        .unwrap()
        .lookup("printer.lan", singbox::option::DomainStrategy::Ipv4Only)
        .await
        .unwrap();
    assert_eq!(addresses, ["192.0.2.81".parse::<IpAddr>().unwrap()]);
}

struct CloudflaredApiCallbacks;

impl CloudflaredConfigurationApplier for CloudflaredApiCallbacks {
    fn apply_configuration(
        &self,
        version: i32,
        _configuration: &[u8],
    ) -> CloudflaredConfigurationUpdate {
        CloudflaredConfigurationUpdate {
            latest_applied_version: version,
            error: None,
        }
    }
}

#[async_trait::async_trait]
impl CloudflaredUdpSessionHandler for CloudflaredApiCallbacks {
    async fn register_udp_session(
        &self,
        _registration: CloudflaredUdpRegistration,
    ) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    async fn unregister_udp_session(
        &self,
        _session_id: uuid::Uuid,
        _message: &str,
    ) {
    }
}

#[test]
fn cloudflared_configuration_and_protocol_are_public_library_api() {
    const TOKEN: &str = "eyJhIjoiYWNjb3VudDEyMyIsInQiOiI1NTBlODQwMC1lMjlhLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJzIjoiYzJWamNtVjBMVE15TFdKNWRHVnpMV3h2Ym1jdGVIZz0iLCJlIjoiZmVkIn0=";
    let options: Options = serde_json::from_str(&format!(
        r#"{{"inbounds":[{{"type":"cloudflared","tag":"edge","token":"{TOKEN}","protocol":"quic","edge_ip_version":6,"datagram_version":"v3"}}]}}"#
    ))
    .unwrap();
    options.validate().unwrap();
    let inbound = options.inbounds[0]
        .decode::<CloudflaredInboundOptions>()
        .unwrap();
    assert_eq!(inbound.effective_ha_connections(), 4);
    assert_eq!(
        parse_cloudflared_token(&inbound.token).unwrap().endpoint,
        "fed"
    );
    assert_eq!(
        CloudflaredProtocolSelection::new(&inbound.protocol, false)
            .unwrap()
            .current,
        CloudflaredTransportProtocol::Quic
    );
    assert_eq!(
        &cloudflared_data_stream_prefix()[..6],
        &CLOUDFLARED_DATA_STREAM_SIGNATURE
    );
    assert_eq!(CLOUDFLARED_PROTOCOL_VERSION, *b"01");
    assert_eq!(CLOUDFLARED_DEFAULT_DATAGRAM_VERSION, "v2");
    assert_eq!(cloudflared_quic_initial_packet_size(4), 1232);
    assert_eq!(cloudflared_quic_initial_packet_size(6), 1252);
    assert_eq!(
        CLOUDFLARED_QUIC_HANDSHAKE_IDLE_TIMEOUT,
        Duration::from_secs(5)
    );
    assert_eq!(CLOUDFLARED_QUIC_MAX_IDLE_TIMEOUT, Duration::from_secs(5));
    assert_eq!(CLOUDFLARED_QUIC_KEEP_ALIVE_INTERVAL, Duration::from_secs(1));
    assert_eq!(CLOUDFLARED_REGISTRATION_TIMEOUT, Duration::from_secs(5));
    cloudflared_quic_transport_config(4).unwrap();
    assert_eq!(CLOUDFLARED_POST_QUANTUM_FEATURE, "postquantum");
    assert_eq!(CLOUDFLARED_EDGE_TLS_HANDSHAKE_TIMEOUT.as_secs(), 15);
    assert_eq!(
        CLOUDFLARED_ROOT_CA_PEM.matches("BEGIN CERTIFICATE").count(),
        3
    );
    let edge_tls = cloudflared_edge_tls_configs(false).unwrap();
    assert!(std::mem::size_of_val(&edge_tls) > 0);
    assert!(std::mem::size_of::<CloudflaredEdgeTlsConfigs>() > 0);
    assert!(std::mem::size_of::<CloudflaredEdgeConnectionFactory>() > 0);
    assert_eq!(CLOUDFLARED_DEFAULT_HTTP_CONNECT_TIMEOUT.as_secs(), 30);
    assert_eq!(CLOUDFLARED_DEFAULT_WARP_CONNECT_TIMEOUT.as_secs(), 5);
    assert_eq!(CLOUDFLARED_DEFAULT_KEEP_ALIVE_CONNECTIONS, 100);
    assert!(std::mem::size_of::<CloudflaredConfigManager>() > 0);
    assert!(std::mem::size_of::<CloudflaredRuntimeConfig>() > 0);
    assert!(std::mem::size_of::<CloudflaredIngressRule>() > 0);
    assert!(std::mem::size_of::<CloudflaredResolvedService>() > 0);
    assert!(std::mem::size_of::<CloudflaredResolvedServiceKind>() > 0);
    assert!(std::mem::size_of::<CloudflaredOriginRequestConfig>() > 0);
    assert!(std::mem::size_of::<CloudflaredWarpRoutingConfig>() > 0);
    assert!(std::mem::size_of::<CloudflaredAccessConfig>() > 0);
    assert!(std::mem::size_of::<CloudflaredIpRule>() > 0);
    assert!(std::mem::size_of::<CloudflaredIpRulePolicy>() > 0);
    assert!(std::mem::size_of::<CloudflaredLocalIngressRule>() > 0);
    assert!(std::mem::size_of::<CloudflaredOriginService>() > 0);
    assert!(std::mem::size_of::<CloudflaredAccessValidator>() > 0);
    assert!(std::mem::size_of::<CloudflaredDatagramService>() > 0);
    assert!(std::mem::size_of::<Arc<dyn CloudflaredDatagramTransport>>() > 0);
    assert_eq!(CLOUDFLARED_DATAGRAM_V2_QUEUE_SIZE, 256);
    assert_eq!(CLOUDFLARED_DATAGRAM_V3_QUEUE_SIZE, 512);
    assert_eq!(CLOUDFLARED_V3_RESPONSE_OK, 0);
    assert_eq!(CLOUDFLARED_V3_RESPONSE_DESTINATION_UNREACHABLE, 1);
    assert_eq!(CLOUDFLARED_V3_RESPONSE_UNABLE_TO_BIND_SOCKET, 2);
    assert_eq!(CLOUDFLARED_V3_RESPONSE_TOO_MANY_ACTIVE_FLOWS, 3);
    assert_eq!(CLOUDFLARED_V3_RESPONSE_ERROR_WITH_MESSAGE, 0xff);
    assert!(std::mem::size_of::<CloudflaredIcmpBridge>() > 0);
    assert!(std::mem::size_of::<CloudflaredIcmpPacket>() > 0);
    assert_eq!(CLOUDFLARED_ICMP_FLOW_TIMEOUT, Duration::from_secs(30));
    assert_eq!(CLOUDFLARED_ICMP_TRACE_IDENTITY_LENGTH, 25);
    assert_eq!(CLOUDFLARED_ICMP_IPV4_TTL_QUOTE_LENGTH, 548);
    assert_eq!(CLOUDFLARED_ICMP_IPV6_TTL_QUOTE_LENGTH, 1232);
    assert_eq!(CLOUDFLARED_ICMP_MAX_PAYLOAD_LENGTH, 1280);
    let _ = parse_cloudflared_icmp_packet;
    assert_eq!(
        CLOUDFLARED_ACCESS_JWT_ASSERTION_HEADER,
        "Cf-Access-Jwt-Assertion"
    );
    assert_eq!(CLOUDFLARED_ACCESS_JWKS_PATH, "/cdn-cgi/access/certs");
    assert_eq!(CLOUDFLARED_ACCESS_MAX_JWKS_SIZE, 1024 * 1024);
    assert_eq!(
        cloudflared_access_issuer_url("team", "fed"),
        "https://team.fed.cloudflareaccess.com"
    );
    let _ = cloudflared_access_validator_key;
    let _ = build_cloudflared_remote_config;
    let _ = compile_cloudflared_ingress_rules;
    let _ = match_cloudflared_ingress_host;
    let _ = match_cloudflared_ingress_rule;
    let _ = parse_cloudflared_resolved_service;
    assert_eq!(CLOUDFLARED_H2_CONTENT_TYPE_SSE, "text/event-stream");
    assert_eq!(CLOUDFLARED_H2_CONTENT_TYPE_GRPC, "application/grpc");
    assert_eq!(CLOUDFLARED_H2_CONTENT_TYPE_NDJSON, "application/x-ndjson");
    assert!(CLOUDFLARED_H2_RESPONSE_META_EDGE.contains("cloudflared"));
    assert!(std::mem::size_of::<CloudflaredHttp2Connection>() > 0);
    assert!(std::mem::size_of::<CloudflaredHttp2Stream>() > 0);
    assert!(std::mem::size_of::<CloudflaredHttp2ResponseWriter>() > 0);
    assert!(std::mem::size_of::<CloudflaredHttp2ResponseHead>() > 0);
    assert!(std::mem::size_of::<CloudflaredHttp2RequestKind>() > 0);
    fn accepts_http2_handler<T: CloudflaredHttp2Handler + ?Sized>() {}
    accepts_http2_handler::<dyn CloudflaredHttp2Handler>();
    let _ = classify_cloudflared_http2_request::<()>;
    let _ = decode_cloudflared_http2_connect_request::<()>;
    let _ = encode_cloudflared_http2_response_head;
    let _ = cloudflared_http2_should_flush_headers;
    let _ = cloudflared_http2_method_is_bodyless;
    let _ = decode_cloudflared_http2_configuration;
    let _ = encode_cloudflared_http2_configuration_response;
    assert!(std::mem::size_of::<CloudflaredQuicDatagramSender>() > 0);
    assert!(std::mem::size_of::<CloudflaredQuicEdge>() > 0);
    assert!(std::mem::size_of::<CloudflaredQuicEvent>() > 0);
    assert!(std::mem::size_of::<Arc<dyn CloudflaredQuicHandler>>() > 0);
    assert!(std::mem::size_of::<CloudflaredQuicSession>() > 0);
    assert!(std::mem::size_of::<CloudflaredQuicStream>() > 0);
    assert!(std::mem::size_of::<CloudflaredConnectionAttempt>() > 0);
    assert!(std::mem::size_of::<Arc<dyn CloudflaredConnectionFactory>>() > 0);
    assert!(std::mem::size_of::<Arc<dyn CloudflaredManagedConnection>>() > 0);
    assert!(std::mem::size_of::<CloudflaredHaSupervisor>() > 0);
    assert!(std::mem::size_of::<CloudflaredQuicManagedConnection>() > 0);
    assert!(std::mem::size_of::<CloudflaredSupervisorEvent>() > 0);
    assert_eq!(CLOUDFLARED_PROTOCOL_RETRY_LIMIT, 5);
    assert_eq!(CLOUDFLARED_RETRY_BASE, Duration::from_secs(1));
    assert_eq!(CLOUDFLARED_RETRY_MAX, Duration::from_secs(120));
    assert_eq!(
        CLOUDFLARED_FIRST_CONNECTION_READY_TIMEOUT,
        Duration::from_secs(15)
    );
    assert_eq!(cloudflared_initial_edge_index(3, 2), 1);
    assert_eq!(cloudflared_rotate_edge_index(1, 3), 2);
    assert!(cloudflared_retry_backoff(20) >= Duration::from_secs(60));
    assert!(!cloudflared_quic_is_broken(
        &singbox::protocol::cloudflared::CloudflaredError::Transport(
            "ordinary connection failure".into()
        )
    ));
    assert!(std::mem::size_of::<CloudflaredRegistrationClient>() > 0);
    assert!(std::mem::size_of::<CloudflaredRegistrationOptions>() > 0);
    assert!(std::mem::size_of::<CloudflaredRegistrationResult>() > 0);
    assert!(std::mem::size_of::<CloudflaredRpcSystem>() > 0);
    assert_eq!(
        CloudflaredIncomingDatagramVersion::V3,
        CloudflaredIncomingDatagramVersion::V3
    );
    let (stream, peer) = tokio::io::duplex(64);
    let (registration, rpc) = cloudflared_registration_rpc(stream);
    drop((registration, rpc, peer));
    let callbacks = Arc::new(CloudflaredApiCallbacks);
    let server =
        CloudflaredIncomingRpcServer::datagram_v2(callbacks.clone(), callbacks);
    let (stream, peer) = tokio::io::duplex(64);
    let rpc = cloudflared_incoming_rpc(stream, server);
    drop((rpc, peer));

    let invalid: Options = serde_json::from_str(
        r#"{"inbounds":[{"type":"cloudflared","tag":"bad","token":"not-base64"}]}"#,
    )
    .unwrap();
    let error = invalid.validate().unwrap_err().to_string();
    assert!(error.contains("cloudflared inbound \"bad\""), "{error}");

    let runtime_options: Options = serde_json::from_value(serde_json::json!({
        "dns": {
            "servers": [{"type": "hosts", "tag": "hosts"}],
            "final": "hosts"
        },
        "inbounds": [{
            "type": "cloudflared",
            "tag": "edge",
            "token": TOKEN,
            "protocol": "quic",
            "datagram_version": "v3"
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .unwrap();
    let runtime = Runtime::from_options(runtime_options).unwrap();
    let handle = runtime.cloudflared_inbound("edge").unwrap();
    assert_eq!(handle.active_flows(), 0);
    assert!(handle.terminal_error().is_none());
}

#[test]
fn embedded_schema_is_byte_identical_to_the_pinned_upstream_schema() {
    assert_eq!(
        UPSTREAM_SCHEMA_JSON.as_bytes(),
        include_bytes!("../../../inner/sing-box/docs/schema.json")
    );
}

#[test]
fn version_constants_are_available_to_the_embedding_application() {
    assert_eq!(singbox::VERSION, env!("CARGO_PKG_VERSION"));
    assert_eq!(singbox::UPSTREAM_VERSION, "1.14.0");
    assert_eq!(singbox::UPSTREAM_REVISION.len(), 40);
}

#[tokio::test]
async fn openconnect_authentication_is_available_as_a_library_api() {
    let form = parse_anyconnect_authentication_xml(
        br#"<auth id="main"><form><input type="text" name="username"/></form></auth>"#,
        "linux-64",
    )
    .unwrap();
    assert_eq!(form.fields[0].submission_key, "main:username:1");
    let prepared = prepare_anyconnect_auth_form(
        form,
        &AnyConnectAuthPrefillOptions {
            credentials: AnyConnectCredentialCache {
                username: Some("alice".into()),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    assert!(prepared.challenge.is_none());
    assert_eq!(
        complete_anyconnect_auth_form(prepared, None)
            .unwrap()
            .fields[0]
            .value,
        "alice"
    );

    let request = build_anyconnect_initial_xml(
        &AnyConnectAuthClientIdentity {
            version: "5.1.2".into(),
            reported_os: "linux-64".into(),
            ..Default::default()
        },
        "https://vpn.example",
        "",
        false,
    )
    .unwrap();
    assert!(request.starts_with(b"<?xml version=\"1.0\""));
    assert!(request.windows(11).any(|value| value == b"<device-id>"));

    let http =
        AnyConnectAuthHttpClient::new(Arc::new(NoopAuthTransport), "zay");
    let mut authenticator = AnyConnectAuthenticator::new(
        http,
        "https://vpn.example/",
        AnyConnectAuthenticatorOptions {
            direct_cookie: Some("webvpn=already-authenticated".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let AnyConnectAuthenticationProgress::Complete(session) =
        authenticator.begin().await.unwrap()
    else {
        panic!("direct cookie did not complete authentication");
    };
    assert_eq!(session.webvpn_cookie, "already-authenticated");
}

#[test]
fn key_generation_api_returns_upstream_key_shapes() {
    let wireguard = generate_wireguard_keypair().unwrap();
    assert_eq!(wireguard.private_key[0] & 7, 0);
    assert_eq!(wireguard.private_key[31] & 0x80, 0);
    assert_ne!(wireguard.public_key, [0; 32]);

    let reality = generate_reality_keypair().unwrap();
    assert_ne!(reality.private_key, [0; 32]);
    assert_ne!(reality.public_key, [0; 32]);

    let vapid = generate_vapid_keypair().unwrap();
    assert_eq!(vapid.public_key[0], 4);
    assert_ne!(vapid.private_key, [0; 32]);
}

#[test]
fn tls_key_generation_api_returns_parseable_pem() {
    let pair = generate_tls_keypair("server.example", 1).unwrap();
    assert!(pair.private_key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pair.certificate_pem.contains("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn ech_key_generation_api_returns_upstream_pem_blocks() {
    let pair = generate_ech_keypair("public.example").unwrap();
    assert!(pair.config_pem.contains("-----BEGIN ECH CONFIGS-----"));
    assert!(pair.key_pem.contains("-----BEGIN ECH KEYS-----"));
}

#[tokio::test]
async fn embedding_application_can_supply_dynamic_ech_resolver() {
    let pair = generate_ech_keypair("public.example").unwrap();
    let config_list = pem::parse(pair.config_pem).unwrap().into_contents();
    let tls = build_client_config_with_ech_resolver(
        "secret.example",
        &OutboundTlsOptions {
            insecure: true,
            ech: Some(OutboundEchOptions {
                enabled: true,
                query_server_name: "discovery.example".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
        &["h2"],
        Arc::new(LibraryEchResolver(config_list)),
    )
    .unwrap();
    let config = tls.config_for_handshake().await.unwrap();
    assert_eq!(config.alpn_protocols, [b"h2".to_vec()]);
}

#[test]
fn embedding_application_can_share_ntp_clock_with_tls_and_outbounds() {
    let clock = NtpClock::default();
    clock.update(NtpSample {
        offset_nanos: 1_000_000_000,
        round_trip_nanos: 1,
        stratum: 1,
    });
    let tls = build_client_config_with_clock(
        "example.com",
        &OutboundTlsOptions {
            insecure: true,
            ..Default::default()
        },
        &[],
        Some(clock.clone()),
    )
    .unwrap();
    assert_eq!(tls.server_name.to_str(), "example.com");

    let manager = OutboundManager::from_options_with_clock(
        &Options::default(),
        "",
        Some(clock),
    )
    .unwrap();
    assert_eq!(manager.default_tag(), "direct");
}

#[test]
fn embedding_application_can_supply_privileged_system_clock_writer() {
    struct NoopWriter;

    impl SystemClockWriter for NoopWriter {
        fn set_system_time(
            &self,
            _time: std::time::SystemTime,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    let options: Options = serde_json::from_value(serde_json::json!({
        "dns": {
            "servers": [{"type": "hosts", "tag": "hosts"}],
            "final": "hosts"
        },
        "ntp": {
            "enabled": true,
            "server": "127.0.0.1",
            "write_to_system": true
        }
    }))
    .unwrap();
    let runtime = Runtime::from_options_with_system_clock_writer(
        options,
        Some(Arc::new(NoopWriter)),
    )
    .unwrap();
    assert!(runtime.ntp_clock().is_some());
}

#[test]
fn embedding_application_can_manage_the_shared_certificate_store() {
    let generated = generate_tls_keypair("root.example", 1).unwrap();
    let options = CertificateOptions {
        store: CertificateStoreKind::None,
        certificate: Listable(vec![generated.certificate_pem]),
        ..Default::default()
    };
    let store =
        CertificateStore::new(&options, std::path::Path::new(".")).unwrap();
    assert!(store.exclusive_anchors());
    assert_eq!(store.root_store().unwrap().subjects().len(), 1);

    let runtime_options: Options = serde_json::from_value(serde_json::json!({
        "certificate": {"store": "none"}
    }))
    .unwrap();
    let runtime = Runtime::from_options(runtime_options).unwrap();
    assert_eq!(
        runtime.certificate_store().kind(),
        CertificateStoreKind::None
    );
}

#[test]
fn rule_set_library_compile_decompile_format_and_match_are_compatible() {
    let source = br#"{
      // DNS names and scalar list values use upstream source syntax.
      "version": 5,
      "rules": [
        {"domain_suffix":"example.org"},
        {"query_type":"A"},
        {"ip_cidr":"10.0.0.0/8"}
      ]
    }"#;

    let compiled = compile_rule_set(source).unwrap();
    assert!(compiled.starts_with(b"SRS"));
    let recovered = decompile_rule_set(&compiled).unwrap();
    assert_eq!(recovered.version, 2);
    let recovered_value: serde_json::Value =
        serde_json::from_str(&recovered.format().unwrap()).unwrap();
    assert_eq!(
        recovered_value["rules"][1]["query_type"],
        serde_json::json!("A")
    );

    let source = SourceRuleSet::parse(source).unwrap();
    assert_eq!(source.matching_rules("www.example.org").unwrap(), [0]);
    assert!(source.format().unwrap().contains("\"version\": 5"));
}

#[test]
fn adguard_converter_is_public_library_api() {
    let source = b"||ads.example^$important\n@@|safe.ads.example^$important\n||base.example^\n";
    let conversion = convert_adguard_rule_set(source).unwrap();
    assert_eq!(conversion.rule_set.version, 2);
    assert_eq!(conversion.parsed_lines, 3);
    assert_eq!(conversion.ignored_lines, 0);
    assert_eq!(
        export_adguard_rule_set(&conversion.rule_set).unwrap(),
        source
    );
    assert_eq!(
        conversion.rule_set.matching_rules("ads.example").unwrap(),
        [0]
    );
    assert!(
        conversion
            .rule_set
            .matching_rules("safe.ads.example")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn rule_set_library_merge_preserves_sorted_input_order() {
    let first = br#"{"version":1,"rules":[{"domain":"first.example"}]}"#;
    let second = br#"{"version":4,"rules":[{"ip_cidr":"10.0.0.0/8"}]}"#;
    let merged =
        merge_rule_sets([first.as_slice(), second.as_slice()]).unwrap();
    let value: serde_json::Value =
        serde_json::from_str(&merged.format().unwrap()).unwrap();
    assert_eq!(value["version"], 4);
    assert_eq!(value["rules"][0]["domain"], "first.example");
    assert_eq!(value["rules"][1]["ip_cidr"], "10.0.0.0/8");
}

#[test]
fn tls_spoof_configuration_and_method_are_public_library_api() {
    use singbox::common::tls_spoof::{TlsSpoofMethod, parse_options};

    assert_eq!(
        parse_options("allowed.example", "wrong-ack").unwrap(),
        Some(TlsSpoofMethod::WrongAcknowledgment)
    );
    assert_eq!(TlsSpoofMethod::WrongMd5.as_str(), "wrong-md5");

    let options: Options = serde_json::from_value(serde_json::json!({
        "route": {
            "final": "direct",
            "rules": [{
                "domain_suffix": "example",
                "action": "route-options",
                "tls_spoof": "allowed.example",
                "tls_spoof_method": "wrong-checksum"
            }]
        },
        "outbounds": [{"type": "direct", "tag": "direct"}]
    }))
    .unwrap();
    Runtime::from_options(options).unwrap();
}

#[test]
fn realm_control_detour_and_legacy_acme_are_typed_library_api() {
    let dialer =
        Arc::new(DirectOutbound::new(DirectOutboundOptions::default()));
    RealmControlClient::new_with_dialer(
        "https://realm.example",
        "token",
        dialer,
        HttpClientOptions {
            version: 3,
            disable_version_fallback: true,
            ..Default::default()
        },
        None,
    )
    .unwrap();

    let tls: InboundTlsOptions = serde_json::from_value(serde_json::json!({
        "enabled": true,
        "acme": {
            "domain": "example.com",
            "key_type": "ed25519"
        }
    }))
    .unwrap();
    assert_eq!(tls.acme.unwrap().domain.as_slice(), ["example.com"]);
}

#[test]
fn top_level_route_is_a_typed_library_api() {
    use singbox::option::{
        DefaultRouteRuleMatcherOptions, DefaultRouteRuleOptions,
        RouteActionOptions, RouteRuleActionOptions, RouteRuleOptions,
    };

    let options = Options {
        certificate: Some(CertificateOptions {
            store: CertificateStoreKind::None,
            ..Default::default()
        }),
        dns: Some(
            serde_json::from_value(serde_json::json!({
                "servers": [{"type": "hosts", "tag": "local"}]
            }))
            .unwrap(),
        ),
        route: Some(RouteOptions {
            rules: vec![RouteRuleOptions::Default(Box::new(
                DefaultRouteRuleOptions {
                    matcher: DefaultRouteRuleMatcherOptions {
                        domain_suffix: Listable(vec!["example.com".into()]),
                        ..Default::default()
                    },
                    action: RouteRuleActionOptions::Route(RouteActionOptions {
                        outbound: "direct".into(),
                        ..Default::default()
                    }),
                },
            ))],
            final_outbound: "direct".into(),
            ..Default::default()
        }),
        outbounds: vec![
            serde_json::from_value(serde_json::json!({
                "type": "direct",
                "tag": "direct"
            }))
            .unwrap(),
        ],
        ..Default::default()
    };
    let runtime = Runtime::from_options(options).unwrap();
    assert_eq!(
        runtime.options().route.as_ref().unwrap().final_outbound,
        "direct"
    );

    let inherited_missing_resolver: Options =
        serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "local"}]},
            "route": {"default_domain_resolver": "missing"},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .unwrap();
    let error = Runtime::from_options(inherited_missing_resolver)
        .err()
        .expect("route default resolver must be inherited")
        .to_string();
    assert!(error.contains("missing"), "{error}");

    let protocol_underlay_inherits_missing_resolver: Options =
        serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "local"}]},
            "route": {"default_domain_resolver": "missing"},
            "outbounds": [{
                "type": "socks",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": 1080
            }]
        }))
        .unwrap();
    let error =
        Runtime::from_options(protocol_underlay_inherits_missing_resolver)
            .err()
            .expect("protocol underlay must inherit route default resolver")
            .to_string();
    assert!(error.contains("missing"), "{error}");

    let detour_without_explicit_resolver: Options =
        serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "route": {"default_domain_resolver": "missing"},
            "dns": {"servers": [{"type": "hosts", "tag": "local"}]},
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "transport",
                    "domain_resolver": "local"
                },
                {
                    "type": "socks",
                    "tag": "proxy",
                    "version": "4",
                    "server": "127.0.0.1",
                    "server_port": 1080,
                    "detour": "transport"
                }
            ]
        }))
        .unwrap();
    Runtime::from_options(detour_without_explicit_resolver)
        .expect("route default resolver must not wrap an explicit detour");

    let detour_with_explicit_missing_resolver: Options =
        serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "local"}]},
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "transport",
                    "connect_timeout": "5s"
                },
                {
                    "type": "socks",
                    "tag": "proxy",
                    "server": "proxy.example",
                    "server_port": 1080,
                    "detour": "transport",
                    "domain_resolver": "missing"
                }
            ]
        }))
        .unwrap();
    let error = Runtime::from_options(detour_with_explicit_missing_resolver)
        .err()
        .expect("explicit resolver must be validated above a detour")
        .to_string();
    assert!(error.contains("missing"), "{error}");

    let naive_resolves_above_detour: Options =
        serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "local"}]},
            "route": {"default_domain_resolver": "missing"},
            "outbounds": [
                {"type": "block", "tag": "transport"},
                {
                    "type": "naive",
                    "tag": "proxy",
                    "server": "proxy.example",
                    "server_port": 443,
                    "detour": "transport",
                    "tls": {"enabled": true}
                }
            ]
        }))
        .unwrap();
    let error = Runtime::from_options(naive_resolves_above_detour)
        .err()
        .expect("Naive must resolve above its explicit detour")
        .to_string();
    assert!(error.contains("missing"), "{error}");

    let naive_requires_unambiguous_resolver: Options =
        serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [
                {"type": "hosts", "tag": "one"},
                {"type": "hosts", "tag": "two"}
            ]},
            "outbounds": [
                {"type": "block", "tag": "transport"},
                {
                    "type": "naive",
                    "tag": "proxy",
                    "server": "proxy.example",
                    "server_port": 443,
                    "detour": "transport",
                    "tls": {"enabled": true}
                }
            ]
        }))
        .unwrap();
    let error = Runtime::from_options(naive_requires_unambiguous_resolver)
        .err()
        .expect("Naive must reject ambiguous DNS transports")
        .to_string();
    assert!(error.contains("missing domain resolver"), "{error}");

    let explicit_resolver_wins: Options =
        serde_json::from_value(serde_json::json!({
            "certificate": {"store": "none"},
            "dns": {"servers": [{"type": "hosts", "tag": "local"}]},
            "route": {"default_domain_resolver": "missing"},
            "outbounds": [{
                "type": "direct",
                "tag": "direct",
                "domain_resolver": "local"
            }]
        }))
        .unwrap();
    Runtime::from_options(explicit_resolver_wins).unwrap();
}

#[test]
fn top_level_dns_rules_are_a_typed_library_api() {
    use singbox::option::{
        DefaultDnsRuleMatcherOptions, DefaultDnsRuleOptions,
        DnsRouteActionOptions, DnsRuleActionKind, DnsRuleActionOptions,
        DnsRuleOptions,
    };

    let rule = DnsRuleOptions::Default(Box::new(DefaultDnsRuleOptions {
        matcher: DefaultDnsRuleMatcherOptions {
            domain_suffix: Listable(vec!["example.com".into()]),
            ..Default::default()
        },
        action: DnsRuleActionOptions {
            race: false,
            action: DnsRuleActionKind::Route(DnsRouteActionOptions {
                server: "local".into(),
                ..Default::default()
            }),
        },
    }));
    let options = Options {
        certificate: Some(CertificateOptions {
            store: CertificateStoreKind::None,
            ..Default::default()
        }),
        dns: Some(singbox::option::DnsOptions {
            servers: vec![
                serde_json::from_value(serde_json::json!({
                    "type": "hosts",
                    "tag": "local"
                }))
                .unwrap(),
            ],
            rules: vec![rule],
            final_server: "local".into(),
            ..Default::default()
        }),
        outbounds: vec![
            serde_json::from_value(serde_json::json!({
                "type": "direct",
                "tag": "direct"
            }))
            .unwrap(),
        ],
        ..Default::default()
    };
    let runtime = Runtime::from_options(options).unwrap();
    assert_eq!(
        runtime.options().dns.as_ref().unwrap().rules[0]
            .to_value()
            .unwrap(),
        serde_json::json!({
            "domain_suffix": "example.com",
            "server": "local"
        })
    );
}

#[test]
fn rule_set_sources_are_a_typed_library_api() {
    use singbox::option::{
        DefaultHeadlessRuleOptions, HeadlessRuleOptions, HttpClientReference,
        InlineRuleSetOptions, RemoteRuleSetOptions, RuleSetOptions,
    };

    let rule_sets = vec![
        RuleSetOptions::Inline(InlineRuleSetOptions {
            tag: Listable(vec!["private".into()]),
            rules: vec![HeadlessRuleOptions::Default(Box::new(
                DefaultHeadlessRuleOptions {
                    ip_cidr: Listable(vec!["192.168.0.0/16".into()]),
                    ..Default::default()
                },
            ))],
        }),
        RuleSetOptions::Remote(RemoteRuleSetOptions {
            tag: Listable(vec!["ads".into()]),
            url: "https://example.com/ads.srs".into(),
            http_client: Some(HttpClientReference::Tag("rules".into())),
            ..Default::default()
        }),
    ];
    assert_eq!(rule_sets[0].kind(), "inline");
    assert_eq!(
        rule_sets[1].remote().unwrap().url,
        "https://example.com/ads.srs"
    );
    let encoded = serde_json::to_value(&rule_sets).unwrap();
    assert!(encoded[0].get("type").is_none());
    assert_eq!(encoded[1]["type"], "remote");
}

#[test]
fn excluded_experimental_services_keep_typed_migration_options() {
    use singbox::option::{
        DebugOptions, ExperimentalOptions, MemoryBytes, V2RayApiOptions,
        V2RayStatsServiceOptions,
    };

    let experimental = ExperimentalOptions {
        v2ray_api: Some(V2RayApiOptions {
            listen: "127.0.0.1:10085".into(),
            stats: Some(V2RayStatsServiceOptions {
                enabled: true,
                inbounds: vec!["mixed-in".into()],
                outbounds: vec!["proxy".into()],
                users: vec!["alice".into()],
            }),
        }),
        debug: Some(DebugOptions {
            gc_percent: Some(50),
            memory_limit: Some(MemoryBytes(512 * 1024 * 1024)),
            ..Default::default()
        }),
        ..Default::default()
    };
    let encoded = serde_json::to_value(&experimental).unwrap();
    assert_eq!(encoded["v2ray_api"]["stats"]["enabled"], true);
    assert_eq!(encoded["debug"]["memory_limit"], 512 * 1024 * 1024_u64);
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::test]
async fn route_auto_detect_interface_is_applied_by_the_library_runtime() {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    let options: Options = serde_json::from_value(serde_json::json!({
        "route": {"auto_detect_interface": true},
        "outbounds": [{"type": "direct", "tag": "direct"}]
    }))
    .unwrap();
    let runtime = Runtime::from_options(options).unwrap();
    let dialer = runtime.outbounds().outbound("direct").unwrap();
    let mut stream = dialer.dial_tcp(&address.into()).await.unwrap();
    stream.write_all(b"auto").await.unwrap();
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"auto");
    echo.await.unwrap();
}
