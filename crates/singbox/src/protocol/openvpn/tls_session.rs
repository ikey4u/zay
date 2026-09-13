use std::{
    future::{Future, ready},
    io,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use openssl::ssl::{Ssl, SslContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_openssl::SslStream;

use super::{
    ClientPullChallengeContext, ClientPullError, ClientPullOptions,
    ClientPullResult, CompressionSettings, DataChannelFraming,
    DataRenegotiationBudget, OpenVpnDataCodecError, OpenVpnPacketTransport,
    Packet, PushedOptions, ServerControlError, ServerControlEvent,
    ServerControlMachine, ServerControlOptions, ServerPushAssignment,
    SessionManager, TLS_IV_PROTO_TLS_KEY_EXPORT, TLS_PRF_KEY_MATERIAL_LENGTH,
    TlsControlChannelCore, TlsControlChannelHandle, TlsControlProtection,
    TlsDataPlane, TlsKeyMethodMessage, TlsKeySource,
    TlsRenegotiationChannelHandle, accept_initial_client_hard_reset,
    accept_server_hard_reset, advertised_data_ciphers, build_client_hard_reset,
    build_server_hard_reset, build_tls_options_string,
    derive_tls_key_material_prf, extract_remote_cipher_name,
    new_tls_data_codec, peer_supports_iv_proto_flag,
    pull_client_configuration_with_challenges, select_server_cipher,
    spawn_tls_control_channel, tunnel_uses_key_material_export,
};

pub struct OpenVpnTlsSession {
    pub tls: SslStream<DuplexStream>,
    pub control: TlsControlChannelHandle,
    pub session: Arc<SessionManager>,
    pub initial_peer_reset: Packet,
}

pub struct OpenVpnTlsRenegotiationSession {
    pub tls: SslStream<DuplexStream>,
    pub control: TlsRenegotiationChannelHandle,
    pub session: Arc<SessionManager>,
}

pub async fn establish_tls_client_renegotiation(
    parent_control: &TlsControlChannelHandle,
    parent_session: &Arc<SessionManager>,
    context: &SslContext,
    protection: &TlsControlProtection,
    key_id: u8,
    handshake_timeout: Duration,
    remote_is_ipv6: bool,
) -> Result<OpenVpnTlsRenegotiationSession, TlsSessionError> {
    let session = Arc::new(parent_session.renegotiation(key_id));
    let driver = parent_control
        .register_renegotiation_channel(
            TlsControlChannelCore::new(
                session.clone(),
                protection.new_session_protection(),
                Vec::new(),
                remote_is_ipv6,
            ),
            None,
        )
        .await?;
    driver.send_initial_soft_reset().await?;
    let (stream, control) = driver.into_stream_and_handle();
    let mut tls = SslStream::new(Ssl::new(context)?, stream)?;
    tokio::time::timeout(handshake_timeout, Pin::new(&mut tls).connect())
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)??;
    Ok(OpenVpnTlsRenegotiationSession {
        tls,
        control,
        session,
    })
}

pub async fn establish_tls_client_renegotiation_from_reset(
    parent_control: &TlsControlChannelHandle,
    parent_session: &Arc<SessionManager>,
    context: &SslContext,
    protection: &TlsControlProtection,
    soft_reset: &Packet,
    handshake_timeout: Duration,
    remote_is_ipv6: bool,
) -> Result<OpenVpnTlsRenegotiationSession, TlsSessionError> {
    let session = Arc::new(parent_session.renegotiation(soft_reset.key_id));
    let driver = parent_control
        .register_renegotiation_channel(
            TlsControlChannelCore::new(
                session.clone(),
                protection.new_session_protection(),
                Vec::new(),
                remote_is_ipv6,
            ),
            Some(soft_reset),
        )
        .await?;
    let (stream, control) = driver.into_stream_and_handle();
    let mut tls = SslStream::new(Ssl::new(context)?, stream)?;
    tokio::time::timeout(handshake_timeout, Pin::new(&mut tls).connect())
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)??;
    Ok(OpenVpnTlsRenegotiationSession {
        tls,
        control,
        session,
    })
}

pub async fn establish_tls_server_renegotiation(
    parent_control: &TlsControlChannelHandle,
    parent_session: &Arc<SessionManager>,
    context: &SslContext,
    protection: &TlsControlProtection,
    soft_reset: &Packet,
    handshake_timeout: Duration,
    remote_is_ipv6: bool,
) -> Result<OpenVpnTlsRenegotiationSession, TlsSessionError> {
    let session = Arc::new(parent_session.renegotiation(soft_reset.key_id));
    let driver = parent_control
        .register_renegotiation_channel(
            TlsControlChannelCore::new(
                session.clone(),
                protection.new_session_protection(),
                Vec::new(),
                remote_is_ipv6,
            ),
            Some(soft_reset),
        )
        .await?;
    let (stream, control) = driver.into_stream_and_handle();
    let mut tls = SslStream::new(Ssl::new(context)?, stream)?;
    tokio::time::timeout(handshake_timeout, Pin::new(&mut tls).accept())
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)??;
    Ok(OpenVpnTlsRenegotiationSession {
        tls,
        control,
        session,
    })
}

pub async fn establish_tls_server_renegotiation_local(
    parent_control: &TlsControlChannelHandle,
    parent_session: &Arc<SessionManager>,
    context: &SslContext,
    protection: &TlsControlProtection,
    key_id: u8,
    handshake_timeout: Duration,
    remote_is_ipv6: bool,
) -> Result<OpenVpnTlsRenegotiationSession, TlsSessionError> {
    let session = Arc::new(parent_session.renegotiation(key_id));
    let driver = parent_control
        .register_renegotiation_channel(
            TlsControlChannelCore::new(
                session.clone(),
                protection.new_session_protection(),
                Vec::new(),
                remote_is_ipv6,
            ),
            None,
        )
        .await?;
    driver.send_initial_soft_reset().await?;
    let (stream, control) = driver.into_stream_and_handle();
    let mut tls = SslStream::new(Ssl::new(context)?, stream)?;
    tokio::time::timeout(handshake_timeout, Pin::new(&mut tls).accept())
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)??;
    Ok(OpenVpnTlsRenegotiationSession {
        tls,
        control,
        session,
    })
}

pub async fn establish_tls_client_session(
    transport: Arc<dyn OpenVpnPacketTransport>,
    context: &SslContext,
    mut protection: TlsControlProtection,
    wrapped_client_key: Vec<u8>,
    tls_timeout: Duration,
    handshake_timeout: Duration,
    remote_is_ipv6: bool,
) -> Result<OpenVpnTlsSession, TlsSessionError> {
    let session = Arc::new(
        SessionManager::new()
            .map_err(|error| TlsSessionError::Random(error.to_string()))?,
    );
    let reset =
        build_client_hard_reset(&session, &protection, &wrapped_client_key)?;
    transport.write_packet(&reset).await?;
    let deadline = tokio::time::Instant::now() + handshake_timeout;
    let mut retry = super::HandshakeRetrySchedule::new(tls_timeout);
    let server_reset = loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(TlsSessionError::HandshakeTimeout);
        }
        let wait = retry.current().min(deadline - now);
        match tokio::time::timeout(wait, transport.read_packet()).await {
            Ok(Ok(raw)) => match accept_server_hard_reset(
                &session,
                &mut protection,
                !wrapped_client_key.is_empty(),
                &raw,
            ) {
                Ok(reset) => break reset.packet,
                Err(_) => continue,
            },
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                transport.write_packet(&reset).await?;
                retry.advance();
            }
        }
    };
    let core = TlsControlChannelCore::new(
        session.clone(),
        protection,
        wrapped_client_key,
        remote_is_ipv6,
    );
    core.seed_incoming_packet(&server_reset);
    let (stream, control) =
        spawn_tls_control_channel(core, transport).into_stream_and_handle();
    let mut tls = SslStream::new(Ssl::new(context)?, stream)?;
    tokio::time::timeout_at(deadline, Pin::new(&mut tls).connect())
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)??;
    Ok(OpenVpnTlsSession {
        tls,
        control,
        session,
        initial_peer_reset: server_reset,
    })
}

pub async fn establish_tls_server_session(
    transport: Arc<dyn OpenVpnPacketTransport>,
    context: &SslContext,
    static_protection: &TlsControlProtection,
    handshake_timeout: Duration,
    remote_is_ipv6: bool,
) -> Result<OpenVpnTlsSession, TlsSessionError> {
    let deadline = tokio::time::Instant::now() + handshake_timeout;
    let raw = tokio::time::timeout_at(deadline, transport.read_packet())
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)??;
    let (client_reset, protection) =
        accept_initial_client_hard_reset(static_protection, &raw)?;
    let session = Arc::new(
        SessionManager::new()
            .map_err(|error| TlsSessionError::Random(error.to_string()))?,
    );
    session.set_remote_session_id(client_reset.local_session_id);
    let reset = build_server_hard_reset(
        &session,
        &protection,
        client_reset.id,
        Vec::new(),
    )?;
    transport.write_packet(&reset).await?;
    let core = TlsControlChannelCore::new(
        session.clone(),
        protection,
        Vec::new(),
        remote_is_ipv6,
    );
    core.seed_incoming_packet(&client_reset);
    let (stream, control) =
        spawn_tls_control_channel(core, transport).into_stream_and_handle();
    let mut tls = SslStream::new(Ssl::new(context)?, stream)?;
    tokio::time::timeout_at(deadline, Pin::new(&mut tls).accept())
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)??;
    Ok(OpenVpnTlsSession {
        tls,
        control,
        session,
        initial_peer_reset: client_reset,
    })
}

pub async fn exchange_client_key_method(
    tls: &mut SslStream<DuplexStream>,
    mut message: TlsKeyMethodMessage,
) -> Result<ClientKeyMethodExchange, TlsSessionError> {
    if message.key_source.random1.is_empty() {
        message.key_source = TlsKeySource::generate(true)
            .map_err(|error| TlsSessionError::Random(error.to_string()))?;
    }
    tls.write_all(&message.encode(false)?).await?;
    tls.flush().await?;
    let response = read_tls_control_record(tls).await?;
    let server_message = TlsKeyMethodMessage::parse(&response, true)?;
    Ok(ClientKeyMethodExchange {
        client_key_source: message.key_source,
        server_message,
    })
}

pub async fn exchange_server_key_method(
    tls: &mut SslStream<DuplexStream>,
    response: TlsKeyMethodMessage,
) -> Result<TlsKeyMethodMessage, TlsSessionError> {
    let request = read_tls_control_record(tls).await?;
    let client_message = TlsKeyMethodMessage::parse(&request, false)
        .map_err(TlsSessionError::from)?;
    tls.write_all(&response.encode(true)?).await?;
    tls.flush().await?;
    Ok(client_message)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyMethodExchange {
    pub client_key_source: TlsKeySource,
    pub server_message: TlsKeyMethodMessage,
}

pub fn derive_session_key_material(
    tls: &SslStream<DuplexStream>,
    client_key_source: &TlsKeySource,
    server_key_source: &TlsKeySource,
    client_session_id: [u8; 8],
    server_session_id: [u8; 8],
    use_exporter: bool,
) -> Result<Vec<u8>, TlsSessionError> {
    if use_exporter {
        let mut material = vec![0; TLS_PRF_KEY_MATERIAL_LENGTH];
        tls.ssl().export_keying_material(
            &mut material,
            "EXPORTER-OpenVPN-datakeys",
            None,
        )?;
        return Ok(material);
    }
    if client_key_source.pre_master.len() != 48
        || client_key_source.random1.len() != 32
        || client_key_source.random2.len() != 32
        || server_key_source.random1.len() != 32
        || server_key_source.random2.len() != 32
    {
        return Err(TlsSessionError::IncompleteKeySource);
    }
    Ok(derive_tls_key_material_prf(
        &client_key_source.pre_master,
        &client_key_source.random1,
        &server_key_source.random1,
        &client_key_source.random2,
        &server_key_source.random2,
        client_session_id,
        server_session_id,
    ))
}

pub struct ClientTlsDataChannelOptions {
    pub replay_window_size: u32,
    pub replay_window_time: Duration,
    pub framing: Option<DataChannelFraming>,
    pub peer_id: Option<u32>,
    pub local_options_string: String,
    pub renegotiation_bytes: u64,
    pub renegotiation_packets: u64,
}

impl Default for ClientTlsDataChannelOptions {
    fn default() -> Self {
        Self {
            replay_window_size: 0,
            replay_window_time: Duration::ZERO,
            framing: None,
            peer_id: None,
            local_options_string: String::new(),
            renegotiation_bytes: 0,
            renegotiation_packets: 0,
        }
    }
}

pub struct NegotiatedOpenVpnClientSession {
    pub session: OpenVpnTlsSession,
    pub data_plane: TlsDataPlane,
    pub pull: ClientPullResult,
    pub server_key_method: TlsKeyMethodMessage,
    pub renegotiation_budget: DataRenegotiationBudget,
}

pub struct NegotiatedOpenVpnClientRenegotiation {
    pub session: OpenVpnTlsRenegotiationSession,
    pub data_plane: TlsDataPlane,
    pub server_key_method: TlsKeyMethodMessage,
}

pub async fn negotiate_tls_client_renegotiation_data_channel(
    mut session: OpenVpnTlsRenegotiationSession,
    client_message: TlsKeyMethodMessage,
    selected_cipher: &str,
    selected_auth: &str,
    data_options: ClientTlsDataChannelOptions,
) -> Result<NegotiatedOpenVpnClientRenegotiation, TlsClientNegotiationError> {
    let local_options_string = if data_options.local_options_string.is_empty() {
        client_message.options_string.clone()
    } else {
        data_options.local_options_string
    };
    let exchange =
        exchange_client_key_method(&mut session.tls, client_message).await?;
    let use_exporter = peer_supports_iv_proto_flag(
        &exchange.server_message.peer_info,
        TLS_IV_PROTO_TLS_KEY_EXPORT,
    );
    let key_material = derive_session_key_material(
        &session.tls,
        &exchange.client_key_source,
        &exchange.server_message.key_source,
        session.session.local_session_id(),
        session
            .session
            .remote_session_id()
            .ok_or(TlsSessionError::IncompleteKeySource)?,
        use_exporter,
    )?;
    let codec = new_tls_data_codec(
        &key_material,
        false,
        selected_cipher,
        selected_auth,
        data_options.replay_window_size,
        data_options.replay_window_time,
    )?;
    let data_plane = TlsDataPlane::new(
        session.session.clone(),
        codec,
        data_options.framing,
        data_options.peer_id,
        local_options_string,
    );
    Ok(NegotiatedOpenVpnClientRenegotiation {
        session,
        data_plane,
        server_key_method: exchange.server_message,
    })
}

/// Finish key-method 2 and PUSH negotiation, derive the initial traffic keys,
/// and install a client data plane. This is the reusable boundary consumed by
/// the eventual OpenVPN endpoint lifecycle.
pub async fn negotiate_tls_client_data_channel(
    session: OpenVpnTlsSession,
    client_message: TlsKeyMethodMessage,
    pull_options: ClientPullOptions,
    data_options: ClientTlsDataChannelOptions,
) -> Result<NegotiatedOpenVpnClientSession, TlsClientNegotiationError> {
    negotiate_tls_client_data_channel_with_challenges(
        session,
        client_message,
        pull_options,
        data_options,
        None,
    )
    .await
}

pub async fn negotiate_tls_client_data_channel_with_challenges(
    mut session: OpenVpnTlsSession,
    client_message: TlsKeyMethodMessage,
    mut pull_options: ClientPullOptions,
    mut data_options: ClientTlsDataChannelOptions,
    challenge_context: Option<&ClientPullChallengeContext>,
) -> Result<NegotiatedOpenVpnClientSession, TlsClientNegotiationError> {
    if data_options.local_options_string.is_empty() {
        data_options
            .local_options_string
            .clone_from(&client_message.options_string);
    }
    let exchange =
        exchange_client_key_method(&mut session.tls, client_message).await?;
    if pull_options.remote_cipher.is_empty() {
        pull_options.remote_cipher =
            extract_remote_cipher_name(&exchange.server_message.options_string)
                .unwrap_or_default();
    }
    let pull = pull_client_configuration_with_challenges(
        &mut session.tls,
        pull_options,
        challenge_context,
    )
    .await?;
    let use_exporter = tunnel_uses_key_material_export(
        &pull.options.key_derivation,
        &pull.options.protocol_flags,
    );
    let key_material = derive_session_key_material(
        &session.tls,
        &exchange.client_key_source,
        &exchange.server_message.key_source,
        session.session.local_session_id(),
        session
            .session
            .remote_session_id()
            .ok_or(TlsSessionError::IncompleteKeySource)?,
        use_exporter,
    )?;
    let peer_id = pull.options.peer_id.or(data_options.peer_id);
    let codec = new_tls_data_codec(
        &key_material,
        false,
        &pull.selected_cipher,
        &pull.selected_auth,
        data_options.replay_window_size,
        data_options.replay_window_time,
    )?;
    let renegotiation_budget = DataRenegotiationBudget::new(
        &pull.selected_cipher,
        data_options.renegotiation_bytes,
        data_options.renegotiation_packets,
        session.session.current_key_id(),
    );
    let data_plane = TlsDataPlane::new(
        session.session.clone(),
        codec,
        data_options.framing,
        peer_id,
        data_options.local_options_string,
    );
    Ok(NegotiatedOpenVpnClientSession {
        session,
        data_plane,
        pull,
        server_key_method: exchange.server_message,
        renegotiation_budget,
    })
}

#[derive(Clone)]
pub struct ServerTlsDataChannelOptions {
    pub configured_ciphers: Vec<String>,
    pub fallback_cipher: String,
    pub configured_auth: String,
    pub protocol: String,
    pub tls_auth_enabled: bool,
    pub compression: CompressionSettings,
    pub tun_mtu: u32,
    pub server_peer_info: String,
    pub pushed_options: PushedOptions,
    pub assignment: ServerPushAssignment,
    pub replay_window_size: u32,
    pub replay_window_time: Duration,
    pub framing: Option<DataChannelFraming>,
    pub renegotiation_bytes: u64,
    pub renegotiation_packets: u64,
    pub handshake_window: Duration,
}

impl Default for ServerTlsDataChannelOptions {
    fn default() -> Self {
        Self {
            configured_ciphers: Vec::new(),
            fallback_cipher: String::new(),
            configured_auth: String::new(),
            protocol: "udp".into(),
            tls_auth_enabled: false,
            compression: CompressionSettings::default(),
            tun_mtu: 1500,
            server_peer_info: String::new(),
            pushed_options: PushedOptions::default(),
            assignment: ServerPushAssignment::default(),
            replay_window_size: 0,
            replay_window_time: Duration::ZERO,
            framing: None,
            renegotiation_bytes: 0,
            renegotiation_packets: 0,
            handshake_window: Duration::from_secs(60),
        }
    }
}

pub struct NegotiatedOpenVpnServerSession {
    pub session: OpenVpnTlsSession,
    pub data_plane: TlsDataPlane,
    pub client_key_method: TlsKeyMethodMessage,
    pub selected_cipher: String,
    pub selected_auth: String,
    pub renegotiation_budget: DataRenegotiationBudget,
}

pub struct ServerTlsRenegotiationDataOptions {
    pub selected_cipher: String,
    pub selected_auth: String,
    pub local_options_string: String,
    pub server_peer_info: String,
    pub replay_window_size: u32,
    pub replay_window_time: Duration,
    pub framing: Option<DataChannelFraming>,
    pub peer_id: Option<u32>,
}

pub struct NegotiatedOpenVpnServerRenegotiation {
    pub session: OpenVpnTlsRenegotiationSession,
    pub data_plane: TlsDataPlane,
    pub client_key_method: TlsKeyMethodMessage,
}

pub async fn negotiate_tls_server_renegotiation_data_channel<F>(
    mut session: OpenVpnTlsRenegotiationSession,
    options: ServerTlsRenegotiationDataOptions,
    verify_credentials: F,
) -> Result<NegotiatedOpenVpnServerRenegotiation, TlsServerNegotiationError>
where
    F: FnOnce(&str, &str) -> Result<(), String>,
{
    let request = read_tls_control_record(&mut session.tls)
        .await
        .map_err(TlsSessionError::from)?;
    let client_message = TlsKeyMethodMessage::parse(&request, false)
        .map_err(TlsSessionError::from)?;
    if verify_credentials(&client_message.username, &client_message.password)
        .is_err()
    {
        session
            .tls
            .write_all(&super::tls_control_string_payload(
                &super::build_auth_failed_payload("invalid credentials"),
            ))
            .await
            .map_err(TlsSessionError::from)?;
        return Err(TlsServerNegotiationError::AuthenticationRejected);
    }
    let server_key_source = TlsKeySource::generate(false)
        .map_err(|error| TlsSessionError::Random(error.to_string()))?;
    let server_message = TlsKeyMethodMessage {
        options_string: options.local_options_string.clone(),
        peer_info: options.server_peer_info,
        key_source: server_key_source.clone(),
        ..TlsKeyMethodMessage::default()
    };
    let use_exporter = peer_supports_iv_proto_flag(
        &client_message.peer_info,
        TLS_IV_PROTO_TLS_KEY_EXPORT,
    );
    let key_material = derive_session_key_material(
        &session.tls,
        &client_message.key_source,
        &server_key_source,
        session
            .session
            .remote_session_id()
            .ok_or(TlsSessionError::IncompleteKeySource)?,
        session.session.local_session_id(),
        use_exporter,
    )?;
    let codec = new_tls_data_codec(
        &key_material,
        true,
        &options.selected_cipher,
        &options.selected_auth,
        options.replay_window_size,
        options.replay_window_time,
    )?;
    let data_plane = TlsDataPlane::new(
        session.session.clone(),
        codec,
        options.framing,
        options.peer_id,
        options.local_options_string,
    );
    session
        .tls
        .write_all(&server_message.encode(true).map_err(TlsSessionError::from)?)
        .await
        .map_err(TlsSessionError::from)?;
    Ok(NegotiatedOpenVpnServerRenegotiation {
        session,
        data_plane,
        client_key_method: client_message,
    })
}

/// Complete server key-method, authentication and PUSH negotiation, then
/// install the initial traffic keys. A rejected credential still receives a
/// valid key-method response before `AUTH_FAILED` is emitted on PUSH request.
pub async fn negotiate_tls_server_data_channel<F>(
    session: OpenVpnTlsSession,
    options: ServerTlsDataChannelOptions,
    verify_credentials: F,
) -> Result<NegotiatedOpenVpnServerSession, TlsServerNegotiationError>
where
    F: FnOnce(&str, &str) -> Result<(), String>,
{
    let assignment = options.assignment.clone();
    negotiate_tls_server_data_channel_with_assignment(
        session,
        options,
        move |username, password| {
            verify_credentials(username, password).map(|()| assignment)
        },
    )
    .await
}

/// Variant used by a multi-client server: credentials are verified after the
/// client's key-method record is available, and a per-client address/peer-id
/// assignment is returned atomically with successful authentication.
pub async fn negotiate_tls_server_data_channel_with_assignment<F>(
    session: OpenVpnTlsSession,
    options: ServerTlsDataChannelOptions,
    authorize_and_assign: F,
) -> Result<NegotiatedOpenVpnServerSession, TlsServerNegotiationError>
where
    F: FnOnce(&str, &str) -> Result<ServerPushAssignment, String>,
{
    negotiate_tls_server_data_channel_with_async_assignment(
        session,
        options,
        move |username, password| {
            ready(authorize_and_assign(username, password))
        },
    )
    .await
}

/// Async authorization variant used by the server runtime when an existing
/// authenticated identity must be closed before its sticky tunnel address can
/// be reassigned to the replacement session.
pub async fn negotiate_tls_server_data_channel_with_async_assignment<F, Fut>(
    mut session: OpenVpnTlsSession,
    mut options: ServerTlsDataChannelOptions,
    authorize_and_assign: F,
) -> Result<NegotiatedOpenVpnServerSession, TlsServerNegotiationError>
where
    F: FnOnce(&str, &str) -> Fut,
    Fut: Future<Output = Result<ServerPushAssignment, String>>,
{
    let deadline = tokio::time::Instant::now() + options.handshake_window;
    let request = tokio::time::timeout_at(
        deadline,
        read_tls_control_record(&mut session.tls),
    )
    .await
    .map_err(|_| TlsSessionError::HandshakeTimeout)?
    .map_err(TlsSessionError::from)?;
    let client_message = TlsKeyMethodMessage::parse(&request, false)
        .map_err(TlsSessionError::from)?;
    let (assignment, mut authentication_failure) = match authorize_and_assign(
        &client_message.username,
        &client_message.password,
    )
    .await
    {
        Ok(assignment) => (assignment, None),
        Err(error) => (ServerPushAssignment::default(), Some(error)),
    };
    let selected_cipher = match select_server_cipher(
        &options.configured_ciphers,
        &options.fallback_cipher,
        &client_message.peer_info,
        &client_message.options_string,
    ) {
        Ok(cipher) => cipher,
        Err(_) => {
            if authentication_failure.is_none() {
                authentication_failure = Some(
                    "Data channel cipher negotiation failed (no shared cipher)"
                        .into(),
                );
            }
            advertised_data_ciphers(&options.configured_ciphers)
                .into_iter()
                .next()
                .unwrap_or_else(|| "AES-256-GCM".into())
        }
    };
    let selected_auth = if options.configured_auth.is_empty() {
        "SHA1".to_owned()
    } else {
        options.configured_auth.clone()
    };
    let server_key_source = TlsKeySource::generate(false)
        .map_err(|error| TlsSessionError::Random(error.to_string()))?;
    let local_options_string = build_tls_options_string(
        &options.protocol,
        false,
        options.tls_auth_enabled,
        options.compression,
        &selected_cipher,
        &selected_auth,
        options.tun_mtu,
    );
    let response = TlsKeyMethodMessage {
        options_string: local_options_string.clone(),
        peer_info: options.server_peer_info.clone(),
        key_source: server_key_source.clone(),
        ..TlsKeyMethodMessage::default()
    }
    .encode(true)
    .map_err(TlsSessionError::from)?;
    session
        .tls
        .write_all(&response)
        .await
        .map_err(TlsSessionError::from)?;

    let peer_id = assignment.peer_id.filter(|_| {
        super::peer_supports_iv_proto_flag(
            &client_message.peer_info,
            super::TLS_IV_PROTO_DATA_V2,
        )
    });
    let mut control = ServerControlMachine::new(ServerControlOptions {
        peer_info: client_message.peer_info.clone(),
        selected_cipher: selected_cipher.clone(),
        pushed_options: std::mem::take(&mut options.pushed_options),
        assignment,
        authentication_failure,
    });
    loop {
        let record = tokio::time::timeout_at(
            deadline,
            read_tls_control_record(&mut session.tls),
        )
        .await
        .map_err(|_| TlsSessionError::HandshakeTimeout)?
        .map_err(TlsSessionError::from)?;
        match control.accept_record(&record)? {
            ServerControlEvent::Ignored => continue,
            ServerControlEvent::AuthenticationRejected { payload } => {
                session
                    .tls
                    .write_all(&payload)
                    .await
                    .map_err(TlsSessionError::from)?;
                return Err(TlsServerNegotiationError::AuthenticationRejected);
            }
            ServerControlEvent::PushReply { payloads, .. } => {
                for payload in payloads {
                    session
                        .tls
                        .write_all(&payload)
                        .await
                        .map_err(TlsSessionError::from)?;
                }
                break;
            }
        }
    }

    let use_exporter = peer_supports_iv_proto_flag(
        &client_message.peer_info,
        TLS_IV_PROTO_TLS_KEY_EXPORT,
    );
    let key_material = derive_session_key_material(
        &session.tls,
        &client_message.key_source,
        &server_key_source,
        session
            .session
            .remote_session_id()
            .ok_or(TlsSessionError::IncompleteKeySource)?,
        session.session.local_session_id(),
        use_exporter,
    )?;
    let codec = new_tls_data_codec(
        &key_material,
        true,
        &selected_cipher,
        &selected_auth,
        options.replay_window_size,
        options.replay_window_time,
    )?;
    let renegotiation_budget = DataRenegotiationBudget::new(
        &selected_cipher,
        options.renegotiation_bytes,
        options.renegotiation_packets,
        session.session.current_key_id(),
    );
    let data_plane = TlsDataPlane::new(
        session.session.clone(),
        codec,
        options.framing,
        peer_id,
        local_options_string,
    );
    Ok(NegotiatedOpenVpnServerSession {
        session,
        data_plane,
        client_key_method: client_message,
        selected_cipher,
        selected_auth,
        renegotiation_budget,
    })
}

async fn read_tls_control_record(
    tls: &mut SslStream<DuplexStream>,
) -> io::Result<Vec<u8>> {
    let mut record = vec![0; 16 * 1024];
    let length = tls.read(&mut record).await?;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "OpenVPN TLS control channel closed",
        ));
    }
    record.truncate(length);
    Ok(record)
}

#[derive(Debug, thiserror::Error)]
pub enum TlsSessionError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    OpenSslStack(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    OpenSsl(#[from] openssl::ssl::Error),
    #[error(transparent)]
    Reset(#[from] super::ResetError),
    #[error(transparent)]
    KeyMethod(#[from] super::KeyMethodError),
    #[error("OpenVPN TLS handshake timed out")]
    HandshakeTimeout,
    #[error("OpenVPN random source failed: {0}")]
    Random(String),
    #[error("OpenVPN TLS key source is incomplete")]
    IncompleteKeySource,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsClientNegotiationError {
    #[error(transparent)]
    TlsSession(#[from] TlsSessionError),
    #[error(transparent)]
    Pull(#[from] ClientPullError),
    #[error(transparent)]
    DataCodec(#[from] OpenVpnDataCodecError),
}

#[derive(Debug, thiserror::Error)]
pub enum TlsServerNegotiationError {
    #[error(transparent)]
    TlsSession(#[from] TlsSessionError),
    #[error(transparent)]
    ServerControl(#[from] ServerControlError),
    #[error(transparent)]
    DataCodec(#[from] OpenVpnDataCodecError),
    #[error("OpenVPN authentication failed")]
    AuthenticationRejected,
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    };
    use tokio::sync::{Mutex, mpsc};

    use super::*;
    use crate::protocol::openvpn::{
        ClientPullStateError, IncomingControlEvent, IncomingDataEvent,
        OpenVpnActiveDataSession, OpenVpnTlsContextOptions, OpenVpnTlsRole,
        ServerPushAssignment, TLS_IV_PROTO_DATA_V2,
        TLS_IV_PROTO_TLS_KEY_EXPORT, TlsMaterial, VerifyClientCertMode,
        build_openssl_tls_context,
    };

    struct MemoryPacketTransport {
        receive: Mutex<mpsc::Receiver<Vec<u8>>>,
        send: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl OpenVpnPacketTransport for MemoryPacketTransport {
        async fn read_packet(&self) -> io::Result<Vec<u8>> {
            self.receive.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "packet link closed",
                )
            })
        }

        async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            self.send.send(packet.to_vec()).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "packet link closed")
            })
        }
    }

    fn packet_pair() -> (
        Arc<dyn OpenVpnPacketTransport>,
        Arc<dyn OpenVpnPacketTransport>,
    ) {
        let (left_send, right_receive) = mpsc::channel(128);
        let (right_send, left_receive) = mpsc::channel(128);
        (
            Arc::new(MemoryPacketTransport {
                receive: Mutex::new(left_receive),
                send: left_send,
            }),
            Arc::new(MemoryPacketTransport {
                receive: Mutex::new(right_receive),
                send: right_send,
            }),
        )
    }

    fn contexts() -> (SslContext, SslContext) {
        let mut params =
            CertificateParams::new(vec!["vpn.test".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "vpn.test");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap().pem().into_bytes();
        let server = build_openssl_tls_context(&OpenVpnTlsContextOptions {
            role: OpenVpnTlsRole::Server,
            certificate: TlsMaterial::from_pem(certificate.clone()),
            key: TlsMaterial::from_pem(key.serialize_pem()),
            verify_client_certificate: VerifyClientCertMode::None,
            ..OpenVpnTlsContextOptions::server()
        })
        .unwrap();
        let client = build_openssl_tls_context(&OpenVpnTlsContextOptions {
            certificate_authority: TlsMaterial::from_pem(certificate),
            remote_certificate_tls: "server".into(),
            ..OpenVpnTlsContextOptions::client()
        })
        .unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn completes_reset_tls_key_method_and_both_key_derivations() {
        let (client_context, server_context) = contexts();
        let (client_transport, server_transport) = packet_pair();
        let timeout = Duration::from_secs(5);
        let server = async {
            let mut session = establish_tls_server_session(
                server_transport,
                &server_context,
                &TlsControlProtection::default(),
                timeout,
                false,
            )
            .await?;
            let server_key_source = TlsKeySource::generate(false)
                .map_err(|error| TlsSessionError::Random(error.to_string()))?;
            let client_message = exchange_server_key_method(
                &mut session.tls,
                TlsKeyMethodMessage {
                    options_string: "V4,tls-server".into(),
                    peer_info: "IV_PROTO=138\n".into(),
                    key_source: server_key_source.clone(),
                    ..TlsKeyMethodMessage::default()
                },
            )
            .await?;
            let prf = derive_session_key_material(
                &session.tls,
                &client_message.key_source,
                &server_key_source,
                session.session.remote_session_id().unwrap(),
                session.session.local_session_id(),
                false,
            )?;
            let exporter = derive_session_key_material(
                &session.tls,
                &client_message.key_source,
                &server_key_source,
                session.session.remote_session_id().unwrap(),
                session.session.local_session_id(),
                true,
            )?;
            Ok::<_, TlsSessionError>((prf, exporter))
        };
        let client = async {
            let mut session = establish_tls_client_session(
                client_transport,
                &client_context,
                TlsControlProtection::default(),
                Vec::new(),
                Duration::from_millis(100),
                timeout,
                false,
            )
            .await?;
            let exchange = exchange_client_key_method(
                &mut session.tls,
                TlsKeyMethodMessage {
                    options_string: "V4,tls-client".into(),
                    username: "alice".into(),
                    password: "secret".into(),
                    peer_info: "IV_PROTO=414\n".into(),
                    ..TlsKeyMethodMessage::default()
                },
            )
            .await?;
            let prf = derive_session_key_material(
                &session.tls,
                &exchange.client_key_source,
                &exchange.server_message.key_source,
                session.session.local_session_id(),
                session.session.remote_session_id().unwrap(),
                false,
            )?;
            let exporter = derive_session_key_material(
                &session.tls,
                &exchange.client_key_source,
                &exchange.server_message.key_source,
                session.session.local_session_id(),
                session.session.remote_session_id().unwrap(),
                true,
            )?;
            Ok::<_, TlsSessionError>((prf, exporter))
        };
        let ((client_prf, client_exporter), (server_prf, server_exporter)) =
            tokio::time::timeout(timeout, async {
                let (server, client) = tokio::join!(server, client);
                Ok::<_, TlsSessionError>((client?, server?))
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client_prf, server_prf);
        assert_eq!(client_exporter, server_exporter);
        assert_ne!(client_prf, client_exporter);
    }

    #[tokio::test]
    async fn performs_a_real_tls_soft_reset_on_a_second_key_state() {
        let (client_context, server_context) = contexts();
        let (client_transport, server_transport) = packet_pair();
        let timeout = Duration::from_secs(5);
        let server_protection = TlsControlProtection::default();
        let (client, mut server) = tokio::time::timeout(timeout, async {
            let client = establish_tls_client_session(
                client_transport,
                &client_context,
                TlsControlProtection::default(),
                Vec::new(),
                Duration::from_millis(100),
                timeout,
                false,
            );
            let server = establish_tls_server_session(
                server_transport,
                &server_context,
                &server_protection,
                timeout,
                false,
            );
            let (client, server) = tokio::join!(client, server);
            Ok::<_, TlsSessionError>((client?, server?))
        })
        .await
        .unwrap()
        .unwrap();

        let client_rekey_protection = TlsControlProtection::default();
        let client_rekey = establish_tls_client_renegotiation(
            &client.control,
            &client.session,
            &client_context,
            &client_rekey_protection,
            1,
            timeout,
            false,
        );
        let server_rekey = async {
            let reset =
                server.control.resets.recv().await.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "soft-reset channel closed",
                    )
                })?;
            let IncomingControlEvent::SoftReset(reset) = reset else {
                return Err(TlsSessionError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected soft reset",
                )));
            };
            establish_tls_server_renegotiation(
                &server.control,
                &server.session,
                &server_context,
                &server_protection,
                &reset,
                timeout,
                false,
            )
            .await
        };
        let (client_rekey, server_rekey) =
            tokio::time::timeout(timeout, async {
                let (client, server) = tokio::join!(client_rekey, server_rekey);
                Ok::<_, TlsSessionError>((client?, server?))
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client_rekey.session.current_key_id(), 1);
        assert_eq!(server_rekey.session.current_key_id(), 1);

        let client_key_method = TlsKeyMethodMessage {
            options_string: "V4,tls-client".into(),
            peer_info: format!("IV_PROTO={TLS_IV_PROTO_TLS_KEY_EXPORT}\n"),
            ..TlsKeyMethodMessage::default()
        };
        let client_data = negotiate_tls_client_renegotiation_data_channel(
            client_rekey,
            client_key_method,
            "AES-256-GCM",
            "SHA1",
            ClientTlsDataChannelOptions::default(),
        );
        let server_data = negotiate_tls_server_renegotiation_data_channel(
            server_rekey,
            ServerTlsRenegotiationDataOptions {
                selected_cipher: "AES-256-GCM".into(),
                selected_auth: "SHA1".into(),
                local_options_string: "V4,tls-server".into(),
                server_peer_info: format!(
                    "IV_PROTO={TLS_IV_PROTO_TLS_KEY_EXPORT}\n"
                ),
                replay_window_size: 0,
                replay_window_time: Duration::ZERO,
                framing: None,
                peer_id: None,
            },
            |_, _| Ok(()),
        );
        let (client_data, server_data) = tokio::time::timeout(timeout, async {
            let (client, server) = tokio::join!(client_data, server_data);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                client?, server?,
            ))
        })
        .await
        .unwrap()
        .unwrap();
        let wire = client_data
            .data_plane
            .encode_payload(b"renegotiated data", 1500)
            .unwrap();
        assert_eq!(
            server_data.data_plane.decode_raw_packet(&wire[0]).unwrap(),
            IncomingDataEvent::Payload(b"renegotiated data".to_vec())
        );
    }

    #[tokio::test]
    async fn client_accepts_a_server_initiated_tls_soft_reset() {
        let (client_context, server_context) = contexts();
        let (client_transport, server_transport) = packet_pair();
        let timeout = Duration::from_secs(5);
        let client_protection = TlsControlProtection::default();
        let server_protection = TlsControlProtection::default();
        let (mut client, server) = tokio::time::timeout(timeout, async {
            let client = establish_tls_client_session(
                client_transport,
                &client_context,
                client_protection.new_session_protection(),
                Vec::new(),
                Duration::from_millis(100),
                timeout,
                false,
            );
            let server = establish_tls_server_session(
                server_transport,
                &server_context,
                &server_protection,
                timeout,
                false,
            );
            let (client, server) = tokio::join!(client, server);
            Ok::<_, TlsSessionError>((client?, server?))
        })
        .await
        .unwrap()
        .unwrap();

        let server_rekey = establish_tls_server_renegotiation_local(
            &server.control,
            &server.session,
            &server_context,
            &server_protection,
            1,
            timeout,
            false,
        );
        let client_rekey = async {
            let reset =
                client.control.resets.recv().await.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "soft-reset channel closed",
                    )
                })?;
            let IncomingControlEvent::SoftReset(reset) = reset else {
                return Err(TlsSessionError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected soft reset",
                )));
            };
            establish_tls_client_renegotiation_from_reset(
                &client.control,
                &client.session,
                &client_context,
                &client_protection,
                &reset,
                timeout,
                false,
            )
            .await
        };
        let (server_rekey, client_rekey) =
            tokio::time::timeout(timeout, async {
                let (server, client) = tokio::join!(server_rekey, client_rekey);
                Ok::<_, TlsSessionError>((server?, client?))
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server_rekey.session.current_key_id(), 1);
        assert_eq!(client_rekey.session.current_key_id(), 1);
    }

    #[tokio::test]
    async fn negotiates_push_and_carries_an_encrypted_data_packet() {
        let (client_context, server_context) = contexts();
        let (client_transport, server_transport) = packet_pair();
        let client_link = client_transport.clone();
        let server_link = server_transport.clone();
        let timeout = Duration::from_secs(5);
        let server = async {
            let session = establish_tls_server_session(
                server_transport,
                &server_context,
                &TlsControlProtection::default(),
                timeout,
                false,
            )
            .await?;
            negotiate_tls_server_data_channel(
                session,
                ServerTlsDataChannelOptions {
                    configured_ciphers: vec!["AES-256-GCM".into()],
                    server_peer_info: "IV_PROTO=138\n".into(),
                    assignment: ServerPushAssignment {
                        peer_id: Some(23),
                        ..ServerPushAssignment::default()
                    },
                    replay_window_size: 64,
                    replay_window_time: Duration::from_secs(15),
                    handshake_window: timeout,
                    ..ServerTlsDataChannelOptions::default()
                },
                |_, _| Ok(()),
            )
            .await
        };
        let client = async {
            let session = establish_tls_client_session(
                client_transport,
                &client_context,
                TlsControlProtection::default(),
                Vec::new(),
                Duration::from_millis(100),
                timeout,
                false,
            )
            .await?;
            negotiate_tls_client_data_channel(
                session,
                TlsKeyMethodMessage {
                    options_string: "V4,tls-client".into(),
                    peer_info: format!(
                        "IV_PROTO={}\nIV_CIPHERS=AES-256-GCM\n",
                        TLS_IV_PROTO_DATA_V2 | TLS_IV_PROTO_TLS_KEY_EXPORT
                    ),
                    ..TlsKeyMethodMessage::default()
                },
                ClientPullOptions {
                    configured_ciphers: vec!["AES-256-GCM".into()],
                    hand_window: timeout,
                    ..ClientPullOptions::default()
                },
                ClientTlsDataChannelOptions {
                    replay_window_size: 64,
                    replay_window_time: Duration::from_secs(15),
                    ..ClientTlsDataChannelOptions::default()
                },
            )
            .await
        };
        let (client, server) = tokio::time::timeout(timeout, async {
            let (server, client) = tokio::join!(server, client);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                client?, server?,
            ))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(client.pull.options.peer_id, Some(23));
        assert_eq!(client.pull.selected_cipher, "AES-256-GCM");
        let client =
            OpenVpnActiveDataSession::from_client(client_link, client, 0);
        let server =
            OpenVpnActiveDataSession::from_server(server_link, server, 0);
        let outcome = client
            .write_data_packet(b"encrypted IP packet")
            .await
            .unwrap();
        assert_eq!(outcome.packet_count, 1);
        let incoming = tokio::time::timeout(timeout, server.read_data_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(incoming, b"encrypted IP packet");

        let client_protection = TlsControlProtection::default();
        let server_protection = TlsControlProtection::default();
        let client_rekey = establish_tls_client_renegotiation(
            &client.tls_session().control,
            &client.tls_session().session,
            &client_context,
            &client_protection,
            1,
            timeout,
            false,
        );
        let server_rekey = async {
            let event = server.next_reset_event().await.map_err(|error| {
                TlsSessionError::Io(io::Error::other(error))
            })?;
            let IncomingControlEvent::SoftReset(reset) = event else {
                return Err(TlsSessionError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected soft reset",
                )));
            };
            establish_tls_server_renegotiation(
                &server.tls_session().control,
                &server.tls_session().session,
                &server_context,
                &server_protection,
                &reset,
                timeout,
                false,
            )
            .await
        };
        let (client_rekey, server_rekey) =
            tokio::time::timeout(timeout, async {
                let (client, server) = tokio::join!(client_rekey, server_rekey);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                    client?, server?,
                ))
            })
            .await
            .unwrap()
            .unwrap();
        let client_rekey = negotiate_tls_client_renegotiation_data_channel(
            client_rekey,
            TlsKeyMethodMessage {
                options_string: "V4,tls-client".into(),
                peer_info: format!(
                    "IV_PROTO={}\n",
                    TLS_IV_PROTO_DATA_V2 | TLS_IV_PROTO_TLS_KEY_EXPORT
                ),
                ..TlsKeyMethodMessage::default()
            },
            "AES-256-GCM",
            "SHA1",
            ClientTlsDataChannelOptions {
                peer_id: Some(23),
                ..ClientTlsDataChannelOptions::default()
            },
        );
        let server_rekey = negotiate_tls_server_renegotiation_data_channel(
            server_rekey,
            ServerTlsRenegotiationDataOptions {
                selected_cipher: "AES-256-GCM".into(),
                selected_auth: "SHA1".into(),
                local_options_string: "V4,tls-server".into(),
                server_peer_info: format!(
                    "IV_PROTO={TLS_IV_PROTO_TLS_KEY_EXPORT}\n"
                ),
                replay_window_size: 0,
                replay_window_time: Duration::ZERO,
                framing: None,
                peer_id: Some(23),
            },
            |_, _| Ok(()),
        );
        let (client_rekey, server_rekey) =
            tokio::time::timeout(timeout, async {
                let (client, server) = tokio::join!(client_rekey, server_rekey);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                    client?, server?,
                ))
            })
            .await
            .unwrap()
            .unwrap();
        let now = std::time::Instant::now();
        assert!(
            client
                .install_client_renegotiation(1, client_rekey, now)
                .await
                .unwrap()
        );
        assert!(
            server
                .install_server_renegotiation(1, server_rekey, now)
                .await
                .unwrap()
        );
        assert_eq!(client.data_plane().session().current_key_id(), 1);
        client
            .write_data_packet(b"IP packet after soft reset")
            .await
            .unwrap();
        let incoming = tokio::time::timeout(timeout, server.read_data_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(incoming, b"IP packet after soft reset");
    }

    #[tokio::test]
    async fn server_finishes_key_method_before_rejecting_credentials() {
        let (client_context, server_context) = contexts();
        let (client_transport, server_transport) = packet_pair();
        let timeout = Duration::from_secs(5);
        let server = async {
            let session = establish_tls_server_session(
                server_transport,
                &server_context,
                &TlsControlProtection::default(),
                timeout,
                false,
            )
            .await
            .unwrap();
            negotiate_tls_server_data_channel(
                session,
                ServerTlsDataChannelOptions {
                    configured_ciphers: vec!["AES-256-GCM".into()],
                    server_peer_info: "IV_PROTO=138\n".into(),
                    handshake_window: timeout,
                    ..ServerTlsDataChannelOptions::default()
                },
                |username, password| {
                    assert_eq!((username, password), ("alice", "wrong"));
                    Err("invalid credentials".into())
                },
            )
            .await
        };
        let client = async {
            let session = establish_tls_client_session(
                client_transport,
                &client_context,
                TlsControlProtection::default(),
                Vec::new(),
                Duration::from_millis(100),
                timeout,
                false,
            )
            .await
            .unwrap();
            negotiate_tls_client_data_channel(
                session,
                TlsKeyMethodMessage {
                    options_string: "V4,tls-client".into(),
                    username: "alice".into(),
                    password: "wrong".into(),
                    peer_info: "IV_PROTO=138\nIV_CIPHERS=AES-256-GCM\n".into(),
                    ..TlsKeyMethodMessage::default()
                },
                ClientPullOptions {
                    configured_ciphers: vec!["AES-256-GCM".into()],
                    hand_window: timeout,
                    ..ClientPullOptions::default()
                },
                ClientTlsDataChannelOptions::default(),
            )
            .await
        };
        let (server_error, client_error) =
            tokio::time::timeout(timeout, async {
                let (server, client) = tokio::join!(server, client);
                let server = match server {
                    Ok(_) => panic!("server unexpectedly accepted credentials"),
                    Err(error) => error,
                };
                let client = match client {
                    Ok(_) => panic!("client unexpectedly completed PUSH"),
                    Err(error) => error,
                };
                (server, client)
            })
            .await
            .unwrap();
        assert!(matches!(
            server_error,
            TlsServerNegotiationError::AuthenticationRejected
        ));
        assert!(matches!(
            client_error,
            TlsClientNegotiationError::Pull(ClientPullError::State(
                ClientPullStateError::AuthenticationFailed(_)
            ))
        ));
    }
}
