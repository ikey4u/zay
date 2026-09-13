use std::{
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{
    AuthFailedInfo, Challenge, ChallengeError, ChallengeKind, ChallengeManager,
    CipherNegotiationError, KeyMethodError, PUSH_REQUEST_PAYLOAD, PullFilter,
    PushedOptions, TlsControlDirective, append_push_reply_payload_segment,
    auth_pending_extension, classify_tls_control_directive,
    decode_push_reply_option_lines, normalize_control_payload,
    parse_auth_failed_payload, parse_server_pushed_challenge,
    select_pulled_cipher, tls_control_string_payload,
    validate_server_pushed_cipher,
};

pub const TLS_PUSH_REQUEST_RESEND_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPullOptions {
    pub configured_ciphers: Vec<String>,
    pub fallback_cipher: String,
    pub remote_cipher: String,
    pub configured_auth: String,
    pub remote_host: Option<IpAddr>,
    pub filters: Vec<PullFilter>,
    pub hand_window: Duration,
    pub renegotiation_interval: Duration,
    pub pre_pull_ping_restart: Duration,
}

impl Default for ClientPullOptions {
    fn default() -> Self {
        Self {
            configured_ciphers: Vec::new(),
            fallback_cipher: String::new(),
            remote_cipher: String::new(),
            configured_auth: String::new(),
            remote_host: None,
            filters: Vec::new(),
            hand_window: Duration::from_secs(60),
            renegotiation_interval: Duration::from_secs(3600),
            pre_pull_ping_restart: Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPullResult {
    pub options: PushedOptions,
    pub selected_cipher: String,
    pub selected_auth: String,
    pub info_pre_records: Vec<String>,
}

#[derive(Clone)]
pub struct ClientPullChallengeContext {
    pub manager: Arc<ChallengeManager>,
    pub owner: u64,
    pub username: String,
    pub cancellation: CancellationToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientPullEvent {
    Ignored,
    AuthenticationPending { extension: Duration },
    InfoPre(String),
    Complete(Box<ClientPullResult>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientRemoteAdvance {
    #[default]
    Stay,
    NextAddress,
    NextRemote,
}

/// Pure state for the client-side `PUSH_REQUEST` exchange.  Keeping this
/// separate from the TLS stream lets endpoint code preserve the state across
/// a primary control-channel handover during renegotiation.
#[derive(Debug, Clone)]
pub struct ClientPullMachine {
    options: ClientPullOptions,
    selected_cipher: String,
    selected_auth: String,
    accumulated_push_reply_lines: Vec<String>,
    push_continuation_pending: bool,
    authentication_pending: bool,
    info_pre_records: Vec<String>,
}

impl ClientPullMachine {
    pub fn new(options: ClientPullOptions) -> Self {
        let selected_auth = if options.configured_auth.is_empty() {
            "SHA1".to_owned()
        } else {
            options.configured_auth.clone()
        };
        Self {
            options,
            selected_cipher: String::new(),
            selected_auth,
            accumulated_push_reply_lines: Vec::new(),
            push_continuation_pending: false,
            authentication_pending: false,
            info_pre_records: Vec::new(),
        }
    }

    pub fn request_payload(&self) -> Vec<u8> {
        tls_control_string_payload(PUSH_REQUEST_PAYLOAD.as_bytes())
    }

    pub fn authentication_pending(&self) -> bool {
        self.authentication_pending
    }

    pub fn push_continuation_pending(&self) -> bool {
        self.push_continuation_pending
    }

    pub fn accept_record(
        &mut self,
        control_record: &[u8],
    ) -> Result<ClientPullEvent, ClientPullStateError> {
        match classify_tls_control_directive(control_record) {
            TlsControlDirective::AuthFailed => {
                Err(ClientPullStateError::AuthenticationFailed(
                    parse_auth_failed_payload(control_record),
                ))
            }
            TlsControlDirective::AuthPending => {
                self.authentication_pending = true;
                Ok(ClientPullEvent::AuthenticationPending {
                    extension: auth_pending_extension(
                        self.options.hand_window,
                        self.options.renegotiation_interval,
                        control_record,
                    ),
                })
            }
            TlsControlDirective::Restart => {
                Err(ClientPullStateError::ServerRestart {
                    advance: parse_server_restart_advance(control_record),
                })
            }
            TlsControlDirective::Halt => Err(ClientPullStateError::ServerHalt),
            TlsControlDirective::Exit => Err(ClientPullStateError::ServerExit),
            TlsControlDirective::InfoPre => {
                let record = normalize_control_payload(control_record);
                self.info_pre_records.push(record.clone());
                Ok(ClientPullEvent::InfoPre(record))
            }
            TlsControlDirective::PushReply => {
                self.accept_push_reply(control_record)
            }
            TlsControlDirective::Unknown
            | TlsControlDirective::Info
            | TlsControlDirective::ChallengeResponse => {
                Ok(ClientPullEvent::Ignored)
            }
        }
    }

    pub fn timeout_error(&self) -> ClientPullStateError {
        if self.authentication_pending {
            ClientPullStateError::AuthenticationPendingTimeout
        } else if self.push_continuation_pending {
            ClientPullStateError::IncompletePushContinuation
        } else {
            ClientPullStateError::NoPushReply
        }
    }

    fn accept_push_reply(
        &mut self,
        control_record: &[u8],
    ) -> Result<ClientPullEvent, ClientPullStateError> {
        let Some((lines, continuation)) = append_push_reply_payload_segment(
            std::mem::take(&mut self.accumulated_push_reply_lines),
            control_record,
        ) else {
            return Ok(ClientPullEvent::Ignored);
        };
        self.accumulated_push_reply_lines = lines;
        self.push_continuation_pending = continuation == 2;
        if self.push_continuation_pending {
            return Ok(ClientPullEvent::Ignored);
        }

        let command = self.accumulated_push_reply_lines[0].clone();
        let (options, _) = decode_push_reply_option_lines(
            &command,
            &self.accumulated_push_reply_lines[1..],
            self.options.remote_host,
            &self.options.filters,
        );
        self.accumulated_push_reply_lines.clear();
        if !options.pull_filter_rejection.is_empty() {
            return Err(ClientPullStateError::PullFilterRejected(
                options.pull_filter_rejection,
            ));
        }
        if !options.selected_cipher.is_empty() {
            self.selected_cipher.clone_from(&options.selected_cipher);
        }
        if !options.selected_auth.is_empty() {
            self.selected_auth.clone_from(&options.selected_auth);
        }
        if self.selected_cipher.is_empty() {
            self.selected_cipher = select_pulled_cipher(
                &self.options.configured_ciphers,
                &self.options.fallback_cipher,
                &self.options.remote_cipher,
            )?;
        }
        self.selected_cipher = validate_server_pushed_cipher(
            &self.options.configured_ciphers,
            &self.options.fallback_cipher,
            &self.selected_cipher,
        )?
        .ok_or(CipherNegotiationError::MissingPeerCipher)?;
        Ok(ClientPullEvent::Complete(Box::new(ClientPullResult {
            options,
            selected_cipher: self.selected_cipher.clone(),
            selected_auth: self.selected_auth.clone(),
            info_pre_records: std::mem::take(&mut self.info_pre_records),
        })))
    }
}

pub async fn pull_client_configuration<S>(
    stream: &mut S,
    options: ClientPullOptions,
) -> Result<ClientPullResult, ClientPullError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pull_client_configuration_with_challenges(stream, options, None).await
}

pub async fn pull_client_configuration_with_challenges<S>(
    stream: &mut S,
    options: ClientPullOptions,
    challenge_context: Option<&ClientPullChallengeContext>,
) -> Result<ClientPullResult, ClientPullError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hand_window = options.hand_window;
    let mut machine = ClientPullMachine::new(options);
    stream.write_all(&machine.request_payload()).await?;
    let mut deadline = tokio::time::Instant::now() + hand_window;
    let mut last_inbound = tokio::time::Instant::now();
    let mut next_push_request =
        tokio::time::Instant::now() + TLS_PUSH_REQUEST_RESEND_INTERVAL;
    let mut record = vec![0; 16 * 1024];
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(machine.timeout_error().into());
        }
        let ping_deadline = (!machine.options.pre_pull_ping_restart.is_zero())
            .then(|| last_inbound + machine.options.pre_pull_ping_restart);
        let read_deadline = ping_deadline
            .map_or(deadline.min(next_push_request), |ping_deadline| {
                deadline.min(next_push_request).min(ping_deadline)
            });
        match tokio::time::timeout_at(read_deadline, stream.read(&mut record))
            .await
        {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "OpenVPN TLS control channel closed",
                )
                .into());
            }
            Ok(Ok(length)) => {
                last_inbound = tokio::time::Instant::now();
                match machine.accept_record(&record[..length])? {
                    ClientPullEvent::Complete(result) => return Ok(*result),
                    ClientPullEvent::AuthenticationPending { extension } => {
                        deadline = tokio::time::Instant::now() + extension;
                    }
                    ClientPullEvent::InfoPre(record) => {
                        if let Some(challenge_context) = challenge_context {
                            handle_client_info_pre_challenge(
                                stream,
                                challenge_context,
                                &record,
                                deadline,
                            )
                            .await?;
                        }
                    }
                    ClientPullEvent::Ignored => {}
                }
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(machine.timeout_error().into());
                }
                if let Some(ping_deadline) = ping_deadline
                    && now >= ping_deadline
                {
                    return Err(ClientPullStateError::PingRestartTimeout.into());
                }
                if now >= next_push_request {
                    stream.write_all(&machine.request_payload()).await?;
                    next_push_request = now + TLS_PUSH_REQUEST_RESEND_INTERVAL;
                }
            }
        }
    }
}

pub fn client_info_pre_challenge(
    control_record: &str,
    username: &str,
    deadline: Option<SystemTime>,
) -> Option<Challenge> {
    let (_, payload) = control_record.split_once(',')?;
    let mut challenge = parse_server_pushed_challenge(payload)?;
    challenge.username = username.to_owned();
    challenge.deadline = deadline;
    Some(challenge)
}

pub fn client_challenge_response_payload(secret: &str) -> Vec<u8> {
    tls_control_string_payload(
        format!("CR_RESPONSE,{}", STANDARD.encode(secret)).as_bytes(),
    )
}

async fn handle_client_info_pre_challenge<S>(
    stream: &mut S,
    context: &ClientPullChallengeContext,
    control_record: &str,
    deadline: tokio::time::Instant,
) -> Result<(), ClientPullError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let wall_deadline = SystemTime::now().checked_add(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
    );
    let Some(challenge) = client_info_pre_challenge(
        control_record,
        &context.username,
        wall_deadline,
    ) else {
        return Ok(());
    };
    if challenge.kind != ChallengeKind::Secret {
        context.manager.publish_message(context.owner, challenge)?;
        return Ok(());
    }
    let response = tokio::select! {
        _ = tokio::time::sleep_until(deadline) => {
            context.manager.clear_owner(context.owner);
            return Err(ClientPullStateError::AuthenticationPendingTimeout.into());
        }
        response = context.manager.await_response(
            context.owner,
            challenge,
            context.cancellation.clone(),
        ) => response?,
    };
    context.manager.note_response_submitted();
    stream
        .write_all(&client_challenge_response_payload(&response.secret))
        .await?;
    Ok(())
}

pub fn parse_server_restart_advance(payload: &[u8]) -> ClientRemoteAdvance {
    let payload = normalize_control_payload(payload);
    let Some((_, flags)) = payload.split_once(',') else {
        return ClientRemoteAdvance::Stay;
    };
    let flags = flags.trim();
    let Some(flags) = flags.strip_prefix('[') else {
        return ClientRemoteAdvance::Stay;
    };
    let Some(end) = flags.find(']') else {
        return ClientRemoteAdvance::Stay;
    };
    if flags[..end].to_ascii_uppercase().contains('N') {
        ClientRemoteAdvance::NextAddress
    } else {
        ClientRemoteAdvance::Stay
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientPullStateError {
    #[error("OpenVPN authentication failed: {0:?}")]
    AuthenticationFailed(AuthFailedInfo),
    #[error("OpenVPN server requested restart")]
    ServerRestart { advance: ClientRemoteAdvance },
    #[error("OpenVPN server halted session")]
    ServerHalt,
    #[error("OpenVPN server exited")]
    ServerExit,
    #[error("OpenVPN pushed option rejected by pull-filter: {0}")]
    PullFilterRejected(String),
    #[error(transparent)]
    Cipher(#[from] CipherNegotiationError),
    #[error(transparent)]
    KeyMethod(#[from] KeyMethodError),
    #[error("OpenVPN pending authentication timed out")]
    AuthenticationPendingTimeout,
    #[error("OpenVPN server did not finish push continuation")]
    IncompletePushContinuation,
    #[error("OpenVPN server did not reply to push requests")]
    NoPushReply,
    #[error("OpenVPN pre-pull ping-restart timeout")]
    PingRestartTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientPullError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    State(#[from] ClientPullStateError),
    #[error(transparent)]
    Challenge(#[from] ChallengeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> ClientPullOptions {
        ClientPullOptions {
            configured_ciphers: vec![
                "AES-256-GCM".into(),
                "AES-128-GCM".into(),
            ],
            remote_cipher: "AES-256-GCM".into(),
            hand_window: Duration::from_secs(5),
            renegotiation_interval: Duration::from_secs(100),
            ..ClientPullOptions::default()
        }
    }

    #[test]
    fn combines_continuations_and_selects_pushed_cipher_and_auth() {
        let mut machine = ClientPullMachine::new(options());
        assert_eq!(machine.request_payload(), b"PUSH_REQUEST\0");
        assert_eq!(
            machine
                .accept_record(
                    b"PUSH_REPLY,route 10.0.0.0 255.0.0.0,push-continuation 2\0"
                )
                .unwrap(),
            ClientPullEvent::Ignored
        );
        assert!(machine.push_continuation_pending());
        let ClientPullEvent::Complete(result) = machine
            .accept_record(
                b"PUSH_REPLY,cipher AES-128-GCM,auth SHA256,push-continuation 1\0",
            )
            .unwrap()
        else {
            panic!("expected completed push reply");
        };
        assert_eq!(result.selected_cipher, "AES-128-GCM");
        assert_eq!(result.selected_auth, "SHA256");
        assert_eq!(result.options.routes.len(), 1);
    }

    #[test]
    fn applies_default_auth_fallback_cipher_and_pull_filter_rejection() {
        let mut fallback = options();
        fallback.remote_cipher.clear();
        fallback.fallback_cipher = "BF-CBC".into();
        let mut machine = ClientPullMachine::new(fallback);
        let ClientPullEvent::Complete(result) = machine
            .accept_record(b"PUSH_REPLY,topology subnet\0")
            .unwrap()
        else {
            panic!("expected completed push reply");
        };
        assert_eq!(result.selected_cipher, "BF-CBC");
        assert_eq!(result.selected_auth, "SHA1");

        let mut rejected = options();
        rejected.filters.push(PullFilter {
            action: "reject".into(),
            text: "route ".into(),
        });
        let error = ClientPullMachine::new(rejected)
            .accept_record(b"PUSH_REPLY,route 192.0.2.0 255.255.255.0\0")
            .unwrap_err();
        assert!(matches!(error, ClientPullStateError::PullFilterRejected(_)));

        assert!(matches!(
            ClientPullMachine::new(options())
                .accept_record(b"PUSH_REPLY,cipher BF-CBC\0")
                .unwrap_err(),
            ClientPullStateError::KeyMethod(
                KeyMethodError::NegotiatedCipherNotAllowed(_)
            )
        ));
    }

    #[test]
    fn converts_info_pre_to_ui_challenge_and_encodes_response() {
        let deadline = SystemTime::now();
        let challenge = client_info_pre_challenge(
            "INFO_PRE,CR_TEXT:E,R:One-time password",
            "alice",
            Some(deadline),
        )
        .unwrap();
        assert_eq!(challenge.kind, ChallengeKind::Secret);
        assert_eq!(challenge.username, "alice");
        assert_eq!(challenge.deadline, Some(deadline));
        assert!(challenge.echo);
        assert_eq!(
            client_challenge_response_payload("123456"),
            b"CR_RESPONSE,MTIzNDU2\0"
        );
    }

    #[test]
    fn handles_pending_info_and_terminal_directives() {
        let mut machine = ClientPullMachine::new(options());
        assert_eq!(
            machine.accept_record(b"AUTH_PENDING,timeout 90\0").unwrap(),
            ClientPullEvent::AuthenticationPending {
                extension: Duration::from_secs(50)
            }
        );
        assert!(machine.authentication_pending());
        assert_eq!(
            machine.timeout_error(),
            ClientPullStateError::AuthenticationPendingTimeout
        );
        assert_eq!(
            machine
                .accept_record(b"INFO_PRE,CR_TEXT:R:state:Enter OTP\0")
                .unwrap(),
            ClientPullEvent::InfoPre(
                "INFO_PRE,CR_TEXT:R:state:Enter OTP".into()
            )
        );
        assert_eq!(
            ClientPullMachine::new(options())
                .accept_record(b"RESTART,[N]\0")
                .unwrap_err(),
            ClientPullStateError::ServerRestart {
                advance: ClientRemoteAdvance::NextAddress
            }
        );
        assert!(matches!(
            ClientPullMachine::new(options())
                .accept_record(b"AUTH_FAILED,bad password\0")
                .unwrap_err(),
            ClientPullStateError::AuthenticationFailed(AuthFailedInfo {
                failed: true,
                reason,
                ..
            }) if reason == "bad password"
        ));
    }

    #[tokio::test]
    async fn async_exchange_sends_request_and_returns_push_reply() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = [0; 64];
            let length = server.read(&mut request).await.unwrap();
            assert_eq!(&request[..length], b"PUSH_REQUEST\0");
            server
                .write_all(b"PUSH_REPLY,cipher AES-128-GCM,auth SHA512\0")
                .await
                .unwrap();
        });
        let result = pull_client_configuration(&mut client, options())
            .await
            .unwrap();
        server_task.await.unwrap();
        assert_eq!(result.selected_cipher, "AES-128-GCM");
        assert_eq!(result.selected_auth, "SHA512");
    }

    #[tokio::test]
    async fn pre_pull_ping_restart_bounds_silent_control_channel() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut request = [0_u8; 13];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"PUSH_REQUEST\0");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let error = pull_client_configuration(
            &mut client,
            ClientPullOptions {
                hand_window: Duration::from_secs(1),
                pre_pull_ping_restart: Duration::from_millis(20),
                ..options()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ClientPullError::State(ClientPullStateError::PingRestartTimeout)
        ));
        peer.abort();
    }
}
