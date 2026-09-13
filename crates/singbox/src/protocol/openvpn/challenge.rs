use std::{sync::Arc, time::SystemTime};

use parking_lot::Mutex;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Credentials,
    Secret,
    Message,
    OpenUrl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub id: String,
    pub kind: ChallengeKind,
    pub username: String,
    pub message: String,
    pub url: String,
    pub secret_message: String,
    pub echo: bool,
    pub previous_error: String,
    pub deadline: Option<SystemTime>,
}

impl Challenge {
    pub fn new(kind: ChallengeKind) -> Self {
        Self {
            id: String::new(),
            kind,
            username: String::new(),
            message: String::new(),
            url: String::new(),
            secret_message: String::new(),
            echo: false,
            previous_error: String::new(),
            deadline: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChallengeResponse {
    pub username: String,
    pub password: String,
    pub secret: String,
}

struct Completion {
    response: ChallengeResponse,
    acknowledged: oneshot::Sender<()>,
}

struct PendingChallenge {
    challenge: Challenge,
    owner: u64,
    complete: Option<oneshot::Sender<Completion>>,
    cancellation: CancellationToken,
}

struct ChallengeInner {
    pending: Option<PendingChallenge>,
    previous_authentication_error: String,
    sent_interactive_credentials: bool,
    closed: bool,
    generation: u64,
}

/// Thread-safe interactive authentication challenge state shared by an
/// embeddable OpenVPN client and its UI.
pub struct ChallengeManager {
    inner: Mutex<ChallengeInner>,
    updates: watch::Sender<u64>,
}

impl Default for ChallengeManager {
    fn default() -> Self {
        let (updates, _) = watch::channel(0);
        Self {
            inner: Mutex::new(ChallengeInner {
                pending: None,
                previous_authentication_error: String::new(),
                sent_interactive_credentials: false,
                closed: false,
                generation: 0,
            }),
            updates,
        }
    }
}

impl ChallengeManager {
    pub fn pending(&self) -> Option<Challenge> {
        self.inner
            .lock()
            .pending
            .as_ref()
            .map(|pending| pending.challenge.clone())
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.updates.subscribe()
    }

    pub async fn complete(
        &self,
        challenge_id: &str,
        response: ChallengeResponse,
    ) -> Result<(), ChallengeError> {
        let sender = {
            let mut inner = self.inner.lock();
            let pending = inner
                .pending
                .as_ref()
                .filter(|pending| pending.challenge.id == challenge_id)
                .ok_or(ChallengeError::NoPendingChallenge)?;
            if pending.complete.is_none() {
                return Err(ChallengeError::NotAnswerable);
            }
            let sender =
                inner.pending.as_mut().unwrap().complete.take().unwrap();
            inner.pending = None;
            signal_update(&mut inner, &self.updates);
            sender
        };
        let (acknowledged, acknowledgment) = oneshot::channel();
        sender
            .send(Completion {
                response,
                acknowledged,
            })
            .map_err(|_| ChallengeError::Canceled)?;
        acknowledgment.await.map_err(|_| ChallengeError::Canceled)
    }

    pub fn cancel(&self, challenge_id: &str) -> Result<(), ChallengeError> {
        let cancellation = {
            let mut inner = self.inner.lock();
            let pending = inner
                .pending
                .as_ref()
                .filter(|pending| pending.challenge.id == challenge_id)
                .ok_or(ChallengeError::NoPendingChallenge)?;
            let cancellation = pending.cancellation.clone();
            inner.pending = None;
            signal_update(&mut inner, &self.updates);
            cancellation
        };
        cancellation.cancel();
        Ok(())
    }

    pub async fn await_response(
        &self,
        owner: u64,
        mut challenge: Challenge,
        context: CancellationToken,
    ) -> Result<ChallengeResponse, ChallengeError> {
        challenge.id = new_challenge_id()?;
        let challenge_id = challenge.id.clone();
        let cancellation = CancellationToken::new();
        let (sender, receiver) = oneshot::channel();
        {
            let mut inner = self.inner.lock();
            if inner.closed {
                return Err(ChallengeError::Closed);
            }
            if challenge.previous_error.is_empty() {
                challenge.previous_error =
                    std::mem::take(&mut inner.previous_authentication_error);
            }
            inner.pending = Some(PendingChallenge {
                challenge,
                owner,
                complete: Some(sender),
                cancellation: cancellation.clone(),
            });
            signal_update(&mut inner, &self.updates);
        }
        let completion = tokio::select! {
            _ = context.cancelled() => {
                self.clear_owner(owner);
                return Err(ChallengeError::Canceled);
            }
            _ = cancellation.cancelled() => return Err(ChallengeError::Canceled),
            completion = receiver => completion.map_err(|_| ChallengeError::Canceled)?,
        };
        let response = completion.response;
        let _ = completion.acknowledged.send(());
        debug_assert!(
            self.pending()
                .is_none_or(|pending| pending.id != challenge_id)
        );
        Ok(response)
    }

    pub fn publish_message(
        &self,
        owner: u64,
        mut challenge: Challenge,
    ) -> Result<(), ChallengeError> {
        challenge.id = new_challenge_id()?;
        let mut inner = self.inner.lock();
        if inner.closed {
            return Err(ChallengeError::Closed);
        }
        if challenge.previous_error.is_empty() {
            challenge.previous_error =
                std::mem::take(&mut inner.previous_authentication_error);
        }
        inner.pending = Some(PendingChallenge {
            challenge,
            owner,
            complete: None,
            cancellation: CancellationToken::new(),
        });
        signal_update(&mut inner, &self.updates);
        Ok(())
    }

    pub fn clear_owner(&self, owner: u64) {
        let mut inner = self.inner.lock();
        if inner
            .pending
            .as_ref()
            .is_some_and(|pending| pending.owner == owner)
        {
            inner.pending = None;
            signal_update(&mut inner, &self.updates);
        }
    }

    pub fn update_deadline(&self, owner: u64, deadline: Option<SystemTime>) {
        let mut inner = self.inner.lock();
        if let Some(pending) = inner.pending.as_mut().filter(|pending| {
            pending.owner == owner && pending.challenge.deadline != deadline
        }) {
            pending.challenge.deadline = deadline;
            signal_update(&mut inner, &self.updates);
        }
    }

    pub fn note_response_submitted(&self) {
        self.inner.lock().sent_interactive_credentials = true;
    }

    /// Record whether credentials selected for the next key-method exchange
    /// came from an interactive response. Auth-token and configured
    /// credentials reset the flag; a challenge response sets it again.
    pub fn note_credentials_sent(&self, interactive: bool) {
        self.inner.lock().sent_interactive_credentials = interactive;
    }

    pub fn sent_interactive_credentials(&self) -> bool {
        self.inner.lock().sent_interactive_credentials
    }

    pub fn note_previous_auth_failure(&self, reason: impl Into<String>) {
        self.inner.lock().previous_authentication_error = reason.into();
    }

    pub fn clear_previous_auth_failure(&self) {
        self.inner.lock().previous_authentication_error.clear();
    }

    pub fn close(&self) {
        let cancellation = {
            let mut inner = self.inner.lock();
            inner.closed = true;
            let cancellation = inner
                .pending
                .as_ref()
                .map(|pending| pending.cancellation.clone());
            inner.pending = None;
            signal_update(&mut inner, &self.updates);
            cancellation
        };
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }
}

fn signal_update(inner: &mut ChallengeInner, updates: &watch::Sender<u64>) {
    inner.generation = inner.generation.wrapping_add(1);
    updates.send_replace(inner.generation);
}

fn new_challenge_id() -> Result<String, ChallengeError> {
    let mut identifier = [0; 8];
    getrandom::fill(&mut identifier)
        .map_err(|_| ChallengeError::RandomFailed)?;
    Ok(hex::encode(identifier))
}

pub fn parse_server_pushed_challenge(payload: &str) -> Option<Challenge> {
    if let Some(url) = payload.strip_prefix("OPEN_URL:") {
        let mut challenge = Challenge::new(ChallengeKind::OpenUrl);
        challenge.url = url.into();
        return Some(challenge);
    }
    if let Some(value) = payload.strip_prefix("WEB_AUTH:") {
        let (_, url) = value.split_once(':')?;
        let mut challenge = Challenge::new(ChallengeKind::OpenUrl);
        challenge.url = url.into();
        return Some(challenge);
    }
    if let Some(value) = payload.strip_prefix("CR_TEXT:") {
        let (flags, text) = value.split_once(':')?;
        let required = challenge_flags_contain(flags, "R");
        let mut challenge = Challenge::new(if required {
            ChallengeKind::Secret
        } else {
            ChallengeKind::Message
        });
        challenge.message = text.into();
        challenge.echo = challenge_flags_contain(flags, "E");
        return Some(challenge);
    }
    None
}

fn challenge_flags_contain(flags: &str, expected: &str) -> bool {
    flags.split(',').any(|flag| flag.trim() == expected)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    #[error("no pending OpenVPN challenge")]
    NoPendingChallenge,
    #[error("OpenVPN challenge is not answerable")]
    NotAnswerable,
    #[error("OpenVPN challenge was canceled")]
    Canceled,
    #[error("OpenVPN challenge manager is closed")]
    Closed,
    #[error("failed to generate OpenVPN challenge identifier")]
    RandomFailed,
}

pub type SharedChallengeManager = Arc<ChallengeManager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_management_challenge_payloads() {
        assert_eq!(
            parse_server_pushed_challenge("OPEN_URL:https://example.com")
                .unwrap()
                .url,
            "https://example.com"
        );
        let web = parse_server_pushed_challenge(
            "WEB_AUTH:proxy,hidden:https://login",
        )
        .unwrap();
        assert_eq!(web.kind, ChallengeKind::OpenUrl);
        assert_eq!(web.url, "https://login");
        let secret =
            parse_server_pushed_challenge("CR_TEXT:E,R:One-time password")
                .unwrap();
        assert_eq!(secret.kind, ChallengeKind::Secret);
        assert!(secret.echo);
        assert!(
            parse_server_pushed_challenge("WEB_AUTH:missing-url").is_none()
        );
    }

    #[tokio::test]
    async fn publishes_completes_and_acknowledges_answerable_challenges() {
        let manager = Arc::new(ChallengeManager::default());
        manager.note_previous_auth_failure("bad password");
        let task_manager = manager.clone();
        let task = tokio::spawn(async move {
            task_manager
                .await_response(
                    7,
                    Challenge::new(ChallengeKind::Credentials),
                    CancellationToken::new(),
                )
                .await
        });
        let mut updates = manager.subscribe();
        updates.changed().await.unwrap();
        let challenge = manager.pending().unwrap();
        assert_eq!(challenge.previous_error, "bad password");
        let response = ChallengeResponse {
            username: "alice".into(),
            password: "secret".into(),
            secret: String::new(),
        };
        manager
            .complete(&challenge.id, response.clone())
            .await
            .unwrap();
        assert_eq!(task.await.unwrap().unwrap(), response);
    }

    #[tokio::test]
    async fn cancellation_wakes_waiter() {
        let manager = Arc::new(ChallengeManager::default());
        let task_manager = manager.clone();
        let task = tokio::spawn(async move {
            task_manager
                .await_response(
                    9,
                    Challenge::new(ChallengeKind::Secret),
                    CancellationToken::new(),
                )
                .await
        });
        let mut updates = manager.subscribe();
        updates.changed().await.unwrap();
        let id = manager.pending().unwrap().id;
        manager.cancel(&id).unwrap();
        assert_eq!(task.await.unwrap(), Err(ChallengeError::Canceled));
    }
}
