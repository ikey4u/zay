//! Job supervisor for SSH / Fwd / HTTP tasks.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;
use tokio::{sync::broadcast, task::JoinHandle};
use uuid::Uuid;

use super::log_buf::LogBuffer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Stack,
    Ssh,
    Fwd,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Starting,
    Running,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobSummary {
    pub id: String,
    pub kind: JobKind,
    pub state: JobState,
    pub created_at: DateTime<Utc>,
    pub spec: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

struct JobRecord {
    summary: JobSummary,
    logs: LogBuffer,
    handle: Option<JoinHandle<()>>,
}

pub struct JobSupervisor {
    inner: Arc<Mutex<HashMap<String, JobRecord>>>,
    events: broadcast::Sender<JobSummary>,
}

impl JobSupervisor {
    pub fn new(events: broadcast::Sender<JobSummary>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            events,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<JobSummary> {
        self.events.subscribe()
    }

    pub fn list(&self) -> Vec<JobSummary> {
        let guard = self.inner.lock().expect("jobs lock");
        let mut jobs: Vec<_> =
            guard.values().map(|r| r.summary.clone()).collect();
        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        jobs
    }

    pub fn get(&self, id: &str) -> Option<(JobSummary, Vec<String>)> {
        let guard = self.inner.lock().expect("jobs lock");
        guard.get(id).map(|r| (r.summary.clone(), r.logs.tail(500)))
    }

    fn emit(&self, summary: &JobSummary) {
        let _ = self.events.send(summary.clone());
    }

    fn insert_starting(
        &self,
        kind: JobKind,
        spec: JsonValue,
    ) -> (String, LogBuffer) {
        let id = Uuid::new_v4().to_string();
        let logs = LogBuffer::with_default_capacity();
        let summary = JobSummary {
            id: id.clone(),
            kind,
            state: JobState::Starting,
            created_at: Utc::now(),
            spec,
            error: None,
            exit_code: None,
        };
        self.inner.lock().expect("jobs lock").insert(
            id.clone(),
            JobRecord {
                summary: summary.clone(),
                logs: logs.clone(),
                handle: None,
            },
        );
        self.emit(&summary);
        (id, logs)
    }

    fn set_running(&self, id: &str) {
        let mut guard = self.inner.lock().expect("jobs lock");
        if let Some(rec) = guard.get_mut(id) {
            rec.summary.state = JobState::Running;
            self.emit(&rec.summary);
        }
    }

    fn finish(
        &self,
        id: &str,
        state: JobState,
        error: Option<String>,
        exit_code: Option<i32>,
    ) {
        let mut guard = self.inner.lock().expect("jobs lock");
        if let Some(rec) = guard.get_mut(id) {
            rec.summary.state = state;
            rec.summary.error = error;
            rec.summary.exit_code = exit_code;
            rec.handle = None;
            self.emit(&rec.summary);
        }
    }

    pub async fn start_ssh(&self, spec: JsonValue) -> Result<JobSummary> {
        let parsed: crate::ssh::SshArgs = serde_json::from_value::<
            super::job_specs::SshJobSpec,
        >(spec.clone())
        .context("invalid ssh job spec")
        .map(|s| s.into_args())?;
        let (id, logs) = self.insert_starting(JobKind::Ssh, spec);
        let supervisor = self.clone();
        let job_id = id.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Runtime::new().expect("ssh job runtime");
            rt.block_on(async {
                supervisor.set_running(&job_id);
                logs.push("starting SSH tunnel".to_string());
                let result = crate::ssh::tunnel::run(parsed).await;
                match result {
                    Ok(()) => {
                        logs.push("SSH tunnel stopped".to_string());
                        supervisor.finish(
                            &job_id,
                            JobState::Stopped,
                            None,
                            Some(0),
                        );
                    }
                    Err(e) => {
                        logs.push(format!("SSH error: {e:#}"));
                        supervisor.finish(
                            &job_id,
                            JobState::Failed,
                            Some(format!("{e:#}")),
                            None,
                        );
                    }
                }
            });
        });
        self.inner
            .lock()
            .expect("jobs lock")
            .get_mut(&id)
            .unwrap()
            .handle = Some(handle);
        Ok(self.get(&id).map(|(s, _)| s).expect("job"))
    }

    pub async fn start_fwd(&self, spec: JsonValue) -> Result<JobSummary> {
        let cli = serde_json::from_value::<super::job_specs::FwdJobSpec>(
            spec.clone(),
        )
        .context("invalid fwd job spec")
        .and_then(|s| s.into_cli())?;
        let args = crate::fwd::parse_fwd_cli(cli)?;
        let (id, logs) = self.insert_starting(JobKind::Fwd, spec);
        let supervisor = self.clone();
        let job_id = id.clone();
        let handle = tokio::spawn(async move {
            supervisor.set_running(&job_id);
            logs.push("starting fwd relay".to_string());
            let result = crate::fwd::run(args).await;
            match result {
                Ok(()) => {
                    supervisor.finish(
                        &job_id,
                        JobState::Stopped,
                        None,
                        Some(0),
                    );
                }
                Err(e) => {
                    logs.push(format!("fwd error: {e:#}"));
                    supervisor.finish(
                        &job_id,
                        JobState::Failed,
                        Some(format!("{e:#}")),
                        None,
                    );
                }
            }
        });
        self.inner
            .lock()
            .expect("jobs lock")
            .get_mut(&id)
            .unwrap()
            .handle = Some(handle);
        Ok(self.get(&id).map(|(s, _)| s).expect("job"))
    }

    pub async fn start_http(&self, spec: JsonValue) -> Result<JobSummary> {
        let cli = serde_json::from_value::<super::job_specs::HttpJobSpec>(
            spec.clone(),
        )
        .context("invalid http job spec")
        .and_then(|s| s.into_cli())?;
        let (id, logs) = self.insert_starting(JobKind::Http, spec);
        let supervisor = self.clone();
        let job_id = id.clone();
        let handle = tokio::spawn(async move {
            supervisor.set_running(&job_id);
            logs.push(format!("HTTP server on {}", cli.listen));
            let result = crate::http::run(cli).await;
            match result {
                Ok(()) => {
                    supervisor.finish(
                        &job_id,
                        JobState::Stopped,
                        None,
                        Some(0),
                    );
                }
                Err(e) => {
                    logs.push(format!("http error: {e:#}"));
                    supervisor.finish(
                        &job_id,
                        JobState::Failed,
                        Some(format!("{e:#}")),
                        None,
                    );
                }
            }
        });
        self.inner
            .lock()
            .expect("jobs lock")
            .get_mut(&id)
            .unwrap()
            .handle = Some(handle);
        Ok(self.get(&id).map(|(s, _)| s).expect("job"))
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        let mut guard = self.inner.lock().expect("jobs lock");
        let rec = guard
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("job {id} not found"))?;
        if let Some(handle) = rec.handle.take() {
            handle.abort();
            rec.summary.state = JobState::Stopped;
            rec.summary.exit_code = Some(130);
            self.emit(&rec.summary);
            Ok(())
        } else {
            bail!("job {id} is not running")
        }
    }
}

impl Clone for JobSupervisor {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            events: self.events.clone(),
        }
    }
}
