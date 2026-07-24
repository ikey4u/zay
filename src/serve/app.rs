//! Shared application state for `zay serve`.

use std::sync::Arc;

use tokio::sync::broadcast;

use super::{
    jobs::{JobSummary, JobSupervisor},
    log_buf::LogBuffer,
    paths::ServePaths,
};
use crate::stack::controller::StackController;

pub struct ServeApp {
    pub paths: ServePaths,
    pub token: Arc<String>,
    pub jobs: JobSupervisor,
    pub stack: StackController,
    pub job_events: broadcast::Sender<JobSummary>,
}

impl ServeApp {
    pub fn new(paths: ServePaths, token: String) -> Self {
        let (job_events, _) = broadcast::channel(256);
        let stack_logs = LogBuffer::with_default_capacity();
        Self {
            paths,
            token: Arc::new(token),
            jobs: JobSupervisor::new(job_events.clone()),
            stack: StackController::new(stack_logs),
            job_events,
        }
    }
}
