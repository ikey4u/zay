//! Lifecycle stages shared by the eventual DNS, route, endpoint and service graph.

use std::{future::Future, pin::Pin};

pub type LifecycleFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), LifecycleError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StartStage {
    Initialize,
    Start,
    PostStart,
    Started,
}

impl StartStage {
    pub const ALL: [Self; 4] = [
        Self::Initialize,
        Self::Start,
        Self::PostStart,
        Self::Started,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Start => "start",
            Self::PostStart => "post-start",
            Self::Started => "finish-start",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("component {component} failed during {stage:?}: {message}")]
    Start {
        component: String,
        stage: StartStage,
        message: String,
    },
    #[error("component {component} failed to close: {message}")]
    Close { component: String, message: String },
}

/// Embeddable equivalent of sing-box's staged lifecycle contract.
pub trait Lifecycle: Send + Sync {
    fn name(&self) -> &str;

    fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_>;

    fn close(&mut self) -> LifecycleFuture<'_>;
}
