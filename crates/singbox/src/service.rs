//! Embeddable sing-box lifecycle coordinator.

pub mod hysteria_realm;
pub mod ssm_api;

use std::collections::HashSet;

use tokio_util::sync::CancellationToken;

use crate::{
    common::lifecycle::{Lifecycle, LifecycleError, StartStage},
    option::Options,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxState {
    Created,
    Starting(StartStage),
    Started,
    Closing,
    Closed,
}

#[derive(Debug, thiserror::Error)]
pub enum BoxError {
    #[error("cannot {operation} sing-box while it is {state:?}")]
    InvalidState {
        operation: &'static str,
        state: BoxState,
    },
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    #[error("start cancelled before {stage:?}")]
    Cancelled { stage: StartStage },
    #[error("one or more components failed to close: {0}")]
    Close(String),
}

pub struct BoxBuilder {
    options: Options,
    components: Vec<std::boxed::Box<dyn Lifecycle>>,
}

impl BoxBuilder {
    pub fn new(options: Options) -> Self {
        Self {
            options,
            components: Vec::new(),
        }
    }

    pub fn component(mut self, component: impl Lifecycle + 'static) -> Self {
        self.components.push(std::boxed::Box::new(component));
        self
    }

    /// Insert a dependency that must run before already-collected components.
    pub fn component_first(
        mut self,
        component: impl Lifecycle + 'static,
    ) -> Self {
        self.components.insert(0, std::boxed::Box::new(component));
        self
    }

    pub fn build(self) -> Result<Box, BoxError> {
        let mut names = HashSet::new();
        for component in &self.components {
            let name = component.name();
            if !names.insert(name.to_owned()) {
                return Err(BoxError::Lifecycle(LifecycleError::Start {
                    component: name.to_owned(),
                    stage: StartStage::Initialize,
                    message: "duplicate component name".into(),
                }));
            }
        }
        Ok(Box {
            options: self.options,
            components: self.components,
            state: BoxState::Created,
            cancellation: CancellationToken::new(),
            touched: Vec::new(),
        })
    }
}

/// Native service container. It owns every runtime component and can be
/// embedded directly by zay without spawning a child process.
pub struct Box {
    options: Options,
    components: Vec<std::boxed::Box<dyn Lifecycle>>,
    state: BoxState,
    cancellation: CancellationToken,
    touched: Vec<usize>,
}

impl Box {
    pub fn builder(options: Options) -> BoxBuilder {
        BoxBuilder::new(options)
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn state(&self) -> BoxState {
        self.state
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn start(&mut self) -> Result<(), BoxError> {
        if self.state != BoxState::Created {
            return Err(BoxError::InvalidState {
                operation: "start",
                state: self.state,
            });
        }
        for stage in StartStage::ALL {
            self.state = BoxState::Starting(stage);
            for index in 0..self.components.len() {
                if self.cancellation.is_cancelled() {
                    let error = BoxError::Cancelled { stage };
                    self.rollback().await;
                    return Err(error);
                }
                if !self.touched.contains(&index) {
                    self.touched.push(index);
                }
                if let Err(error) = self.components[index].start(stage).await {
                    self.rollback().await;
                    return Err(BoxError::Lifecycle(error));
                }
            }
        }
        self.state = BoxState::Started;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), BoxError> {
        match self.state {
            BoxState::Closed => return Ok(()),
            BoxState::Closing => {
                return Err(BoxError::InvalidState {
                    operation: "close",
                    state: self.state,
                });
            }
            _ => {}
        }
        self.cancellation.cancel();
        self.close_touched().await
    }

    async fn rollback(&mut self) {
        self.cancellation.cancel();
        let _ = self.close_touched().await;
    }

    async fn close_touched(&mut self) -> Result<(), BoxError> {
        self.state = BoxState::Closing;
        let mut errors = Vec::new();
        while let Some(index) = self.touched.pop() {
            if let Err(error) = self.components[index].close().await {
                errors.push(error.to_string());
            }
        }
        self.state = BoxState::Closed;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(BoxError::Close(errors.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{Box, BoxState};
    use crate::{
        common::lifecycle::{
            Lifecycle, LifecycleError, LifecycleFuture, StartStage,
        },
        option::Options,
    };

    struct Recorder {
        name: String,
        events: Arc<Mutex<Vec<String>>>,
        fail_at: Option<StartStage>,
    }

    impl Lifecycle for Recorder {
        fn name(&self) -> &str {
            &self.name
        }

        fn start(&mut self, stage: StartStage) -> LifecycleFuture<'_> {
            std::boxed::Box::pin(async move {
                self.events.lock().unwrap().push(format!(
                    "{}:{}",
                    self.name,
                    stage.as_str()
                ));
                if self.fail_at == Some(stage) {
                    return Err(LifecycleError::Start {
                        component: self.name.clone(),
                        stage,
                        message: "injected".into(),
                    });
                }
                Ok(())
            })
        }

        fn close(&mut self) -> LifecycleFuture<'_> {
            std::boxed::Box::pin(async move {
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("{}:close", self.name));
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn starts_all_four_stages_and_closes_in_reverse_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut engine = Box::builder(Options::default())
            .component(Recorder {
                name: "one".into(),
                events: events.clone(),
                fail_at: None,
            })
            .component(Recorder {
                name: "two".into(),
                events: events.clone(),
                fail_at: None,
            })
            .build()
            .unwrap();
        engine.start().await.unwrap();
        assert_eq!(engine.state(), BoxState::Started);
        engine.close().await.unwrap();
        let events = events.lock().unwrap();
        assert_eq!(&events[events.len() - 2..], ["two:close", "one:close"]);
    }

    #[tokio::test]
    async fn failure_rolls_back_every_touched_component() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut engine = Box::builder(Options::default())
            .component(Recorder {
                name: "one".into(),
                events: events.clone(),
                fail_at: None,
            })
            .component(Recorder {
                name: "two".into(),
                events: events.clone(),
                fail_at: Some(StartStage::Start),
            })
            .build()
            .unwrap();
        assert!(engine.start().await.is_err());
        assert_eq!(engine.state(), BoxState::Closed);
        let events = events.lock().unwrap();
        assert_eq!(&events[events.len() - 2..], ["two:close", "one:close"]);
    }

    #[test]
    fn rejects_duplicate_component_names() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let result = Box::builder(Options::default())
            .component(Recorder {
                name: "same".into(),
                events: events.clone(),
                fail_at: None,
            })
            .component(Recorder {
                name: "same".into(),
                events,
                fail_at: None,
            })
            .build();
        assert!(result.is_err());
    }
}
