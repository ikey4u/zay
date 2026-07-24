//! Ring buffer for job / stack log lines.

use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};

const DEFAULT_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<RwLock<VecDeque<String>>>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(VecDeque::new())),
            capacity: capacity.max(64),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    pub fn push(&self, line: impl Into<String>) {
        let line = line.into();
        let mut guard = self.inner.write().expect("log buffer lock");
        guard.push_back(line);
        while guard.len() > self.capacity {
            guard.pop_front();
        }
    }

    pub fn tail(&self, limit: usize) -> Vec<String> {
        let guard = self.inner.read().expect("log buffer lock");
        let n = limit.min(guard.len());
        guard
            .iter()
            .skip(guard.len().saturating_sub(n))
            .cloned()
            .collect()
    }
}

/// Pipe subprocess output into buffer and stderr.
pub fn pipe_to_buffer(
    stream: impl std::io::Read + Send + 'static,
    buffer: LogBuffer,
) {
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    eprintln!("{line}");
                    buffer.push(line);
                }
                Err(_) => break,
            }
        }
    });
}
