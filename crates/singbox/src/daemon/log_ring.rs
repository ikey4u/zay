use super::proto;

/// Fixed-size chronological log buffer used by daemon subscriptions.
#[derive(Debug)]
pub struct LogRing {
    entries: Vec<proto::log::Message>,
    max_lines: usize,
    start: usize,
}

impl LogRing {
    pub fn new(max_lines: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_lines),
            max_lines,
            start: 0,
        }
    }

    pub fn push(&mut self, entry: proto::log::Message) {
        if self.max_lines == 0 {
            return;
        }
        if self.entries.len() < self.max_lines {
            self.entries.push(entry);
            return;
        }
        self.entries[self.start] = entry;
        self.start += 1;
        if self.start == self.entries.len() {
            self.start = 0;
        }
    }

    pub fn snapshot(&self) -> Vec<proto::log::Message> {
        self.entries[self.start..]
            .iter()
            .chain(&self.entries[..self.start])
            .cloned()
            .collect()
    }

    pub fn reset(&mut self) {
        self.entries.clear();
        self.start = 0;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{LogRing, proto};

    fn message(value: &str) -> proto::log::Message {
        proto::log::Message {
            level: proto::LogLevel::Info.into(),
            message: value.into(),
        }
    }

    #[test]
    fn wraps_in_chronological_order_and_resets_like_upstream() {
        let mut ring = LogRing::new(3);
        for value in ["one", "two", "three", "four", "five"] {
            ring.push(message(value));
        }
        assert_eq!(
            ring.snapshot()
                .into_iter()
                .map(|entry| entry.message)
                .collect::<Vec<_>>(),
            ["three", "four", "five"]
        );
        assert_eq!(ring.len(), 3);

        ring.reset();
        assert!(ring.is_empty());
        ring.push(message("six"));
        assert_eq!(ring.snapshot()[0].message, "six");

        let mut disabled = LogRing::new(0);
        disabled.push(message("ignored"));
        assert!(disabled.is_empty());
    }
}
