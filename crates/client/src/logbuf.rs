//! Ring buffer of recent log lines, fed by a `tracing` layer.

use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Number of lines kept.
pub const LOG_CAPACITY: usize = 500;

/// Shared handle to the ring buffer.
#[derive(Debug, Clone, Default)]
pub struct LogBuffer {
    lines: Arc<Mutex<VecDeque<(Level, String)>>>,
}

impl LogBuffer {
    /// Appends a line, evicting the oldest when full.
    pub fn push(&self, level: Level, line: String) {
        // A poisoned lock only means another thread panicked while logging.
        let mut lines = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        if lines.len() >= LOG_CAPACITY {
            lines.pop_front();
        }
        lines.push_back((level, line));
    }

    /// Copy of the current lines, oldest first.
    pub fn snapshot(&self) -> Vec<(Level, String)> {
        let lines = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        lines.iter().cloned().collect()
    }

    /// Removes all lines.
    pub fn clear(&self) {
        self.lines.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// A `tracing` layer writing into this buffer.
    pub fn layer(&self) -> BufferLayer {
        BufferLayer {
            buffer: self.clone(),
        }
    }
}

/// `tracing` layer that formats events into a [`LogBuffer`].
#[derive(Debug)]
pub struct BufferLayer {
    buffer: LogBuffer,
}

struct LineVisitor(String);

impl Visit for LineVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut v = LineVisitor(String::new());
        event.record(&mut v);
        let line = format!("{:>5} {}", meta.level(), v.0);
        self.buffer.push(*meta.level(), line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn keeps_only_last_lines() {
        let buf = LogBuffer::default();
        for i in 0..(LOG_CAPACITY + 10) {
            buf.push(Level::INFO, format!("line {i}"));
        }
        let snap = buf.snapshot();
        assert_eq!(snap.len(), LOG_CAPACITY);
        assert_eq!(snap[0].1, "line 10");
    }

    #[test]
    fn layer_captures_events() {
        let buf = LogBuffer::default();
        let subscriber = tracing_subscriber::registry().with(buf.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(port = 1234, "something happened");
        });
        let snap = buf.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap[0].1.contains("something happened"));
        assert!(snap[0].1.contains("port=1234"));
        assert_eq!(snap[0].0, Level::WARN);
    }
}
