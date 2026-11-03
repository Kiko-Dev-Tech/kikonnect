//! Counter for datagrams dropped because they exceed the path's maximum datagram
//! size. Used to log drops at `warn` level without flooding the log.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Minimum time between two log-worthy reports.
const REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Counts dropped oversized datagrams and decides when a drop should be logged.
#[derive(Debug, Default)]
pub struct OversizeCounter {
    total: AtomicU64,
    last_report: Mutex<Option<Instant>>,
}

impl OversizeCounter {
    /// Creates a counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one dropped datagram.
    ///
    /// Returns `Some(total)` if the caller should log the drop now (the first drop
    /// and then at most once every few seconds), `None` otherwise.
    pub fn record(&self) -> Option<u64> {
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        let now = Instant::now();
        let mut last = match self.last_report.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match *last {
            Some(t) if now.duration_since(t) < REPORT_INTERVAL => None,
            _ => {
                *last = Some(now);
                Some(total)
            }
        }
    }

    /// Total number of drops recorded so far.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_drop_is_reported_then_throttled() {
        let c = OversizeCounter::new();
        assert_eq!(c.record(), Some(1));
        assert_eq!(c.record(), None);
        assert_eq!(c.record(), None);
        assert_eq!(c.total(), 3);
    }
}
