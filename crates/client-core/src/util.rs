//! Small shared helpers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use kikonnect_protocol::OversizeCounter;
use quinn::Connection;
use tokio::sync::mpsc;
use tracing::{trace, warn};

/// Sends an event without ever blocking networking. Drops the event (with a
/// warning) if the consumer is not keeping up.
pub(crate) fn emit<T>(tx: &mpsc::Sender<T>, event: T) {
    if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(event) {
        warn!("event channel full, dropping event");
    }
}

/// Sends a datagram if it fits into the current maximum datagram size; otherwise
/// drops it and logs (throttled) at `warn` level.
pub(crate) fn send_datagram_checked(conn: &Connection, data: Bytes, counter: &OversizeCounter) {
    match conn.max_datagram_size() {
        Some(max) if data.len() <= max => {
            if let Err(e) = conn.send_datagram(data) {
                trace!("failed to send datagram: {e}");
            }
        }
        Some(max) => {
            if let Some(total) = counter.record() {
                warn!(
                    size = data.len(),
                    max,
                    total_dropped = total,
                    "dropping oversized UDP packet (fragmentation is not supported)"
                );
            }
        }
        None => trace!("server does not support datagrams"),
    }
}

/// A shareable "last activity" timestamp relative to a base instant.
#[derive(Debug)]
pub(crate) struct Activity {
    base: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    pub(crate) fn new(base: Instant) -> Self {
        let a = Self {
            base,
            last_ms: AtomicU64::new(0),
        };
        a.touch();
        a
    }

    pub(crate) fn touch(&self) {
        let ms = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    pub(crate) fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        self.base.elapsed().saturating_sub(last)
    }
}

/// Whether a UDP receive error is transient (ICMP port unreachable reported on the
/// socket, notably `WSAECONNRESET` on Windows) and the socket remains usable.
pub(crate) fn is_transient_udp_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    )
}
