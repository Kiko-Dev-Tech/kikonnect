//! Protocol constants shared by server and clients.

use std::time::Duration;

/// Version of the wire protocol. Bumped on every incompatible change.
pub const PROTOCOL_VERSION: u16 = 1;

/// TLS ALPN protocol identifier used on every QUIC connection.
pub const ALPN: &[u8] = b"kikonnect/1";

/// Default UDP port of the relay server.
pub const DEFAULT_SERVER_PORT: u16 = 7000;

/// QUIC keep-alive interval.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// QUIC idle timeout. A connection without any traffic (including keep-alives)
/// for this long is considered dead.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for every individual handshake step (QUIC handshake, opening the
/// control stream, waiting for `Hello`, `Register`, `Join`, stream headers, ...).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum size of one control frame payload (excluding the 4-byte length prefix).
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// How long a tunnel name stays reserved for its previous host after the host
/// disconnected. The host can reclaim it with its reconnect secret.
pub const NAME_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// Default idle timeout of a UDP session (on all three sides).
pub const DEFAULT_UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of services a single host may expose.
pub const MAX_SERVICES: usize = 16;

/// Maximum length (in bytes) of a service label.
pub const MAX_LABEL_LEN: usize = 64;

/// Maximum length (in bytes) of a join password.
pub const MAX_PASSWORD_LEN: usize = 128;

/// Interval at which clients send `Ping` on the control stream to measure latency.
pub const PING_INTERVAL: Duration = Duration::from_secs(5);

/// QUIC application close codes used when closing a connection.
pub mod close_code {
    /// Normal close, e.g. the user pressed "Stop" / "Disconnect".
    pub const NORMAL: u32 = 0;
    /// The peer violated the protocol.
    pub const PROTOCOL_ERROR: u32 = 1;
    /// The tunnel's host left; sent by the server to players.
    pub const HOST_GONE: u32 = 2;
    /// The server is shutting down.
    pub const SERVER_SHUTDOWN: u32 = 3;
    /// The request was rejected; a `ServerMsg::Error` was sent before closing.
    pub const REJECTED: u32 = 4;
    /// The host connection was replaced by a newer connection of the same host.
    pub const REPLACED: u32 = 5;
}

/// QUIC stream error codes used for `reset` / `stop` on data streams.
pub mod stream_code {
    /// The other side of the relayed connection failed or was aborted.
    pub const ABORTED: u32 = 1;
    /// The stream was rejected (unknown service, bad header, local service unreachable).
    pub const REJECTED: u32 = 2;
}
