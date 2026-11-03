//! Server configuration.

use std::net::SocketAddr;
use std::time::Duration;

use kikonnect_protocol::{
    DEFAULT_SERVER_PORT, DEFAULT_UDP_SESSION_TIMEOUT, HANDSHAKE_TIMEOUT, NAME_GRACE_PERIOD,
};

/// Runtime configuration of the relay server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UDP address to listen on.
    pub listen: SocketAddr,
    /// Maximum number of simultaneously online tunnels.
    pub max_tunnels: usize,
    /// Maximum number of players per tunnel.
    pub max_players_per_tunnel: usize,
    /// Maximum number of concurrent UDP sessions per tunnel.
    pub max_udp_sessions_per_tunnel: usize,
    /// Maximum number of concurrent bidirectional streams a client may open.
    pub max_streams_per_connection: u32,
    /// Maximum number of concurrent QUIC connections.
    pub max_connections: usize,
    /// Idle timeout of UDP sessions.
    pub udp_session_timeout: Duration,
    /// How long a name stays reserved after its host disconnected.
    pub name_grace_period: Duration,
    /// Timeout for each handshake step.
    pub handshake_timeout: Duration,
    /// Token bucket size for `Register`/`Join` per source IP.
    pub rate_limit_burst: u32,
    /// Token refill rate for `Register`/`Join` per source IP and minute.
    /// `0` disables rate limiting.
    pub rate_limit_per_minute: u32,
    /// Version string reported in `HelloOk`.
    pub server_version: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_SERVER_PORT)),
            max_tunnels: 500,
            max_players_per_tunnel: 32,
            max_udp_sessions_per_tunnel: 1024,
            max_streams_per_connection: 256,
            max_connections: 10_000,
            udp_session_timeout: DEFAULT_UDP_SESSION_TIMEOUT,
            name_grace_period: NAME_GRACE_PERIOD,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            rate_limit_burst: 10,
            rate_limit_per_minute: 30,
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}
