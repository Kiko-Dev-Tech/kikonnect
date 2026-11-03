//! QUIC endpoint, accept loop and graceful shutdown.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kikonnect_protocol::{close_code, OversizeCounter, IDLE_TIMEOUT, KEEP_ALIVE_INTERVAL};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, IdleTimeout, TransportConfig, VarInt};
use tokio::sync::Semaphore;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::config::ServerConfig;
use crate::connection;
use crate::ratelimit::RateLimiter;
use crate::registry::Registry;

/// How long connection handlers get to say goodbye during shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// How often expired grace reservations and rate limiter buckets are purged.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);

/// Errors starting or running the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Binding the UDP socket failed.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The address.
        addr: SocketAddr,
        /// The cause.
        source: io::Error,
    },
    /// The configuration is invalid.
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Shared state of a running server.
#[derive(Debug)]
pub(crate) struct ServerState {
    pub config: ServerConfig,
    pub registry: Registry,
    pub rate_limiter: RateLimiter,
    pub shutdown: CancellationToken,
    pub oversize: OversizeCounter,
}

/// The relay server.
#[derive(Debug)]
pub struct Server {
    endpoint: Endpoint,
    transport: Arc<TransportConfig>,
    state: Arc<ServerState>,
}

fn transport_config(cfg: &ServerConfig) -> Result<TransportConfig, ServerError> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        IdleTimeout::try_from(IDLE_TIMEOUT).map_err(|e| ServerError::Config(e.to_string()))?,
    ));
    t.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    t.max_concurrent_bidi_streams(VarInt::from_u32(cfg.max_streams_per_connection));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.datagram_receive_buffer_size(Some(1 << 20));
    t.datagram_send_buffer_size(1 << 20);
    Ok(t)
}

/// Handle to swap the TLS certificate of a running server.
#[derive(Debug, Clone)]
pub struct CryptoUpdater {
    endpoint: Endpoint,
    transport: Arc<TransportConfig>,
}

impl CryptoUpdater {
    /// Replaces the TLS certificate for new connections. Existing connections are
    /// not affected.
    pub fn set_crypto(&self, crypto: QuicServerConfig) {
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(self.transport.clone());
        self.endpoint.set_server_config(Some(server_config));
    }
}

impl Server {
    /// Binds the QUIC endpoint. Must be called within a tokio runtime.
    pub fn bind(config: ServerConfig, crypto: QuicServerConfig) -> Result<Self, ServerError> {
        if config.max_players_per_tunnel == 0 || config.max_tunnels == 0 {
            return Err(ServerError::Config(
                "max tunnels and max players per tunnel must be at least 1".into(),
            ));
        }
        let transport = Arc::new(transport_config(&config)?);
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(transport.clone());
        let endpoint =
            Endpoint::server(server_config, config.listen).map_err(|source| ServerError::Bind {
                addr: config.listen,
                source,
            })?;
        let state = Arc::new(ServerState {
            registry: Registry::new(config.max_tunnels, config.name_grace_period),
            rate_limiter: RateLimiter::new(config.rate_limit_burst, config.rate_limit_per_minute),
            shutdown: CancellationToken::new(),
            oversize: OversizeCounter::new(),
            config,
        });
        Ok(Self {
            endpoint,
            transport,
            state,
        })
    }

    /// The address the server is listening on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Replaces the TLS certificate for new connections (e.g. after a renewal).
    /// Existing connections are not affected.
    pub fn set_crypto(&self, crypto: QuicServerConfig) {
        self.crypto_updater().set_crypto(crypto);
    }

    /// A cloneable handle to replace the certificate while [`run`](Self::run)
    /// owns the server.
    pub fn crypto_updater(&self) -> CryptoUpdater {
        CryptoUpdater {
            endpoint: self.endpoint.clone(),
            transport: self.transport.clone(),
        }
    }

    /// Number of online tunnels.
    pub fn tunnel_count(&self) -> usize {
        self.state.registry.active_count()
    }

    /// Runs the accept loop until `shutdown` is cancelled, then notifies all
    /// clients, closes their connections and returns.
    pub async fn run(self, shutdown: CancellationToken) -> Result<(), ServerError> {
        let state = self.state;
        let tracker = TaskTracker::new();
        let slots = Arc::new(Semaphore::new(state.config.max_connections));
        let mut maintenance = interval(MAINTENANCE_INTERVAL);
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = maintenance.tick() => {
                    let now = Instant::now();
                    state.registry.cleanup(now);
                    state.rate_limiter.cleanup(now);
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        debug!(remote = %incoming.remote_address(), "connection limit reached, refusing");
                        incoming.refuse();
                        continue;
                    };
                    let state = state.clone();
                    tracker.spawn(async move {
                        handle_incoming(state, incoming).await;
                        drop(permit);
                    });
                }
            }
        }

        info!(
            tunnels = state.registry.active_count(),
            "shutting down, notifying clients"
        );
        state.shutdown.cancel();
        tracker.close();
        if timeout(SHUTDOWN_GRACE, tracker.wait()).await.is_err() {
            warn!("some connections did not close in time");
        }
        self.endpoint.close(
            VarInt::from_u32(close_code::SERVER_SHUTDOWN),
            b"server shutting down",
        );
        let _ = timeout(Duration::from_secs(3), self.endpoint.wait_idle()).await;
        info!("shutdown complete");
        Ok(())
    }
}

async fn handle_incoming(state: Arc<ServerState>, incoming: quinn::Incoming) {
    let remote = incoming.remote_address();
    let connecting = match incoming.accept() {
        Ok(c) => c,
        Err(e) => {
            debug!(%remote, "failed to accept connection: {e}");
            return;
        }
    };
    let conn = tokio::select! {
        _ = state.shutdown.cancelled() => return,
        res = timeout(state.config.handshake_timeout, connecting) => match res {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                debug!(%remote, "QUIC handshake failed: {e}");
                return;
            }
            Err(_) => {
                debug!(%remote, "QUIC handshake timed out");
                return;
            }
        },
    };
    connection::handle(state, conn).await;
}
