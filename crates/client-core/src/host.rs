//! Host mode: share local game servers through the relay.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use kikonnect_protocol::{
    close_code, normalize_name, read_frame, stream_code, validate_services, write_frame, ClientMsg,
    DatagramHeader, HostStreamHeader, OversizeCounter, Role, ServerMsg, ServiceDef, ServiceKind,
    DEFAULT_UDP_SESSION_TIMEOUT, HANDSHAKE_TIMEOUT, PING_INTERVAL,
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{interval, timeout, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::config::ClientConfig;
use crate::error::ClientError;
use crate::pipe;
use crate::transport::{self, close_and_drain, ControlStream};
use crate::util::{emit, is_transient_udp_error, send_datagram_checked, Activity};

/// Maximum number of concurrently relayed TCP connections per host.
const MAX_HOST_STREAMS: usize = 1024;
/// Interval of the UDP session expiry sweep.
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Automatic reconnect behaviour of [`run_host`].
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Whether to reconnect at all.
    pub enabled: bool,
    /// Delay before the first reconnect attempt.
    pub initial_delay: Duration,
    /// Upper bound for the exponential backoff.
    pub max_delay: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
        }
    }
}

impl ReconnectPolicy {
    /// Backoff delay before reconnect attempt `attempt` (starting at 1):
    /// exponential, capped at `max_delay`, with up to ±20% jitter.
    pub fn delay(&self, attempt: u32) -> Duration {
        let exp = attempt.saturating_sub(1).min(16);
        let base = self
            .initial_delay
            .saturating_mul(1u32 << exp)
            .min(self.max_delay);
        // Cheap jitter source; cryptographic quality is not needed here.
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let factor = 0.8 + f64::from(nanos % 1000) / 1000.0 * 0.4;
        base.mul_f64(factor)
    }
}

/// What a host shares.
#[derive(Clone)]
pub struct HostConfig {
    /// Requested tunnel name.
    pub name: String,
    /// Optional join password.
    pub password: Option<String>,
    /// Services to expose.
    pub services: Vec<ServiceDef>,
    /// Address the local game servers listen on (default `127.0.0.1`).
    pub target_ip: IpAddr,
    /// Idle timeout of UDP sessions.
    pub udp_session_timeout: Duration,
    /// Maximum number of concurrent UDP sessions.
    pub max_udp_sessions: usize,
    /// Reconnect behaviour of [`run_host`].
    pub reconnect: ReconnectPolicy,
}

impl fmt::Debug for HostConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostConfig")
            .field("name", &self.name)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("services", &self.services)
            .field("target_ip", &self.target_ip)
            .field("udp_session_timeout", &self.udp_session_timeout)
            .field("max_udp_sessions", &self.max_udp_sessions)
            .field("reconnect", &self.reconnect)
            .finish()
    }
}

impl HostConfig {
    /// Creates a configuration with default settings.
    pub fn new(name: impl Into<String>, services: Vec<ServiceDef>) -> Self {
        Self {
            name: name.into(),
            password: None,
            services,
            target_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            udp_session_timeout: DEFAULT_UDP_SESSION_TIMEOUT,
            max_udp_sessions: 1024,
            reconnect: ReconnectPolicy::default(),
        }
    }
}

/// Events reported by a running host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    /// Connection status changed. On any status other than `Online` the list of
    /// connected players is empty.
    Status(HostStatus),
    /// A player joined.
    PlayerConnected {
        /// Player id within the tunnel.
        player_id: u32,
        /// The player's public address.
        addr: SocketAddr,
        /// When the player joined.
        since: SystemTime,
    },
    /// A player left.
    PlayerDisconnected {
        /// Player id within the tunnel.
        player_id: u32,
    },
    /// Measured round-trip time to the relay server.
    Latency(Duration),
}

/// Connection status of a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostStatus {
    /// Connecting / registering.
    Connecting,
    /// Registered and reachable under `name`.
    Online {
        /// The normalized tunnel name.
        name: String,
    },
    /// Connection lost; waiting before the next attempt.
    Reconnecting {
        /// Attempt number (starting at 1).
        attempt: u32,
        /// Delay before the attempt.
        delay: Duration,
        /// Why the previous connection ended.
        reason: String,
    },
    /// Stopped with a non-recoverable error.
    Failed(String),
    /// Stopped by the user.
    Stopped,
}

/// A registered host connection.
#[derive(Debug)]
pub struct HostSession {
    endpoint: Endpoint,
    conn: Connection,
    control: ControlStream,
    name: String,
    reconnect_secret: String,
    config: HostConfig,
    handshake_timeout: Duration,
}

impl HostSession {
    /// Connects to the relay and registers the tunnel. Pass the secret from a
    /// previous session to reclaim the name after a disconnect.
    pub async fn connect(
        client: &ClientConfig,
        host: &HostConfig,
        reconnect_secret: Option<&str>,
    ) -> Result<Self, ClientError> {
        let name =
            normalize_name(&host.name).map_err(|e| ClientError::InvalidName(e.to_string()))?;
        validate_services(&host.services).map_err(ClientError::InvalidConfig)?;

        let connected = transport::connect(client).await?;
        let register = async {
            let mut control =
                ControlStream::open(&connected.connection, Role::Host, client).await?;
            control
                .send(&ClientMsg::Register {
                    name,
                    password: host.password.clone().filter(|p| !p.is_empty()),
                    services: host.services.clone(),
                    reconnect_secret: reconnect_secret.map(str::to_owned),
                })
                .await?;
            match control
                .recv(client.request_timeout, "waiting for registration")
                .await?
            {
                ServerMsg::Registered {
                    name,
                    reconnect_secret,
                } => Ok((control, name, reconnect_secret)),
                ServerMsg::Error { code, message } => Err(ClientError::Server { code, message }),
                other => Err(ClientError::Protocol(format!(
                    "unexpected reply to Register: {other:?}"
                ))),
            }
        };
        match register.await {
            Ok((control, name, reconnect_secret)) => {
                info!(%name, "tunnel online");
                Ok(Self {
                    endpoint: connected.endpoint,
                    conn: connected.connection,
                    control,
                    name,
                    reconnect_secret,
                    config: host.clone(),
                    handshake_timeout: client.request_timeout.min(HANDSHAKE_TIMEOUT),
                })
            }
            Err(e) => {
                connected.close(close_code::NORMAL, b"").await;
                Err(e)
            }
        }
    }

    /// The normalized tunnel name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Secret to reclaim the name after a disconnect.
    pub fn reconnect_secret(&self) -> &str {
        &self.reconnect_secret
    }

    /// Serves the tunnel until `cancel` is cancelled (`Ok(())`) or the connection
    /// ends (`Err`). Player events are sent to `events`.
    pub async fn run(
        self,
        events: &mpsc::Sender<HostEvent>,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let HostSession {
            endpoint,
            conn,
            control,
            name,
            config,
            handshake_timeout,
            ..
        } = self;
        let (mut ctrl_send, mut inbound) = control.into_running();
        let services: Arc<HashMap<u8, ServiceDef>> =
            Arc::new(config.services.iter().map(|s| (s.id, s.clone())).collect());
        let mut udp = HostUdp::new(conn.clone(), &config);
        let mut streams = JoinSet::new();
        let start = Instant::now();
        let mut ping = interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sweep = interval(UDP_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let result = loop {
            tokio::select! {
                _ = cancel.cancelled() => break Ok(()),
                msg = inbound.recv() => match msg {
                    Some(Ok(ServerMsg::PlayerConnected { player_id, addr })) => {
                        info!(tunnel = %name, player_id, %addr, "player connected");
                        emit(events, HostEvent::PlayerConnected { player_id, addr, since: SystemTime::now() });
                    }
                    Some(Ok(ServerMsg::PlayerDisconnected { player_id })) => {
                        info!(tunnel = %name, player_id, "player disconnected");
                        emit(events, HostEvent::PlayerDisconnected { player_id });
                    }
                    Some(Ok(ServerMsg::Pong { nonce })) => {
                        let rtt = start.elapsed().saturating_sub(Duration::from_micros(nonce));
                        emit(events, HostEvent::Latency(rtt));
                    }
                    Some(Ok(ServerMsg::ShuttingDown)) => break Err(ClientError::ServerShutdown),
                    Some(Ok(ServerMsg::Error { code, message })) => break Err(ClientError::Server { code, message }),
                    Some(Ok(other)) => debug!(?other, "ignoring unexpected control message"),
                    Some(Err(e)) => break Err(ClientError::Protocol(e)),
                    None => break Err(transport::close_error(&conn)),
                },
                stream = conn.accept_bi() => match stream {
                    Ok((mut send, mut recv)) => {
                        if streams.len() >= MAX_HOST_STREAMS {
                            warn!("too many concurrent connections, rejecting");
                            reject_stream(&mut send, &mut recv);
                        } else {
                            streams.spawn(handle_host_stream(
                                services.clone(),
                                config.target_ip,
                                send,
                                recv,
                                handshake_timeout,
                            ));
                        }
                    }
                    Err(_) => break Err(transport::close_error(&conn)),
                },
                dg = conn.read_datagram() => match dg {
                    Ok(data) => udp.on_datagram(data).await,
                    Err(_) => break Err(transport::close_error(&conn)),
                },
                _ = ping.tick() => {
                    let nonce = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                    match timeout(PING_INTERVAL, write_frame(&mut ctrl_send, &ClientMsg::Ping { nonce })).await {
                        Ok(Ok(())) => {}
                        _ => break Err(transport::close_error(&conn)),
                    }
                }
                _ = sweep.tick() => udp.expire(),
                Some(_) = streams.join_next(), if !streams.is_empty() => {}
            }
        };

        drop(udp);
        streams.abort_all();
        let reason: &[u8] = if result.is_ok() { b"host stopped" } else { b"" };
        close_and_drain(&endpoint, &conn, close_code::NORMAL, reason).await;
        match &result {
            Ok(()) => info!(tunnel = %name, "tunnel stopped"),
            Err(e) => info!(tunnel = %name, "tunnel connection ended: {e}"),
        }
        result
    }
}

fn reject_stream(send: &mut SendStream, recv: &mut RecvStream) {
    let _ = send.reset(VarInt::from_u32(stream_code::REJECTED));
    let _ = recv.stop(VarInt::from_u32(stream_code::REJECTED));
}

async fn handle_host_stream(
    services: Arc<HashMap<u8, ServiceDef>>,
    target_ip: IpAddr,
    mut send: SendStream,
    mut recv: RecvStream,
    hs: Duration,
) {
    let header = match timeout(hs, read_frame::<_, HostStreamHeader>(&mut recv)).await {
        Ok(Ok(Some(h))) => h,
        _ => {
            debug!("invalid or missing stream header from server");
            reject_stream(&mut send, &mut recv);
            return;
        }
    };
    let Some(service) = services
        .get(&header.service_id)
        .filter(|s| s.kind == ServiceKind::Tcp)
    else {
        debug!(
            service_id = header.service_id,
            "stream for unknown TCP service"
        );
        reject_stream(&mut send, &mut recv);
        return;
    };
    let target = SocketAddr::new(target_ip, service.port);
    let tcp = match timeout(hs, TcpStream::connect(target)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            warn!(
                service = %service.label,
                %target,
                player_id = header.player_id,
                "cannot reach local game server: {e}. Is it running?"
            );
            reject_stream(&mut send, &mut recv);
            return;
        }
        Err(_) => {
            warn!(service = %service.label, %target, "timed out connecting to local game server");
            reject_stream(&mut send, &mut recv);
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    debug!(
        conn_id = header.conn_id,
        player_id = header.player_id,
        player_addr = %header.player_addr,
        service = %service.label,
        "TCP connection opened"
    );
    let (up, down) = pipe::tcp_over_quic(tcp, send, recv).await;
    debug!(conn_id = header.conn_id, to_player = ?up, from_player = ?down, "TCP connection closed");
}

/// One UDP session on the host: an ephemeral socket connected to the game server.
struct HostUdpSession {
    socket: Arc<UdpSocket>,
    activity: Arc<Activity>,
    task: JoinHandle<()>,
}

impl Drop for HostUdpSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// UDP forwarding state of a host connection.
struct HostUdp {
    conn: Connection,
    target_ip: IpAddr,
    /// UDP service id -> local port.
    services: HashMap<u8, u16>,
    sessions: HashMap<(u8, u32), HostUdpSession>,
    max_sessions: usize,
    timeout: Duration,
    base: Instant,
    oversize: Arc<OversizeCounter>,
}

impl HostUdp {
    fn new(conn: Connection, config: &HostConfig) -> Self {
        Self {
            conn,
            target_ip: config.target_ip,
            services: config
                .services
                .iter()
                .filter(|s| s.kind == ServiceKind::Udp)
                .map(|s| (s.id, s.port))
                .collect(),
            sessions: HashMap::new(),
            max_sessions: config.max_udp_sessions,
            timeout: config.udp_session_timeout,
            base: Instant::now(),
            oversize: Arc::new(OversizeCounter::new()),
        }
    }

    async fn on_datagram(&mut self, data: Bytes) {
        let Ok((hdr, payload)) = DatagramHeader::decode_bytes(&data) else {
            trace!("malformed datagram");
            return;
        };
        let key = (hdr.service_id, hdr.session_id);
        if !self.sessions.contains_key(&key) {
            let Some(&port) = self.services.get(&hdr.service_id) else {
                trace!(
                    service_id = hdr.service_id,
                    "datagram for unknown UDP service"
                );
                return;
            };
            if self.sessions.len() >= self.max_sessions {
                debug!("UDP session limit reached, dropping datagram");
                return;
            }
            match self.open_session(hdr, port).await {
                Ok(session) => {
                    debug!(
                        service_id = hdr.service_id,
                        session = hdr.session_id,
                        "new UDP session"
                    );
                    self.sessions.insert(key, session);
                }
                Err(e) => {
                    warn!("failed to open UDP socket for session: {e}");
                    return;
                }
            }
        }
        if let Some(session) = self.sessions.get(&key) {
            session.activity.touch();
            if let Err(e) = session.socket.send(&payload).await {
                trace!("failed to send to local game server: {e}");
            }
        }
    }

    async fn open_session(
        &self,
        hdr: DatagramHeader,
        port: u16,
    ) -> std::io::Result<HostUdpSession> {
        let bind_ip = match self.target_ip {
            IpAddr::V4(ip) if ip.is_loopback() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(ip) if ip.is_loopback() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
        socket
            .connect(SocketAddr::new(self.target_ip, port))
            .await?;
        let socket = Arc::new(socket);
        let activity = Arc::new(Activity::new(self.base));
        let task = tokio::spawn(host_udp_reader(
            socket.clone(),
            activity.clone(),
            self.conn.clone(),
            hdr,
            self.oversize.clone(),
        ));
        Ok(HostUdpSession {
            socket,
            activity,
            task,
        })
    }

    fn expire(&mut self) {
        let timeout = self.timeout;
        let before = self.sessions.len();
        self.sessions.retain(|_, s| s.activity.idle_for() < timeout);
        let expired = before - self.sessions.len();
        if expired > 0 {
            debug!(expired, "expired idle UDP sessions");
        }
    }
}

async fn host_udp_reader(
    socket: Arc<UdpSocket>,
    activity: Arc<Activity>,
    conn: Connection,
    hdr: DatagramHeader,
    oversize: Arc<OversizeCounter>,
) {
    let mut buf = vec![0u8; 65_535];
    loop {
        match socket.recv(&mut buf).await {
            Ok(n) => {
                activity.touch();
                send_datagram_checked(&conn, hdr.encode_with(&buf[..n]), &oversize);
            }
            Err(e) if is_transient_udp_error(&e) => {
                trace!("transient UDP error (local game server not reachable?): {e}");
            }
            Err(e) => {
                warn!("UDP session socket failed: {e}");
                break;
            }
        }
    }
}

/// Runs a host with automatic reconnects until `cancel` is cancelled or a
/// non-recoverable error occurs.
///
/// After a connection loss the name is reclaimed with the reconnect secret. Status
/// changes and player events are reported through `events`. Returns `Ok(())` when
/// stopped via `cancel`.
pub async fn run_host(
    client: ClientConfig,
    host: HostConfig,
    events: mpsc::Sender<HostEvent>,
    cancel: CancellationToken,
) -> Result<(), ClientError> {
    let mut secret: Option<String> = None;
    let mut attempt = 0u32;
    loop {
        emit(&events, HostEvent::Status(HostStatus::Connecting));
        let connect = HostSession::connect(&client, &host, secret.as_deref());
        let result = tokio::select! {
            _ = cancel.cancelled() => {
                emit(&events, HostEvent::Status(HostStatus::Stopped));
                return Ok(());
            }
            r = connect => r,
        };
        let err = match result {
            Ok(session) => {
                secret = Some(session.reconnect_secret().to_owned());
                attempt = 0;
                emit(
                    &events,
                    HostEvent::Status(HostStatus::Online {
                        name: session.name().to_owned(),
                    }),
                );
                match session.run(&events, &cancel).await {
                    Ok(()) => {
                        emit(&events, HostEvent::Status(HostStatus::Stopped));
                        return Ok(());
                    }
                    Err(e) => e,
                }
            }
            Err(e) => e,
        };
        if !host.reconnect.enabled || !err.is_retryable() {
            let message = if err.code() == Some(kikonnect_protocol::ErrorCode::NameTaken)
                && secret.is_some()
            {
                format!("{err} (the reservation expired and someone else took the name)")
            } else {
                err.to_string()
            };
            emit(&events, HostEvent::Status(HostStatus::Failed(message)));
            return Err(err);
        }
        attempt = attempt.saturating_add(1);
        let delay = host.reconnect.delay(attempt);
        warn!(attempt, ?delay, "host connection lost: {err}; reconnecting");
        emit(
            &events,
            HostEvent::Status(HostStatus::Reconnecting {
                attempt,
                delay,
                reason: err.to_string(),
            }),
        );
        tokio::select! {
            _ = cancel.cancelled() => {
                emit(&events, HostEvent::Status(HostStatus::Stopped));
                return Ok(());
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        let p = ReconnectPolicy {
            enabled: true,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
        };
        let within = |d: Duration, base: f64| {
            let s = d.as_secs_f64();
            s >= base * 0.8 - 1e-9 && s <= base * 1.2 + 1e-9
        };
        assert!(within(p.delay(1), 1.0));
        assert!(within(p.delay(2), 2.0));
        assert!(within(p.delay(3), 4.0));
        assert!(within(p.delay(10), 30.0));
        assert!(within(p.delay(u32::MAX), 30.0));
    }

    #[test]
    fn debug_redacts_password() {
        let mut c = HostConfig::new("kilian", vec![]);
        c.password = Some("hunter2".into());
        assert!(!format!("{c:?}").contains("hunter2"));
    }
}
