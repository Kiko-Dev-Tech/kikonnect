//! Join mode: connect local game clients to a host through the relay.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use kikonnect_protocol::{
    close_code, normalize_name, write_frame, ClientMsg, DatagramHeader, OversizeCounter, Role,
    ServerMsg, ServiceDef, ServiceKind, StreamHeader, DEFAULT_UDP_SESSION_TIMEOUT,
    HANDSHAKE_TIMEOUT, PING_INTERVAL,
};
use quinn::{Connection, Endpoint};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{interval, timeout, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::config::ClientConfig;
use crate::error::ClientError;
use crate::pipe;
use crate::transport::{self, close_and_drain, ControlStream};
use crate::util::{emit, is_transient_udp_error, send_datagram_checked};

/// Capacity of the per-service queue of datagrams coming from the tunnel.
const UDP_QUEUE: usize = 1024;

/// What to join and how to expose it locally.
#[derive(Clone)]
pub struct JoinConfig {
    /// Tunnel name of the host.
    pub name: String,
    /// Join password, if the host set one.
    pub password: Option<String>,
    /// IP the local listeners bind to (default `127.0.0.1`; never exposed to the LAN
    /// unless changed).
    pub bind_ip: IpAddr,
    /// Idle timeout of UDP sessions.
    pub udp_session_timeout: Duration,
    /// Maximum number of UDP sessions (distinct local game clients) per service.
    pub max_udp_sessions_per_service: usize,
    /// Maximum number of concurrent TCP connections per service.
    pub max_tcp_connections_per_service: usize,
    /// If a preferred local port is busy, try up to this many following ports.
    pub port_search_range: u16,
}

impl fmt::Debug for JoinConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinConfig")
            .field("name", &self.name)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("bind_ip", &self.bind_ip)
            .field("udp_session_timeout", &self.udp_session_timeout)
            .field(
                "max_udp_sessions_per_service",
                &self.max_udp_sessions_per_service,
            )
            .field(
                "max_tcp_connections_per_service",
                &self.max_tcp_connections_per_service,
            )
            .field("port_search_range", &self.port_search_range)
            .finish()
    }
}

impl JoinConfig {
    /// Creates a configuration with default settings.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: None,
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            udp_session_timeout: DEFAULT_UDP_SESSION_TIMEOUT,
            max_udp_sessions_per_service: 256,
            max_tcp_connections_per_service: 256,
            port_search_range: 100,
        }
    }
}

/// Events reported by a running player session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayerEvent {
    /// A service is reachable locally at `local_addr`.
    Forwarding {
        /// Service id.
        service_id: u8,
        /// Local address to point the game at.
        local_addr: SocketAddr,
    },
    /// A service could not be bound locally.
    ForwardFailed {
        /// Service id.
        service_id: u8,
        /// What went wrong.
        error: String,
    },
    /// Measured round-trip time to the relay server.
    Latency(Duration),
    /// The host left; the session ends.
    HostGone,
}

/// Commands accepted by a running player session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayerCommand {
    /// Move a service to another local port (`0` = any free port). Existing
    /// connections of that service are closed.
    SetLocalPort {
        /// Service id.
        service_id: u8,
        /// Preferred local port.
        port: u16,
    },
}

/// Why a player session ended without error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayerExit {
    /// Stopped via the cancellation token.
    Cancelled,
    /// The host left.
    HostGone,
}

/// A locally bound socket for one service.
#[derive(Debug)]
enum BoundSocket {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

impl BoundSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            BoundSocket::Tcp(l) => l.local_addr(),
            BoundSocket::Udp(s) => s.local_addr(),
        }
    }
}

fn is_port_busy(e: &io::Error) -> bool {
    // Windows reports excluded / reserved port ranges as PermissionDenied.
    matches!(
        e.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}

/// Binds a local socket at `preferred` or, if busy, the next free port within
/// `range`. `preferred == 0` picks any free port.
async fn bind_local(
    kind: ServiceKind,
    ip: IpAddr,
    preferred: u16,
    range: u16,
) -> io::Result<BoundSocket> {
    let bind = |port: u16| async move {
        let addr = SocketAddr::new(ip, port);
        match kind {
            ServiceKind::Tcp => TcpListener::bind(addr).await.map(BoundSocket::Tcp),
            ServiceKind::Udp => UdpSocket::bind(addr).await.map(BoundSocket::Udp),
        }
    };
    if preferred == 0 {
        return bind(0).await;
    }
    let mut last_err = None;
    for offset in 0..=range {
        let Some(port) = preferred.checked_add(offset) else {
            break;
        };
        match bind(port).await {
            Ok(s) => return Ok(s),
            Err(e) if is_port_busy(&e) => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "no free local port found near {preferred}{}",
            last_err.map(|e| format!(" ({e})")).unwrap_or_default()
        ),
    ))
}

/// A joined tunnel.
#[derive(Debug)]
pub struct PlayerSession {
    endpoint: Endpoint,
    conn: Connection,
    control: ControlStream,
    host_name: String,
    services: Vec<ServiceDef>,
    player_id: u32,
    config: JoinConfig,
    handshake_timeout: Duration,
    bound: HashMap<u8, BoundSocket>,
}

impl PlayerSession {
    /// Connects to the relay and joins the tunnel `join.name`.
    pub async fn connect(client: &ClientConfig, join: &JoinConfig) -> Result<Self, ClientError> {
        let name =
            normalize_name(&join.name).map_err(|e| ClientError::InvalidName(e.to_string()))?;
        let connected = transport::connect(client).await?;
        let joined = async {
            let mut control =
                ControlStream::open(&connected.connection, Role::Player, client).await?;
            control
                .send(&ClientMsg::Join {
                    name,
                    password: join.password.clone().filter(|p| !p.is_empty()),
                })
                .await?;
            match control
                .recv(client.request_timeout, "waiting to join")
                .await?
            {
                ServerMsg::Joined {
                    host_name,
                    services,
                    player_id,
                } => Ok((control, host_name, services, player_id)),
                ServerMsg::Error { code, message } => Err(ClientError::Server { code, message }),
                other => Err(ClientError::Protocol(format!(
                    "unexpected reply to Join: {other:?}"
                ))),
            }
        };
        match joined.await {
            Ok((control, host_name, services, player_id)) => {
                info!(host = %host_name, player_id, services = services.len(), "joined tunnel");
                Ok(Self {
                    endpoint: connected.endpoint,
                    conn: connected.connection,
                    control,
                    host_name,
                    services,
                    player_id,
                    config: join.clone(),
                    handshake_timeout: client.request_timeout.min(HANDSHAKE_TIMEOUT),
                    bound: HashMap::new(),
                })
            }
            Err(e) => {
                connected.close(close_code::NORMAL, b"").await;
                Err(e)
            }
        }
    }

    /// The host's tunnel name.
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    /// Services exposed by the host.
    pub fn services(&self) -> &[ServiceDef] {
        &self.services
    }

    /// This player's id within the tunnel.
    pub fn player_id(&self) -> u32 {
        self.player_id
    }

    /// Binds the local socket for a service at `port` (or the next free port;
    /// `0` = any free port) ahead of [`run`](Self::run). Services not bound
    /// explicitly are bound at the host's port when `run` starts.
    pub async fn bind(&mut self, service_id: u8, port: u16) -> Result<SocketAddr, ClientError> {
        let service = self
            .services
            .iter()
            .find(|s| s.id == service_id)
            .ok_or_else(|| ClientError::InvalidConfig(format!("unknown service {service_id}")))?;
        // Release a previous binding first so its port can be reused.
        self.bound.remove(&service_id);
        let socket = bind_local(
            service.kind,
            self.config.bind_ip,
            port,
            self.config.port_search_range,
        )
        .await?;
        let addr = socket.local_addr()?;
        self.bound.insert(service_id, socket);
        Ok(addr)
    }

    /// Binds all services: `ports` overrides the local port per service id,
    /// otherwise the host's port is preferred. Returns the result per service.
    pub async fn bind_all(
        &mut self,
        ports: &HashMap<u8, u16>,
    ) -> Vec<(u8, Result<SocketAddr, ClientError>)> {
        let wanted: Vec<(u8, u16)> = self
            .services
            .iter()
            .map(|s| (s.id, ports.get(&s.id).copied().unwrap_or(s.port)))
            .collect();
        let mut out = Vec::with_capacity(wanted.len());
        for (id, port) in wanted {
            let r = self.bind(id, port).await;
            out.push((id, r));
        }
        out
    }

    /// The local address of an already bound service.
    pub fn local_addr(&self, service_id: u8) -> Option<SocketAddr> {
        self.bound
            .get(&service_id)
            .and_then(|s| s.local_addr().ok())
    }

    /// Forwards traffic until the host leaves (`Ok(PlayerExit::HostGone)`), `cancel`
    /// is cancelled (`Ok(PlayerExit::Cancelled)`) or the connection fails (`Err`).
    ///
    /// All local listeners are closed before this returns.
    pub async fn run(
        self,
        events: mpsc::Sender<PlayerEvent>,
        mut commands: Option<mpsc::Receiver<PlayerCommand>>,
        cancel: CancellationToken,
    ) -> Result<PlayerExit, ClientError> {
        let PlayerSession {
            endpoint,
            conn,
            control,
            host_name,
            services,
            config,
            handshake_timeout,
            mut bound,
            ..
        } = self;
        let (mut ctrl_send, mut inbound) = control.into_running();
        let shared = Arc::new(Shared {
            conn: conn.clone(),
            next_session: AtomicU32::new(1),
            oversize: OversizeCounter::new(),
            udp_timeout: config.udp_session_timeout,
            max_udp_sessions: config.max_udp_sessions_per_service,
            max_tcp_connections: config.max_tcp_connections_per_service,
            handshake_timeout,
        });

        let mut forwarders: HashMap<u8, Forwarder> = HashMap::new();
        for service in &services {
            let socket = match bound.remove(&service.id) {
                Some(s) => Ok(s),
                None => {
                    bind_local(
                        service.kind,
                        config.bind_ip,
                        service.port,
                        config.port_search_range,
                    )
                    .await
                }
            };
            start_service(&shared, service, socket, &mut forwarders, &events);
        }

        let start = Instant::now();
        let mut ping = interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let result = loop {
            let mut commands_closed = false;
            tokio::select! {
                _ = cancel.cancelled() => break Ok(PlayerExit::Cancelled),
                msg = inbound.recv() => match msg {
                    Some(Ok(ServerMsg::Pong { nonce })) => {
                        let rtt = start.elapsed().saturating_sub(Duration::from_micros(nonce));
                        emit(&events, PlayerEvent::Latency(rtt));
                    }
                    Some(Ok(ServerMsg::HostGone)) => break Ok(PlayerExit::HostGone),
                    Some(Ok(ServerMsg::ShuttingDown)) => break Err(ClientError::ServerShutdown),
                    Some(Ok(ServerMsg::Error { code, message })) => break Err(ClientError::Server { code, message }),
                    Some(Ok(other)) => debug!(?other, "ignoring unexpected control message"),
                    Some(Err(e)) => break Err(ClientError::Protocol(e)),
                    None => match transport::close_error(&conn) {
                        ClientError::HostGone => break Ok(PlayerExit::HostGone),
                        e => break Err(e),
                    },
                },
                dg = conn.read_datagram() => match dg {
                    Ok(data) => dispatch_datagram(&forwarders, data),
                    Err(_) => match transport::close_error(&conn) {
                        ClientError::HostGone => break Ok(PlayerExit::HostGone),
                        e => break Err(e),
                    },
                },
                _ = ping.tick() => {
                    let nonce = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                    match timeout(PING_INTERVAL, write_frame(&mut ctrl_send, &ClientMsg::Ping { nonce })).await {
                        Ok(Ok(())) => {}
                        _ => match transport::close_error(&conn) {
                            ClientError::HostGone => break Ok(PlayerExit::HostGone),
                            e => break Err(e),
                        },
                    }
                }
                cmd = next_command(&mut commands) => match cmd {
                    Some(PlayerCommand::SetLocalPort { service_id, port }) => {
                        let Some(service) = services.iter().find(|s| s.id == service_id) else {
                            emit(&events, PlayerEvent::ForwardFailed { service_id, error: "unknown service".into() });
                            continue;
                        };
                        if let Some(old) = forwarders.remove(&service_id) {
                            old.stop().await;
                        }
                        let socket = bind_local(service.kind, config.bind_ip, port, config.port_search_range).await;
                        start_service(&shared, service, socket, &mut forwarders, &events);
                    }
                    None => commands_closed = true,
                },
            }
            if commands_closed {
                commands = None;
            }
        };

        for (_, f) in forwarders.drain() {
            f.stop().await;
        }
        if matches!(result, Ok(PlayerExit::HostGone)) {
            info!(host = %host_name, "host left the tunnel");
            emit(&events, PlayerEvent::HostGone);
        }
        close_and_drain(&endpoint, &conn, close_code::NORMAL, b"").await;
        if let Err(e) = &result {
            info!(host = %host_name, "connection ended: {e}");
        }
        result
    }
}

async fn next_command(
    commands: &mut Option<mpsc::Receiver<PlayerCommand>>,
) -> Option<PlayerCommand> {
    match commands {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn start_service(
    shared: &Arc<Shared>,
    service: &ServiceDef,
    socket: io::Result<BoundSocket>,
    forwarders: &mut HashMap<u8, Forwarder>,
    events: &mpsc::Sender<PlayerEvent>,
) {
    let started = socket.and_then(|s| Forwarder::start(shared, service, s));
    match started {
        Ok(f) => {
            info!(
                service = %service.label,
                kind = %service.kind,
                local = %f.local_addr,
                "forwarding: connect your game to {}",
                f.local_addr
            );
            emit(
                events,
                PlayerEvent::Forwarding {
                    service_id: service.id,
                    local_addr: f.local_addr,
                },
            );
            forwarders.insert(service.id, f);
        }
        Err(e) => {
            warn!(service = %service.label, "cannot bind local port: {e}");
            emit(
                events,
                PlayerEvent::ForwardFailed {
                    service_id: service.id,
                    error: e.to_string(),
                },
            );
        }
    }
}

fn dispatch_datagram(forwarders: &HashMap<u8, Forwarder>, data: Bytes) {
    let Ok((hdr, payload)) = DatagramHeader::decode_bytes(&data) else {
        trace!("malformed datagram");
        return;
    };
    let Some(tx) = forwarders
        .get(&hdr.service_id)
        .and_then(|f| f.udp_tx.as_ref())
    else {
        return;
    };
    if tx.try_send((hdr.session_id, payload)).is_err() {
        trace!("UDP queue full, dropping datagram");
    }
}

/// State shared by all forwarders of a player connection.
struct Shared {
    conn: Connection,
    /// Player-local UDP session ids, unique across services.
    next_session: AtomicU32,
    oversize: OversizeCounter,
    udp_timeout: Duration,
    max_udp_sessions: usize,
    max_tcp_connections: usize,
    handshake_timeout: Duration,
}

/// A running local listener for one service.
struct Forwarder {
    local_addr: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    udp_tx: Option<mpsc::Sender<(u32, Bytes)>>,
}

impl Forwarder {
    fn start(shared: &Arc<Shared>, service: &ServiceDef, socket: BoundSocket) -> io::Result<Self> {
        let local_addr = socket.local_addr()?;
        let cancel = CancellationToken::new();
        let (task, udp_tx) = match socket {
            BoundSocket::Tcp(listener) => (
                tokio::spawn(tcp_forwarder(
                    shared.clone(),
                    service.id,
                    listener,
                    cancel.clone(),
                )),
                None,
            ),
            BoundSocket::Udp(socket) => {
                let (tx, rx) = mpsc::channel(UDP_QUEUE);
                (
                    tokio::spawn(udp_forwarder(
                        shared.clone(),
                        service.id,
                        socket,
                        rx,
                        cancel.clone(),
                    )),
                    Some(tx),
                )
            }
        };
        Ok(Self {
            local_addr,
            cancel,
            task,
            udp_tx,
        })
    }

    /// Stops the forwarder and waits until its socket is closed.
    async fn stop(self) {
        self.cancel.cancel();
        let mut task = self.task;
        if timeout(Duration::from_secs(2), &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn tcp_forwarder(
    shared: Arc<Shared>,
    service_id: u8,
    listener: TcpListener,
    cancel: CancellationToken,
) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer)) => {
                    if conns.len() >= shared.max_tcp_connections {
                        warn!(%peer, "too many local connections, rejecting");
                        drop(tcp);
                        continue;
                    }
                    debug!(%peer, service_id, "local TCP connection");
                    conns.spawn(player_tcp_conn(shared.clone(), service_id, tcp));
                }
                Err(e) => {
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    drop(listener);
    conns.abort_all();
    while conns.join_next().await.is_some() {}
}

async fn player_tcp_conn(shared: Arc<Shared>, service_id: u8, tcp: TcpStream) {
    let _ = tcp.set_nodelay(true);
    let hs = shared.handshake_timeout;
    let (mut send, recv) = match timeout(hs, shared.conn.open_bi()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!("cannot open tunnel stream: {e}");
            return;
        }
        Err(_) => {
            warn!("timed out opening a tunnel stream");
            return;
        }
    };
    match timeout(hs, write_frame(&mut send, &StreamHeader { service_id })).await {
        Ok(Ok(())) => {}
        _ => {
            debug!("failed to send stream header");
            return;
        }
    }
    let (up, down) = pipe::tcp_over_quic(tcp, send, recv).await;
    debug!(service_id, to_host = ?up, from_host = ?down, "local TCP connection closed");
}

async fn udp_forwarder(
    shared: Arc<Shared>,
    service_id: u8,
    socket: UdpSocket,
    mut from_tunnel: mpsc::Receiver<(u32, Bytes)>,
    cancel: CancellationToken,
) {
    let mut by_addr: HashMap<SocketAddr, u32> = HashMap::new();
    let mut by_id: HashMap<u32, (SocketAddr, Instant)> = HashMap::new();
    let mut buf = vec![0u8; 65_535];
    let mut sweep = interval(Duration::from_secs(1));
    sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            received = socket.recv_from(&mut buf) => match received {
                Ok((n, src)) => {
                    let id = match by_addr.get(&src) {
                        Some(&id) => id,
                        None => {
                            if by_id.len() >= shared.max_udp_sessions {
                                debug!(%src, "UDP session limit reached, dropping packet");
                                continue;
                            }
                            let id = shared.next_session.fetch_add(1, Ordering::Relaxed);
                            by_addr.insert(src, id);
                            by_id.insert(id, (src, Instant::now()));
                            debug!(%src, session = id, service_id, "new UDP session");
                            id
                        }
                    };
                    if let Some(entry) = by_id.get_mut(&id) {
                        entry.1 = Instant::now();
                    }
                    let data = DatagramHeader::new(service_id, id).encode_with(&buf[..n]);
                    send_datagram_checked(&shared.conn, data, &shared.oversize);
                }
                Err(e) if is_transient_udp_error(&e) => {
                    trace!("transient UDP error: {e}");
                }
                Err(e) => {
                    warn!("local UDP socket error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            Some((id, payload)) = from_tunnel.recv() => {
                if let Some((addr, last)) = by_id.get_mut(&id) {
                    *last = Instant::now();
                    if let Err(e) = socket.send_to(&payload, *addr).await {
                        trace!("failed to send to local game client: {e}");
                    }
                }
            }
            _ = sweep.tick() => {
                let timeout = shared.udp_timeout;
                let before = by_id.len();
                by_id.retain(|_, (addr, last)| {
                    let keep = last.elapsed() < timeout;
                    if !keep {
                        by_addr.remove(addr);
                    }
                    keep
                });
                if by_id.len() != before {
                    debug!(expired = before - by_id.len(), service_id, "expired idle UDP sessions");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_local_skips_busy_ports() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let first = bind_local(ServiceKind::Tcp, ip, 0, 0).await.unwrap();
        let busy = first.local_addr().unwrap().port();
        let second = bind_local(ServiceKind::Tcp, ip, busy, 20).await.unwrap();
        let got = second.local_addr().unwrap().port();
        assert_ne!(got, busy);
        assert!(got > busy && got <= busy.saturating_add(20));

        let u1 = bind_local(ServiceKind::Udp, ip, 0, 0).await.unwrap();
        let ubusy = u1.local_addr().unwrap().port();
        assert!(bind_local(ServiceKind::Udp, ip, ubusy, 0).await.is_err());
        let u2 = bind_local(ServiceKind::Udp, ip, ubusy, 20).await.unwrap();
        assert_ne!(u2.local_addr().unwrap().port(), ubusy);
    }
}
