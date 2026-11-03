//! Test harness for the end-to-end tests: an in-process relay server with a
//! self-signed certificate, local echo servers, and helpers to run hosts and
//! players via `kikonnect-client-core`.

// Test support code: panicking on unexpected failures is the desired behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use kikonnect_client_core::{
    run_host, ClientConfig, ClientError, HostConfig, HostEvent, HostStatus, JoinConfig,
    PlayerCommand, PlayerEvent, PlayerExit, PlayerSession, ServiceDef, ServiceKind,
};
use kikonnect_server::tls::{generate_self_signed, server_crypto};
use kikonnect_server::{Server, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Default timeout for any awaited step in tests.
pub const T: Duration = Duration::from_secs(30);

/// Awaits `fut` with the default test timeout.
pub async fn within<F: Future>(what: &str, fut: F) -> F::Output {
    tokio::time::timeout(T, fut)
        .await
        .unwrap_or_else(|_| panic!("timed out: {what}"))
}

/// Installs a test log subscriber (filter via `KIKONNECT_LOG`, default `warn`).
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("KIKONNECT_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

/// Server configuration used by tests (rate limiting disabled).
pub fn test_server_config() -> ServerConfig {
    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        rate_limit_per_minute: 0,
        handshake_timeout: Duration::from_secs(5),
        ..ServerConfig::default()
    }
}

/// An in-process relay server.
pub struct TestServer {
    /// Listening address.
    pub addr: SocketAddr,
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    config: ServerConfig,
    shutdown: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Starts a server with [`test_server_config`].
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Starts a server with a modified configuration.
    pub async fn start_with(f: impl FnOnce(&mut ServerConfig)) -> Self {
        let generated = generate_self_signed(&[]).unwrap();
        let mut config = test_server_config();
        f(&mut config);
        Self::spawn(config, generated.cert_der, generated.key_der).await
    }

    async fn spawn(
        config: ServerConfig,
        cert: CertificateDer<'static>,
        key: PrivatePkcs8KeyDer<'static>,
    ) -> Self {
        let mut attempts = 0;
        let server = loop {
            let crypto =
                server_crypto(vec![cert.clone()], PrivateKeyDer::from(key.clone_key())).unwrap();
            match Server::bind(config.clone(), crypto) {
                Ok(s) => break s,
                // The previous socket on a fixed port may take a moment to go away.
                Err(e) if attempts < 50 => {
                    attempts += 1;
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("cannot bind server: {e}"),
            }
        };
        let addr = server.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                server.run(shutdown).await.unwrap();
            }
        });
        Self {
            addr,
            cert,
            key,
            config,
            shutdown,
            handle: Some(handle),
        }
    }

    /// Client configuration trusting this server's certificate.
    pub fn client_config(&self) -> ClientConfig {
        ClientConfig {
            server_addr: self.addr.to_string(),
            extra_roots: vec![self.cert.clone()],
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            ..ClientConfig::default()
        }
    }

    /// Gracefully shuts the server down and waits for it.
    pub async fn stop(&mut self) {
        self.shutdown.cancel();
        if let Some(h) = self.handle.take() {
            within("server shutdown", h).await.unwrap();
        }
    }

    /// Stops the server and starts a fresh one (empty state, same certificate) on
    /// the same address.
    pub async fn restart(&mut self) {
        self.stop().await;
        let mut config = self.config.clone();
        config.listen = self.addr;
        *self = Self::spawn(config, self.cert.clone(), self.key.clone_key()).await;
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// A TCP echo server on 127.0.0.1 that echoes until EOF, then half-closes.
pub async fn tcp_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

/// A UDP echo server on 127.0.0.1.
pub async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let _ = socket.send_to(&buf[..n], from).await;
                }
                // Windows reports ICMP "port unreachable" as ConnectionReset.
                Err(_) => continue,
            }
        }
    });
    addr
}

/// A TCP service definition.
pub fn tcp_service(id: u8, port: u16) -> ServiceDef {
    ServiceDef {
        id,
        kind: ServiceKind::Tcp,
        label: format!("tcp-{id}"),
        port,
    }
}

/// A UDP service definition.
pub fn udp_service(id: u8, port: u16) -> ServiceDef {
    ServiceDef {
        id,
        kind: ServiceKind::Udp,
        label: format!("udp-{id}"),
        port,
    }
}

/// A host running [`run_host`] in the background.
pub struct RunningHost {
    /// Host events.
    pub events: mpsc::Receiver<HostEvent>,
    /// Stops the host.
    pub cancel: CancellationToken,
    /// The `run_host` task.
    pub handle: JoinHandle<Result<(), ClientError>>,
}

impl RunningHost {
    /// Waits for the first event matching `pred`.
    pub async fn wait_for(&mut self, mut pred: impl FnMut(&HostEvent) -> bool) -> HostEvent {
        within("host event", async {
            loop {
                let ev = self.events.recv().await.expect("host event channel closed");
                if pred(&ev) {
                    return ev;
                }
            }
        })
        .await
    }

    /// Waits until the host is online and returns its name.
    pub async fn wait_online(&mut self) -> String {
        match self
            .wait_for(|e| {
                matches!(
                    e,
                    HostEvent::Status(HostStatus::Online { .. } | HostStatus::Failed(_))
                )
            })
            .await
        {
            HostEvent::Status(HostStatus::Online { name }) => name,
            other => panic!("host failed: {other:?}"),
        }
    }

    /// Stops the host and returns the result of `run_host`.
    pub async fn stop(self) -> Result<(), ClientError> {
        self.cancel.cancel();
        within("host stop", self.handle).await.unwrap()
    }
}

/// Starts a host with automatic reconnects and waits until it is online.
pub async fn start_host(server: &TestServer, config: HostConfig) -> RunningHost {
    let (tx, rx) = mpsc::channel(1024);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(run_host(server.client_config(), config, tx, cancel.clone()));
    let mut host = RunningHost {
        events: rx,
        cancel,
        handle,
    };
    host.wait_online().await;
    host
}

/// A joined player running in the background.
pub struct RunningPlayer {
    /// Local address per service id.
    pub addrs: HashMap<u8, SocketAddr>,
    /// The host's services.
    pub services: Vec<ServiceDef>,
    /// Player events.
    pub events: mpsc::Receiver<PlayerEvent>,
    /// Commands to the session.
    pub commands: mpsc::Sender<PlayerCommand>,
    /// Stops the session.
    pub cancel: CancellationToken,
    /// The `run` task.
    pub handle: JoinHandle<Result<PlayerExit, ClientError>>,
}

impl RunningPlayer {
    /// Waits for the first event matching `pred`.
    pub async fn wait_for(&mut self, mut pred: impl FnMut(&PlayerEvent) -> bool) -> PlayerEvent {
        within("player event", async {
            loop {
                let ev = self
                    .events
                    .recv()
                    .await
                    .expect("player event channel closed");
                if pred(&ev) {
                    return ev;
                }
            }
        })
        .await
    }

    /// Waits for the session to end.
    pub async fn finished(self) -> (Result<PlayerExit, ClientError>, mpsc::Receiver<PlayerEvent>) {
        let r = within("player end", self.handle).await.unwrap();
        (r, self.events)
    }

    /// Stops the session.
    pub async fn stop(self) -> Result<PlayerExit, ClientError> {
        self.cancel.cancel();
        within("player stop", self.handle).await.unwrap()
    }
}

/// Joins `name`, binding every service on an ephemeral local port.
pub async fn join(
    server: &TestServer,
    name: &str,
    password: Option<&str>,
) -> Result<RunningPlayer, ClientError> {
    let mut config = JoinConfig::new(name);
    config.password = password.map(str::to_owned);
    let mut session = PlayerSession::connect(&server.client_config(), &config).await?;
    let services = session.services().to_vec();
    let ports: HashMap<u8, u16> = services.iter().map(|s| (s.id, 0)).collect();
    let mut addrs = HashMap::new();
    for (id, result) in session.bind_all(&ports).await {
        addrs.insert(id, result.unwrap());
    }
    let (tx, rx) = mpsc::channel(1024);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(session.run(tx, Some(cmd_rx), cancel.clone()));
    Ok(RunningPlayer {
        addrs,
        services,
        events: rx,
        commands: cmd_tx,
        cancel,
        handle,
    })
}
