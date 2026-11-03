//! QUIC connection setup and the client side of the control stream.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use kikonnect_protocol::{
    close_code, read_frame, write_frame, ClientMsg, ErrorCode, FrameError, Role, ServerMsg, ALPN,
    DEFAULT_SERVER_PORT, IDLE_TIMEOUT, KEEP_ALIVE_INTERVAL, PROTOCOL_VERSION,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connection, ConnectionError, Endpoint, IdleTimeout, RecvStream, SendStream, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::debug;

use crate::config::ClientConfig;
use crate::error::ClientError;

/// Maximum number of concurrent incoming streams (TCP connections towards a host).
const MAX_INCOMING_STREAMS: u32 = 1024;

/// An established QUIC connection together with its endpoint.
///
/// The endpoint must be kept alive as long as the connection is used.
#[derive(Debug)]
pub struct Connected {
    /// The local QUIC endpoint.
    pub endpoint: Endpoint,
    /// The connection to the relay server.
    pub connection: Connection,
}

impl Connected {
    /// Closes the connection and waits (briefly) until the close was sent.
    pub async fn close(self, code: u32, reason: &[u8]) {
        close_and_drain(&self.endpoint, &self.connection, code, reason).await;
    }
}

pub(crate) async fn close_and_drain(
    endpoint: &Endpoint,
    conn: &Connection,
    code: u32,
    reason: &[u8],
) {
    conn.close(VarInt::from_u32(code), reason);
    let _ = timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

/// Splits `host[:port]` (IPv6 literals in brackets) into host and port. The port
/// defaults to [`DEFAULT_SERVER_PORT`].
pub fn split_host_port(addr: &str) -> Result<(String, u16), ClientError> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(ClientError::InvalidAddress(addr.to_owned()));
    }
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok((sa.ip().to_string(), sa.port()));
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Ok((ip.to_string(), DEFAULT_SERVER_PORT));
    }
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| ClientError::InvalidAddress(addr.to_owned()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| ClientError::InvalidAddress(addr.to_owned()))?,
            None if tail.is_empty() => DEFAULT_SERVER_PORT,
            None => return Err(ClientError::InvalidAddress(addr.to_owned())),
        };
        return Ok((host.to_owned(), port));
    }
    match addr.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| ClientError::InvalidAddress(addr.to_owned()))?;
            if host.is_empty() || host.contains(':') {
                return Err(ClientError::InvalidAddress(addr.to_owned()));
            }
            Ok((host.to_owned(), port))
        }
        None => Ok((addr.to_owned(), DEFAULT_SERVER_PORT)),
    }
}

fn transport_config() -> Result<quinn::TransportConfig, ClientError> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(
        IdleTimeout::try_from(IDLE_TIMEOUT)
            .map_err(|e| ClientError::InvalidConfig(e.to_string()))?,
    ));
    t.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    t.max_concurrent_bidi_streams(VarInt::from_u32(MAX_INCOMING_STREAMS));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.datagram_receive_buffer_size(Some(1 << 20));
    t.datagram_send_buffer_size(1 << 20);
    Ok(t)
}

fn quic_client_config(cfg: &ClientConfig) -> Result<quinn::ClientConfig, ClientError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ClientError::Tls(e.to_string()))?;
    let mut tls = if cfg.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier { provider }))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for cert in &cfg.extra_roots {
            roots
                .add(cert.clone())
                .map_err(|e| ClientError::Tls(format!("invalid extra root certificate: {e}")))?;
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(tls).map_err(|e| ClientError::Tls(e.to_string()))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic));
    client.transport_config(Arc::new(transport_config()?));
    Ok(client)
}

/// Resolves the server address and establishes a QUIC connection.
pub async fn connect(cfg: &ClientConfig) -> Result<Connected, ClientError> {
    let (host, port) = split_host_port(&cfg.server_addr)?;
    let addrs: Vec<SocketAddr> = timeout(
        cfg.connect_timeout,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| ClientError::Timeout("resolving the server address"))?
    .map_err(|_| ClientError::Resolve(cfg.server_addr.clone()))?
    .collect();
    if addrs.is_empty() {
        return Err(ClientError::Resolve(cfg.server_addr.clone()));
    }
    let client_config = quic_client_config(cfg)?;
    let mut last_err = ClientError::Resolve(cfg.server_addr.clone());
    for addr in addrs {
        let bind: SocketAddr = if addr.is_ipv6() {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let mut endpoint = Endpoint::client(bind)?;
        endpoint.set_default_client_config(client_config.clone());
        let connecting = match endpoint.connect(addr, &host) {
            Ok(c) => c,
            Err(e) => {
                last_err = ClientError::Connect(e.to_string());
                continue;
            }
        };
        match timeout(cfg.connect_timeout, connecting).await {
            Ok(Ok(connection)) => {
                debug!(%addr, "connected to relay server");
                return Ok(Connected {
                    endpoint,
                    connection,
                });
            }
            Ok(Err(e)) => last_err = ClientError::Connect(e.to_string()),
            Err(_) => last_err = ClientError::Timeout("connecting to the server"),
        }
    }
    Err(last_err)
}

/// Maps the close reason of a connection to an error.
pub(crate) fn close_error(conn: &Connection) -> ClientError {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(ac)) => {
            let reason = String::from_utf8_lossy(&ac.reason).into_owned();
            match u32::try_from(ac.error_code.into_inner()) {
                Ok(close_code::SERVER_SHUTDOWN) => ClientError::ServerShutdown,
                Ok(close_code::HOST_GONE) => ClientError::HostGone,
                Ok(close_code::REPLACED) => ClientError::Server {
                    code: ErrorCode::Replaced,
                    message: "this tunnel was taken over by a newer connection".into(),
                },
                _ => ClientError::ConnectionLost(format!("closed by server: {reason}")),
            }
        }
        Some(e) => ClientError::ConnectionLost(e.to_string()),
        None => ClientError::ConnectionLost("control stream closed".into()),
    }
}

fn frame_error(conn: &Connection, e: FrameError) -> ClientError {
    match e {
        FrameError::Io(_) | FrameError::UnexpectedEof => close_error(conn),
        other => ClientError::Protocol(other.to_string()),
    }
}

/// The client side of the control stream during the handshake phase.
#[derive(Debug)]
pub struct ControlStream {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl ControlStream {
    /// Opens the control stream and performs the `Hello` exchange.
    pub async fn open(
        conn: &Connection,
        role: Role,
        cfg: &ClientConfig,
    ) -> Result<Self, ClientError> {
        Self::open_with_version(conn, role, cfg, PROTOCOL_VERSION).await
    }

    /// Like [`open`](Self::open) with an explicit protocol version (for testing
    /// version negotiation).
    pub async fn open_with_version(
        conn: &Connection,
        role: Role,
        cfg: &ClientConfig,
        protocol_version: u16,
    ) -> Result<Self, ClientError> {
        let (send, recv) = timeout(cfg.request_timeout, conn.open_bi())
            .await
            .map_err(|_| ClientError::Timeout("opening the control stream"))?
            .map_err(|_| close_error(conn))?;
        let mut ctrl = Self {
            conn: conn.clone(),
            send,
            recv,
        };
        ctrl.send(&ClientMsg::Hello {
            protocol_version,
            role,
            client_version: cfg.client_version.clone(),
        })
        .await?;
        match ctrl
            .recv(cfg.request_timeout, "waiting for the server hello")
            .await?
        {
            ServerMsg::HelloOk { server_version } => {
                debug!(%server_version, "server hello");
                Ok(ctrl)
            }
            ServerMsg::Error { code, message } => Err(ClientError::Server { code, message }),
            other => Err(ClientError::Protocol(format!(
                "unexpected reply to Hello: {other:?}"
            ))),
        }
    }

    /// Sends one message.
    pub async fn send(&mut self, msg: &ClientMsg) -> Result<(), ClientError> {
        write_frame(&mut self.send, msg)
            .await
            .map_err(|e| frame_error(&self.conn, e))
    }

    /// Receives one message with a timeout. `what` describes the step for errors.
    pub async fn recv(
        &mut self,
        t: Duration,
        what: &'static str,
    ) -> Result<ServerMsg, ClientError> {
        match timeout(t, read_frame::<_, ServerMsg>(&mut self.recv)).await {
            Err(_) => Err(ClientError::Timeout(what)),
            Ok(Ok(Some(msg))) => Ok(msg),
            Ok(Ok(None)) => Err(close_error(&self.conn)),
            Ok(Err(e)) => Err(frame_error(&self.conn, e)),
        }
    }

    /// Splits into the send half and a reader task delivering incoming messages.
    pub(crate) fn into_running(self) -> (SendStream, mpsc::Receiver<Result<ServerMsg, String>>) {
        let (tx, rx) = mpsc::channel(32);
        let mut recv = self.recv;
        tokio::spawn(async move {
            loop {
                match read_frame::<_, ServerMsg>(&mut recv).await {
                    Ok(Some(msg)) => {
                        if tx.send(Ok(msg)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(FrameError::Io(_)) | Err(FrameError::UnexpectedEof) => break,
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string())).await;
                        break;
                    }
                }
            }
        });
        (self.send, rx)
    }
}

/// Certificate verifier that accepts any certificate (still checks handshake
/// signatures). Development only.
#[derive(Debug)]
struct InsecureVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_parsing() {
        let ok = |s: &str| split_host_port(s).unwrap();
        assert_eq!(ok("example.com:7001"), ("example.com".into(), 7001));
        assert_eq!(ok("example.com"), ("example.com".into(), 7000));
        assert_eq!(ok(" 127.0.0.1:9 "), ("127.0.0.1".into(), 9));
        assert_eq!(ok("127.0.0.1"), ("127.0.0.1".into(), 7000));
        assert_eq!(ok("[::1]:7002"), ("::1".into(), 7002));
        assert_eq!(ok("::1"), ("::1".into(), 7000));
        assert_eq!(ok("[::1]"), ("::1".into(), 7000));
        assert!(split_host_port("").is_err());
        assert!(split_host_port("example.com:abc").is_err());
        assert!(split_host_port(":7000").is_err());
        assert!(split_host_port("[::1]x").is_err());
    }
}
