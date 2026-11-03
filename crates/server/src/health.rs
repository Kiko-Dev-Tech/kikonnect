//! Health check: a local QUIC handshake plus `Hello` exchange against a running
//! server. Used by the Docker `HEALTHCHECK` (`kikonnect-server healthcheck`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kikonnect_protocol::{
    read_frame, write_frame, ClientMsg, Role, ServerMsg, ALPN, PROTOCOL_VERSION,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::time::timeout;

/// Why a health check failed.
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    /// Local setup failed (TLS config, socket).
    #[error("setup failed: {0}")]
    Setup(String),
    /// The server did not answer within the timeout.
    #[error("timed out while {0}")]
    Timeout(&'static str),
    /// The server answered unexpectedly or the connection failed.
    #[error("{0}")]
    Failed(String),
}

/// The certificate is not checked: the check only runs against the local server
/// (usually `127.0.0.1`, which a public certificate does not cover) and
/// transmits nothing sensitive.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
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
            &self.0.signature_verification_algorithms,
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
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Result<ClientConfig, HealthError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| HealthError::Setup(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(crypto).map_err(|e| HealthError::Setup(e.to_string()))?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

/// Connects to `addr`, performs the `Hello` exchange and disconnects. `Ok(())`
/// means the server is up and speaks a compatible protocol.
pub async fn check(addr: SocketAddr, limit: Duration) -> Result<(), HealthError> {
    let bind: SocketAddr = if addr.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = Endpoint::client(bind).map_err(|e| HealthError::Setup(e.to_string()))?;
    endpoint.set_default_client_config(client_config()?);

    let connecting = endpoint
        .connect(addr, "localhost")
        .map_err(|e| HealthError::Failed(e.to_string()))?;
    let conn = timeout(limit, connecting)
        .await
        .map_err(|_| HealthError::Timeout("connecting"))?
        .map_err(|e| HealthError::Failed(format!("handshake failed: {e}")))?;

    let exchange = async {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| HealthError::Failed(e.to_string()))?;
        write_frame(
            &mut send,
            &ClientMsg::Hello {
                protocol_version: PROTOCOL_VERSION,
                role: Role::Player,
                client_version: format!("healthcheck/{}", env!("CARGO_PKG_VERSION")),
            },
        )
        .await
        .map_err(|e| HealthError::Failed(e.to_string()))?;
        match read_frame::<_, ServerMsg>(&mut recv).await {
            Ok(Some(ServerMsg::HelloOk { .. })) => Ok(()),
            Ok(Some(other)) => Err(HealthError::Failed(format!(
                "unexpected reply to Hello: {other:?}"
            ))),
            Ok(None) => Err(HealthError::Failed("server closed the stream".into())),
            Err(e) => Err(HealthError::Failed(e.to_string())),
        }
    };
    let result = timeout(limit, exchange)
        .await
        .map_err(|_| HealthError::Timeout("waiting for HelloOk"))
        .and_then(|r| r);
    conn.close(0u32.into(), b"healthcheck");
    let _ = timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    result
}
