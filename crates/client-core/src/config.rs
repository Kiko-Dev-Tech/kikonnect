//! Connection settings shared by host and join mode.

use std::time::Duration;

use rustls::pki_types::CertificateDer;

/// Default relay server address.
pub const DEFAULT_SERVER_ADDR: &str = "tunnel.example.com:7000";

/// How to reach and authenticate the relay server.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// `host:port` of the relay server. The port defaults to 7000 if omitted.
    pub server_addr: String,
    /// Accept any server certificate. **Development only**: disables protection
    /// against man-in-the-middle attacks.
    pub insecure: bool,
    /// Additional trusted root certificates (e.g. a self-signed development
    /// certificate), on top of the bundled web PKI roots.
    pub extra_roots: Vec<CertificateDer<'static>>,
    /// Client software version sent in `Hello`.
    pub client_version: String,
    /// Timeout for resolving and connecting to the server.
    pub connect_timeout: Duration,
    /// Timeout for each request/response step on the control stream.
    pub request_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: DEFAULT_SERVER_ADDR.to_owned(),
            insecure: false,
            extra_roots: Vec::new(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(15),
        }
    }
}

impl ClientConfig {
    /// Creates a configuration for `server_addr` with default settings.
    pub fn new(server_addr: impl Into<String>) -> Self {
        Self {
            server_addr: server_addr.into(),
            ..Self::default()
        }
    }
}
