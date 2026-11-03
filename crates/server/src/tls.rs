//! TLS helpers: loading PEM certificates, building the QUIC server crypto config
//! and generating self-signed development certificates.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kikonnect_protocol::ALPN;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// TLS related errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Reading a PEM file failed.
    #[error("failed to read {}", path.display())]
    Pem {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: rustls::pki_types::pem::Error,
    },
    /// The certificate file contained no certificates.
    #[error("no certificates found in {0}")]
    NoCertificates(PathBuf),
    /// rustls rejected the configuration (e.g. key does not match certificate).
    #[error("invalid TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    /// The configuration is not usable for QUIC.
    #[error("TLS configuration not usable for QUIC: {0}")]
    Quic(String),
    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    Generate(#[from] rcgen::Error),
    /// Writing generated files failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Loads a certificate chain and private key from PEM files.
pub fn load_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .map_err(|source| TlsError::Pem {
            path: cert_path.to_owned(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(cert_path.to_owned()));
    }
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|source| TlsError::Pem {
        path: key_path.to_owned(),
        source,
    })?;
    Ok((certs, key))
}

/// Builds the QUIC server crypto configuration (TLS 1.3, ALPN `kikonnect/1`).
pub fn server_crypto(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<QuicServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    QuicServerConfig::try_from(cfg).map_err(|e| TlsError::Quic(e.to_string()))
}

/// A freshly generated self-signed certificate.
pub struct GeneratedCert {
    /// Certificate in PEM format.
    pub cert_pem: String,
    /// PKCS#8 private key in PEM format.
    pub key_pem: String,
    /// Certificate in DER format.
    pub cert_der: CertificateDer<'static>,
    /// Private key in DER format.
    pub key_der: PrivatePkcs8KeyDer<'static>,
}

impl std::fmt::Debug for GeneratedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedCert").finish_non_exhaustive()
    }
}

/// Generates a self-signed certificate for the given host names / IP addresses.
/// `localhost`, `127.0.0.1` and `::1` are always included.
pub fn generate_self_signed(hostnames: &[String]) -> Result<GeneratedCert, TlsError> {
    let mut names: Vec<String> = hostnames.to_vec();
    for default in ["localhost", "127.0.0.1", "::1"] {
        if !names.iter().any(|n| n == default) {
            names.push(default.to_owned());
        }
    }
    let certified = rcgen::generate_simple_self_signed(names)?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    Ok(GeneratedCert {
        cert_pem: certified.cert.pem(),
        key_pem: certified.signing_key.serialize_pem(),
        cert_der,
        key_der,
    })
}

/// Writes a generated certificate as `fullchain.pem` and `privkey.pem` into `dir`
/// (created if missing). Returns the two paths.
pub fn write_generated(cert: &GeneratedCert, dir: &Path) -> Result<(PathBuf, PathBuf), TlsError> {
    fs::create_dir_all(dir)?;
    let cert_path = dir.join("fullchain.pem");
    let key_path = dir.join("privkey.pem");
    fs::write(&cert_path, &cert.cert_pem)?;
    fs::write(&key_path, &cert.key_pem)?;
    Ok((cert_path, key_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_write_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("kikonnect-tls-test-{}", std::process::id()));
        let generated = generate_self_signed(&["example.test".into()]).unwrap();
        let (c, k) = write_generated(&generated, &dir).unwrap();
        let (certs, key) = load_pem(&c, &k).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], generated.cert_der);
        server_crypto(certs, key).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
