//! Operational features: health check and certificate hot reload.

use std::net::SocketAddr;
use std::time::Duration;

use kikonnect_client_core::{transport, ClientConfig};
use kikonnect_server::{health, reload, tls, Server, ServerConfig};
use kikonnect_tests::{init_tracing, test_server_config, within};
use tokio_util::sync::CancellationToken;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kikonnect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn write_cert(dir: &std::path::Path) -> rustls_pki_types::CertificateDer<'static> {
    let generated = tls::generate_self_signed(&[]).unwrap();
    tls::write_generated(&generated, dir).unwrap();
    generated.cert_der
}

fn start_server(
    dir: &std::path::Path,
    config: ServerConfig,
) -> (Server, SocketAddr, CancellationToken) {
    let (certs, key) = tls::load_pem(&dir.join("fullchain.pem"), &dir.join("privkey.pem")).unwrap();
    let server = Server::bind(config, tls::server_crypto(certs, key).unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    (server, addr, CancellationToken::new())
}

#[tokio::test]
async fn healthcheck_succeeds_against_running_server_and_fails_without() {
    init_tracing();
    let dir = temp_dir("health");
    write_cert(&dir);
    let (server, addr, shutdown) = start_server(&dir, test_server_config());
    let handle = tokio::spawn(server.run(shutdown.clone()));

    within("healthcheck", health::check(addr, Duration::from_secs(5)))
        .await
        .expect("healthy");

    shutdown.cancel();
    within("server stop", handle).await.unwrap().unwrap();
    // The server is gone now: the check must fail (and quickly).
    let result = within("healthcheck", health::check(addr, Duration::from_secs(2))).await;
    assert!(result.is_err(), "check against a stopped server must fail");
    let _ = std::fs::remove_dir_all(&dir);
}

async fn connects_trusting(
    addr: SocketAddr,
    root: rustls_pki_types::CertificateDer<'static>,
) -> bool {
    let mut cfg = ClientConfig::new(addr.to_string());
    cfg.extra_roots = vec![root];
    cfg.connect_timeout = Duration::from_secs(3);
    match transport::connect(&cfg).await {
        Ok(conn) => {
            conn.close(0, b"").await;
            true
        }
        Err(_) => false,
    }
}

#[tokio::test]
async fn certificate_is_reloaded_when_files_change() {
    init_tracing();
    let dir = temp_dir("reload");
    let cert_a = write_cert(&dir);
    let (server, addr, shutdown) = start_server(&dir, test_server_config());
    let updater = server.crypto_updater();
    let handle = tokio::spawn(server.run(shutdown.clone()));
    tokio::spawn(reload::watch(
        updater,
        dir.join("fullchain.pem"),
        dir.join("privkey.pem"),
        Duration::from_millis(100),
        shutdown.clone(),
    ));

    assert!(connects_trusting(addr, cert_a.clone()).await);

    // "Renew" the certificate on disk; the server must pick it up without a restart.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let cert_b = write_cert(&dir);
    assert_ne!(cert_a, cert_b);
    let mut switched = false;
    for _ in 0..50 {
        if connects_trusting(addr, cert_b.clone()).await {
            switched = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        switched,
        "server never started presenting the renewed certificate"
    );
    assert!(
        !connects_trusting(addr, cert_a).await,
        "old certificate must no longer be presented"
    );

    shutdown.cancel();
    within("server stop", handle).await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
