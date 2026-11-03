//! Host departure, grace period, reconnects and server shutdown.

use std::time::Duration;

use kikonnect_client_core::{
    ClientError, ErrorCode, HostConfig, HostEvent, HostSession, HostStatus, PlayerEvent,
    PlayerExit, ReconnectPolicy,
};
use kikonnect_tests::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_leaving_notifies_players_and_closes_listeners() {
    init_tracing();
    let server = TestServer::start().await;
    let tcp_echo = tcp_echo_server().await;
    let udp_echo = udp_echo_server().await;
    let host = start_host(
        &server,
        HostConfig::new(
            "leaving-host",
            vec![
                tcp_service(0, tcp_echo.port()),
                udp_service(1, udp_echo.port()),
            ],
        ),
    )
    .await;
    let player = join(&server, "leaving-host", None).await.unwrap();
    let tcp_addr = player.addrs[&0];
    let udp_addr = player.addrs[&1];

    let mut s = TcpStream::connect(tcp_addr).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    within("echo", s.read_exact(&mut buf)).await.unwrap();

    host.stop().await.unwrap();

    let (result, mut events) = player.finished().await;
    assert!(matches!(result, Ok(PlayerExit::HostGone)), "{result:?}");
    let mut saw_host_gone = false;
    while let Ok(ev) = events.try_recv() {
        saw_host_gone |= ev == PlayerEvent::HostGone;
    }
    assert!(saw_host_gone, "PlayerEvent::HostGone was not emitted");

    // Local listeners are closed: their ports can be bound again.
    TcpListener::bind(tcp_addr).await.unwrap();
    UdpSocket::bind(udp_addr).await.unwrap();
    // The in-flight connection was closed too.
    let r = within("closed connection", s.read(&mut buf)).await;
    assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_within_grace_period_reclaims_name() {
    init_tracing();
    let server = TestServer::start().await;
    let client = server.client_config();
    let cfg = HostConfig::new("grace-host", vec![tcp_service(0, 1)]);

    let first = HostSession::connect(&client, &cfg, None).await.unwrap();
    let secret = first.reconnect_secret().to_owned();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (tx, _rx) = mpsc::channel(16);
    first.run(&tx, &cancel).await.unwrap(); // closes the connection

    // The name is reserved for the previous host.
    let other = HostSession::connect(&client, &cfg, None).await;
    assert!(matches!(
        other,
        Err(ClientError::Server {
            code: ErrorCode::NameTaken,
            ..
        })
    ));
    let wrong = HostSession::connect(&client, &cfg, Some("guess")).await;
    assert!(matches!(
        wrong,
        Err(ClientError::Server {
            code: ErrorCode::NameTaken,
            ..
        })
    ));

    // With the secret it can be reclaimed.
    let again = HostSession::connect(&client, &cfg, Some(&secret))
        .await
        .unwrap();
    assert_eq!(again.name(), "grace-host");
    assert_ne!(again.reconnect_secret(), secret, "a fresh secret is issued");
    // And it is joinable.
    let (tx, _rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let running = tokio::spawn({
        let cancel = cancel.clone();
        async move { again.run(&tx, &cancel).await }
    });
    let player = join(&server, "grace-host", None).await.unwrap();
    player.stop().await.unwrap();
    cancel.cancel();
    within("host stop", running).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn name_is_released_after_grace_period() {
    init_tracing();
    let server = TestServer::start_with(|c| c.name_grace_period = Duration::from_millis(300)).await;
    let cfg = HostConfig::new("short-grace", vec![tcp_service(0, 1)]);
    let host = start_host(&server, cfg.clone()).await;
    host.stop().await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    let other = HostSession::connect(&server.client_config(), &cfg, None)
        .await
        .unwrap();
    assert_eq!(other.name(), "short-grace");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_with_secret_replaces_a_stale_connection() {
    init_tracing();
    let server = TestServer::start().await;
    let client = server.client_config();
    let cfg = HostConfig::new("takeover", vec![tcp_service(0, 1)]);

    let old = HostSession::connect(&client, &cfg, None).await.unwrap();
    let secret = old.reconnect_secret().to_owned();
    let (tx, _rx) = mpsc::channel(16);
    let old_task = tokio::spawn(async move { old.run(&tx, &CancellationToken::new()).await });
    let player = join(&server, "takeover", None).await.unwrap();

    // Same host reconnects (e.g. after a network change) while the server still
    // considers the old connection alive.
    let new = HostSession::connect(&client, &cfg, Some(&secret))
        .await
        .unwrap();
    let old_result = within("old host", old_task).await.unwrap();
    assert!(
        matches!(
            old_result,
            Err(ClientError::Server {
                code: ErrorCode::Replaced,
                ..
            })
        ),
        "{old_result:?}"
    );
    assert!(!old_result.as_ref().unwrap_err().is_retryable());
    // Players of the old connection are told the host is gone.
    let (r, _) = player.finished().await;
    assert!(matches!(r, Ok(PlayerExit::HostGone)), "{r:?}");
    drop(new);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_shutdown_notifies_clients_and_host_reconnects() {
    init_tracing();
    let mut server = TestServer::start().await;
    let echo = tcp_echo_server().await;
    let mut cfg = HostConfig::new("phoenix", vec![tcp_service(0, echo.port())]);
    cfg.reconnect = ReconnectPolicy {
        enabled: true,
        initial_delay: Duration::from_millis(200),
        max_delay: Duration::from_secs(1),
    };
    let mut host = start_host(&server, cfg).await;
    let player = join(&server, "phoenix", None).await.unwrap();

    server.restart().await;

    let (r, _) = player.finished().await;
    assert!(matches!(r, Err(ClientError::ServerShutdown)), "{r:?}");
    host.wait_for(|e| matches!(e, HostEvent::Status(HostStatus::Reconnecting { .. })))
        .await;
    let name = host.wait_online().await;
    assert_eq!(name, "phoenix");

    let player = join(&server, "phoenix", None).await.unwrap();
    let mut s = TcpStream::connect(player.addrs[&0]).await.unwrap();
    s.write_all(b"back").await.unwrap();
    let mut buf = [0u8; 4];
    within("echo after reconnect", s.read_exact(&mut buf))
        .await
        .unwrap();
    assert_eq!(&buf, b"back");
    player.stop().await.unwrap();
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_fails_permanently_on_non_retryable_errors() {
    init_tracing();
    let server = TestServer::start().await;
    let first = start_host(
        &server,
        HostConfig::new("only-one", vec![tcp_service(0, 1)]),
    )
    .await;
    let (tx, mut rx) = mpsc::channel(64);
    let result = within(
        "second host",
        kikonnect_client_core::run_host(
            server.client_config(),
            HostConfig::new("only-one", vec![tcp_service(0, 1)]),
            tx,
            CancellationToken::new(),
        ),
    )
    .await;
    assert!(matches!(
        result,
        Err(ClientError::Server {
            code: ErrorCode::NameTaken,
            ..
        })
    ));
    let mut failed = false;
    while let Ok(ev) = rx.try_recv() {
        failed |= matches!(ev, HostEvent::Status(HostStatus::Failed(_)));
    }
    assert!(failed);
    first.stop().await.unwrap();
}
