//! Registration / join errors and version negotiation.

use kikonnect_client_core::protocol::{ClientMsg, Role, ServerMsg};
use kikonnect_client_core::transport::{self, ControlStream};
use kikonnect_client_core::{ClientError, ErrorCode, HostConfig, HostSession};
use kikonnect_tests::*;

fn code(r: Result<impl Sized, ClientError>) -> ErrorCode {
    match r {
        Err(ClientError::Server { code, .. }) => code,
        Err(e) => panic!("expected server error, got {e}"),
        Ok(_) => panic!("expected server error, got success"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_password_is_rejected() {
    init_tracing();
    let server = TestServer::start().await;
    let mut cfg = HostConfig::new("secret-host", vec![tcp_service(0, 25565)]);
    cfg.password = Some("open sesame".into());
    let host = start_host(&server, cfg).await;

    assert_eq!(
        code(join(&server, "secret-host", None).await),
        ErrorCode::WrongPassword
    );
    assert_eq!(
        code(join(&server, "secret-host", Some("open sesam")).await),
        ErrorCode::WrongPassword
    );
    let player = join(&server, "secret-host", Some("open sesame"))
        .await
        .unwrap();
    player.stop().await.unwrap();
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_host_is_not_found() {
    init_tracing();
    let server = TestServer::start().await;
    assert_eq!(
        code(join(&server, "nobody-here", None).await),
        ErrorCode::HostNotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_name_is_taken() {
    init_tracing();
    let server = TestServer::start().await;
    let host = start_host(
        &server,
        HostConfig::new("dup-name", vec![tcp_service(0, 1)]),
    )
    .await;
    // Names are case-insensitive.
    let second = HostSession::connect(
        &server.client_config(),
        &HostConfig::new("DUP-NAME", vec![tcp_service(0, 2)]),
        None,
    )
    .await;
    assert_eq!(code(second), ErrorCode::NameTaken);
    // A wrong reconnect secret does not help.
    let third = HostSession::connect(
        &server.client_config(),
        &HostConfig::new("dup-name", vec![tcp_service(0, 2)]),
        Some("not-the-secret"),
    )
    .await;
    assert_eq!(code(third), ErrorCode::NameTaken);
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_names_are_rejected_locally_and_by_the_server() {
    init_tracing();
    let server = TestServer::start().await;
    let local = HostSession::connect(
        &server.client_config(),
        &HostConfig::new("-bad-", vec![tcp_service(0, 1)]),
        None,
    )
    .await;
    assert!(matches!(local, Err(ClientError::InvalidName(_))));

    // Bypass the local check to exercise the server.
    let connected = transport::connect(&server.client_config()).await.unwrap();
    let mut ctrl = ControlStream::open(&connected.connection, Role::Host, &server.client_config())
        .await
        .unwrap();
    ctrl.send(&ClientMsg::Register {
        name: "admin".into(),
        password: None,
        services: vec![tcp_service(0, 1)],
        reconnect_secret: None,
    })
    .await
    .unwrap();
    let reply = ctrl.recv(T, "register reply").await.unwrap();
    assert!(
        matches!(
            reply,
            ServerMsg::Error {
                code: ErrorCode::InvalidName,
                ..
            }
        ),
        "{reply:?}"
    );
    connected.close(0, b"").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_mismatch_is_rejected_cleanly() {
    init_tracing();
    let server = TestServer::start().await;
    let connected = transport::connect(&server.client_config()).await.unwrap();
    let result = ControlStream::open_with_version(
        &connected.connection,
        Role::Player,
        &server.client_config(),
        999,
    )
    .await;
    match result {
        Err(ClientError::Server {
            code: ErrorCode::VersionMismatch,
            message,
        }) => {
            assert!(message.contains("v999"), "{message}");
            assert!(message.contains("v1"), "{message}");
        }
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
    connected.close(0, b"").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_and_register_are_rate_limited() {
    init_tracing();
    let server = TestServer::start_with(|c| {
        c.rate_limit_burst = 3;
        c.rate_limit_per_minute = 1;
    })
    .await;
    for _ in 0..3 {
        assert_eq!(
            code(join(&server, "nobody-here", None).await),
            ErrorCode::HostNotFound
        );
    }
    assert_eq!(
        code(join(&server, "nobody-here", None).await),
        ErrorCode::RateLimited
    );
    let host = HostSession::connect(
        &server.client_config(),
        &HostConfig::new("limited", vec![tcp_service(0, 1)]),
        None,
    )
    .await;
    assert_eq!(code(host), ErrorCode::RateLimited);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn player_and_tunnel_limits() {
    init_tracing();
    let server = TestServer::start_with(|c| {
        c.max_players_per_tunnel = 1;
        c.max_tunnels = 1;
    })
    .await;
    let host = start_host(
        &server,
        HostConfig::new("small-host", vec![tcp_service(0, 1)]),
    )
    .await;
    let p1 = join(&server, "small-host", None).await.unwrap();
    assert_eq!(
        code(join(&server, "small-host", None).await),
        ErrorCode::TunnelFull
    );

    let second_host = HostSession::connect(
        &server.client_config(),
        &HostConfig::new("other-host", vec![tcp_service(0, 1)]),
        None,
    )
    .await;
    assert_eq!(code(second_host), ErrorCode::ServerFull);

    // Leaving frees the slot.
    p1.stop().await.unwrap();
    let p2 = within("rejoin", async {
        loop {
            match join(&server, "small-host", None).await {
                Ok(p) => return p,
                Err(ClientError::Server {
                    code: ErrorCode::TunnelFull,
                    ..
                }) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await;
    p2.stop().await.unwrap();
    host.stop().await.unwrap();
}
