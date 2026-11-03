//! TCP forwarding end to end.

use kikonnect_client_core::{HostConfig, HostEvent, PlayerCommand, PlayerEvent};
use kikonnect_tests::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_round_trip_and_half_close() {
    init_tracing();
    let server = TestServer::start().await;
    let echo = tcp_echo_server().await;
    let mut host = start_host(
        &server,
        HostConfig::new("echo-host", vec![tcp_service(0, echo.port())]),
    )
    .await;
    let player = join(&server, "Echo-Host", None).await.unwrap();
    assert_eq!(player.services.len(), 1);

    let ev = host
        .wait_for(|e| matches!(e, HostEvent::PlayerConnected { .. }))
        .await;
    let HostEvent::PlayerConnected { addr, .. } = ev else {
        unreachable!()
    };
    assert!(addr.ip().is_loopback());

    let mut s = within("connect", TcpStream::connect(player.addrs[&0]))
        .await
        .unwrap();
    s.write_all(b"hello kikonnect").await.unwrap();
    let mut buf = [0u8; 15];
    within("echo", s.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"hello kikonnect");

    // Half-close: after we shut down our write side, the echo server sees EOF,
    // finishes, and we read EOF – while data in flight still arrives.
    s.write_all(b"last words").await.unwrap();
    s.shutdown().await.unwrap();
    let mut rest = Vec::new();
    within("read to end", s.read_to_end(&mut rest))
        .await
        .unwrap();
    assert_eq!(rest, b"last words");

    player.stop().await.unwrap();
    host.wait_for(|e| matches!(e, HostEvent::PlayerDisconnected { .. }))
        .await;
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_many_concurrent_connections() {
    init_tracing();
    let server = TestServer::start().await;
    let echo = tcp_echo_server().await;
    let host = start_host(
        &server,
        HostConfig::new("busy-host", vec![tcp_service(3, echo.port())]),
    )
    .await;
    let player = join(&server, "busy-host", None).await.unwrap();
    let local = player.addrs[&3];

    let mut tasks = Vec::new();
    for i in 0..32u32 {
        tasks.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(local).await.unwrap();
            for round in 0..5u32 {
                let msg = format!("conn {i} round {round} {}", "x".repeat(i as usize * 10));
                s.write_all(msg.as_bytes()).await.unwrap();
                let mut buf = vec![0u8; msg.len()];
                s.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, msg.as_bytes());
            }
        }));
    }
    for t in tasks {
        within("concurrent connection", t).await.unwrap();
    }
    player.stop().await.unwrap();
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_large_transfer_arrives_intact() {
    init_tracing();
    const SIZE: usize = 16 * 1024 * 1024;
    let server = TestServer::start().await;
    let echo = tcp_echo_server().await;
    let host = start_host(
        &server,
        HostConfig::new("bulk-host", vec![tcp_service(0, echo.port())]),
    )
    .await;
    let player = join(&server, "bulk-host", None).await.unwrap();

    let data: Vec<u8> = (0..SIZE)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 11)) as u8)
        .collect();
    let s = TcpStream::connect(player.addrs[&0]).await.unwrap();
    let (mut r, mut w) = s.into_split();
    let to_send = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&to_send).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut received = Vec::with_capacity(SIZE);
    within("large transfer", r.read_to_end(&mut received))
        .await
        .unwrap();
    writer.await.unwrap();
    assert_eq!(received.len(), SIZE);
    assert!(received == data, "transferred data differs");

    player.stop().await.unwrap();
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_unreachable_game_server_closes_local_connection() {
    init_tracing();
    let server = TestServer::start().await;
    // A port nobody listens on.
    let closed_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let host = start_host(
        &server,
        HostConfig::new("dead-host", vec![tcp_service(0, closed_port)]),
    )
    .await;
    let player = join(&server, "dead-host", None).await.unwrap();
    let mut s = TcpStream::connect(player.addrs[&0]).await.unwrap();
    let _ = s.write_all(b"anyone?").await;
    let mut buf = [0u8; 16];
    // Either EOF or a reset: the important part is that it does not hang.
    let r = within("closed connection", s.read(&mut buf)).await;
    assert!(matches!(r, Ok(0) | Err(_)), "unexpected read result {r:?}");
    player.stop().await.unwrap();
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_port_can_be_changed_while_running() {
    init_tracing();
    let server = TestServer::start().await;
    let echo = tcp_echo_server().await;
    let host = start_host(
        &server,
        HostConfig::new("port-host", vec![tcp_service(0, echo.port())]),
    )
    .await;
    let mut player = join(&server, "port-host", None).await.unwrap();
    let old = player.addrs[&0];
    // Find a free port to move to.
    let wanted = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    // The first Forwarding event is the initial binding at startup.
    player
        .wait_for(|e| matches!(e, PlayerEvent::Forwarding { service_id: 0, .. }))
        .await;
    player
        .commands
        .send(PlayerCommand::SetLocalPort {
            service_id: 0,
            port: wanted,
        })
        .await
        .unwrap();
    let ev = player
        .wait_for(|e| matches!(e, PlayerEvent::Forwarding { service_id: 0, .. }))
        .await;
    let PlayerEvent::Forwarding { local_addr, .. } = ev else {
        unreachable!()
    };
    assert_eq!(local_addr.port(), wanted);
    assert_ne!(local_addr, old);
    // The old port is free again.
    TcpListener::bind(old).await.unwrap();

    let mut s = TcpStream::connect(local_addr).await.unwrap();
    s.write_all(b"moved").await.unwrap();
    let mut buf = [0u8; 5];
    within("echo after move", s.read_exact(&mut buf))
        .await
        .unwrap();
    assert_eq!(&buf, b"moved");

    player.stop().await.unwrap();
    host.stop().await.unwrap();
}
