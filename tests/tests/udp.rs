//! UDP forwarding end to end.

use std::net::SocketAddr;
use std::time::Duration;

use kikonnect_client_core::HostConfig;
use kikonnect_tests::*;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Sends `msg` from `client` and waits for its echo, retrying a few times (UDP is
/// unreliable). Panics if a packet that does not belong to this client arrives.
async fn echo_round_trip(client: &UdpSocket, prefix: &str, msg: &str) {
    let mut buf = vec![0u8; 65_535];
    for _ in 0..10 {
        client.send(msg.as_bytes()).await.unwrap();
        match timeout(Duration::from_millis(1000), client.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let got = std::str::from_utf8(&buf[..n]).unwrap();
                assert!(
                    got.starts_with(prefix),
                    "client {prefix} received someone else's packet: {got}"
                );
                if got == msg {
                    return;
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    panic!("no echo for {msg}");
}

async fn game_client(target: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(target).await.unwrap();
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_sessions_reach_the_correct_client() {
    init_tracing();
    let server = TestServer::start().await;
    let echo = udp_echo_server().await;
    let host = start_host(
        &server,
        HostConfig::new(
            "udp-host",
            vec![tcp_service(0, 1), udp_service(1, echo.port())],
        ),
    )
    .await;
    let p1 = join(&server, "udp-host", None).await.unwrap();
    let p2 = join(&server, "udp-host", None).await.unwrap();

    // Two game clients behind player 1, one behind player 2. Players use
    // overlapping local session ids, so the server must rewrite them.
    let clients = vec![
        ("a-", game_client(p1.addrs[&1]).await),
        ("b-", game_client(p1.addrs[&1]).await),
        ("c-", game_client(p2.addrs[&1]).await),
    ];
    for round in 0..5 {
        for (prefix, client) in &clients {
            let msg = format!("{prefix}round-{round}");
            within("udp echo", echo_round_trip(client, prefix, &msg)).await;
        }
    }
    // Interleaved concurrent traffic.
    let mut tasks = Vec::new();
    for (prefix, client) in clients {
        tasks.push(tokio::spawn(async move {
            for round in 0..20 {
                let msg = format!("{prefix}burst-{round}-{}", "z".repeat(round * 20));
                echo_round_trip(&client, prefix, &msg).await;
            }
        }));
    }
    for t in tasks {
        within("udp burst", t).await.unwrap();
    }

    p1.stop().await.unwrap();
    p2.stop().await.unwrap();
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_oversized_packets_are_dropped_without_breaking_the_session() {
    init_tracing();
    let server = TestServer::start().await;
    let echo = udp_echo_server().await;
    let host = start_host(
        &server,
        HostConfig::new("big-udp", vec![udp_service(0, echo.port())]),
    )
    .await;
    let player = join(&server, "big-udp", None).await.unwrap();
    let client = game_client(player.addrs[&0]).await;

    // Larger than any QUIC datagram on a 1500-byte MTU path.
    client.send(&vec![b'x'; 8000]).await.unwrap();
    let mut buf = vec![0u8; 65_535];
    let r = timeout(Duration::from_millis(500), client.recv(&mut buf)).await;
    assert!(r.is_err(), "oversized packet must not arrive");

    within("small echo", echo_round_trip(&client, "ok", "ok-small")).await;

    player.stop().await.unwrap();
    host.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_sessions_expire_and_recover() {
    init_tracing();
    let server =
        TestServer::start_with(|c| c.udp_session_timeout = Duration::from_millis(500)).await;
    let echo = udp_echo_server().await;
    let mut cfg = HostConfig::new("expiring", vec![udp_service(0, echo.port())]);
    cfg.udp_session_timeout = Duration::from_millis(500);
    let host = start_host(&server, cfg).await;
    let player = join(&server, "expiring", None).await.unwrap();
    let client = game_client(player.addrs[&0]).await;

    within("first echo", echo_round_trip(&client, "e", "e-1")).await;
    // Server and host sessions expire; the player's session (60 s) does not, so
    // the next packet arrives with a known player-local id and must create fresh
    // mappings on server and host.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    within("echo after expiry", echo_round_trip(&client, "e", "e-2")).await;

    player.stop().await.unwrap();
    host.stop().await.unwrap();
}
