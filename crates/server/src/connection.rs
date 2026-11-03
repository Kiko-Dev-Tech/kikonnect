//! Per-connection control flow: hello, register / join and the session loops.

use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use kikonnect_protocol::{
    close_code, normalize_name, read_frame, validate_services, write_frame, ClientMsg, ErrorCode,
    Role, ServerMsg, MAX_PASSWORD_LEN, PROTOCOL_VERSION,
};
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::registry::{Tunnel, TunnelParams};
use crate::relay;
use crate::server::ServerState;

/// How long to wait for the client to close the connection after a final message.
const GOODBYE_LINGER: Duration = Duration::from_secs(2);
/// Interval of the per-tunnel UDP session expiry sweep.
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Control stream of one connection, split into a writer and a reader task so the
/// session loops can `select!` on it safely.
struct Control {
    out: mpsc::Sender<ServerMsg>,
    inbound: mpsc::Receiver<Result<ClientMsg, String>>,
}

fn spawn_control(mut send: SendStream, mut recv: RecvStream) -> Control {
    let (out_tx, mut out_rx) = mpsc::channel::<ServerMsg>(64);
    tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if let Err(e) = write_frame(&mut send, &msg).await {
                debug!("control write failed: {e}");
                break;
            }
        }
        let _ = send.finish();
    });
    let (in_tx, in_rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            match read_frame::<_, ClientMsg>(&mut recv).await {
                Ok(Some(msg)) => {
                    if in_tx.send(Ok(msg)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = in_tx.send(Err(e.to_string())).await;
                    break;
                }
            }
        }
    });
    Control {
        out: out_tx,
        inbound: in_rx,
    }
}

async fn recv_msg(ctrl: &mut Control, t: Duration, what: &str) -> Result<ClientMsg, String> {
    match timeout(t, ctrl.inbound.recv()).await {
        Err(_) => Err(format!("timed out waiting for {what}")),
        Ok(None) => Err(format!("control stream closed before {what}")),
        Ok(Some(Err(e))) => Err(format!("invalid frame while waiting for {what}: {e}")),
        Ok(Some(Ok(msg))) => Ok(msg),
    }
}

/// Sends a final message, gives the client a moment to close the connection
/// itself (so the message is guaranteed to be delivered), then closes it.
async fn goodbye(conn: &Connection, ctrl: &Control, msg: ServerMsg, code: u32, reason: &str) {
    let _ = timeout(Duration::from_secs(1), ctrl.out.send(msg)).await;
    let _ = timeout(GOODBYE_LINGER, conn.closed()).await;
    conn.close(VarInt::from_u32(code), reason.as_bytes());
}

async fn reject(conn: &Connection, ctrl: &Control, code: ErrorCode, message: impl Into<String>) {
    let message = message.into();
    debug!(remote = %conn.remote_address(), %code, %message, "rejecting request");
    goodbye(
        conn,
        ctrl,
        ServerMsg::Error { code, message },
        close_code::REJECTED,
        "rejected",
    )
    .await;
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn hash_password(pw: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)?
        .to_string())
}

fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

fn random_secret() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Handles one accepted QUIC connection until it ends.
pub(crate) async fn handle(state: Arc<ServerState>, conn: Connection) {
    let remote = conn.remote_address();
    if let Err(e) = handle_inner(&state, &conn).await {
        debug!(%remote, "connection ended: {e}");
    }
    // No-op if the connection was already closed with a more specific code.
    conn.close(VarInt::from_u32(close_code::NORMAL), b"");
}

async fn handle_inner(state: &Arc<ServerState>, conn: &Connection) -> Result<(), String> {
    let hs = state.config.handshake_timeout;
    let (send, recv) = timeout(hs, conn.accept_bi())
        .await
        .map_err(|_| "timed out waiting for the control stream".to_owned())?
        .map_err(|e| e.to_string())?;
    let mut ctrl = spawn_control(send, recv);

    let hello = recv_msg(&mut ctrl, hs, "Hello").await?;
    let ClientMsg::Hello {
        protocol_version,
        role,
        client_version,
    } = hello
    else {
        reject(conn, &ctrl, ErrorCode::InvalidRequest, "expected Hello").await;
        return Ok(());
    };
    let client_version = truncate(&client_version, 64).to_owned();
    if protocol_version != PROTOCOL_VERSION {
        info!(
            remote = %conn.remote_address(),
            protocol_version,
            %client_version,
            "rejecting client with incompatible protocol version"
        );
        let message = format!(
            "incompatible protocol version: your client (version {client_version}) speaks protocol \
             v{protocol_version}, this server (version {}) speaks v{PROTOCOL_VERSION}. \
             Please update Kikonnect.",
            state.config.server_version
        );
        reject(conn, &ctrl, ErrorCode::VersionMismatch, message).await;
        return Ok(());
    }
    ctrl.out
        .send(ServerMsg::HelloOk {
            server_version: state.config.server_version.clone(),
        })
        .await
        .map_err(|_| "control stream closed".to_owned())?;
    debug!(remote = %conn.remote_address(), ?role, %client_version, "hello");

    match role {
        Role::Host => host_session(state, conn, ctrl).await,
        Role::Player => player_session(state, conn, ctrl).await,
    }
}

async fn host_session(
    state: &Arc<ServerState>,
    conn: &Connection,
    mut ctrl: Control,
) -> Result<(), String> {
    let remote = conn.remote_address();
    let msg = recv_msg(&mut ctrl, state.config.handshake_timeout, "Register").await?;
    let ClientMsg::Register {
        name,
        password,
        services,
        reconnect_secret,
    } = msg
    else {
        reject(conn, &ctrl, ErrorCode::InvalidRequest, "expected Register").await;
        return Ok(());
    };
    if !state.rate_limiter.check(remote.ip()) {
        warn!(%remote, "register rate limited");
        reject(
            conn,
            &ctrl,
            ErrorCode::RateLimited,
            "too many attempts, please wait a minute",
        )
        .await;
        return Ok(());
    }
    let name = match normalize_name(&name) {
        Ok(n) => n,
        Err(e) => {
            reject(conn, &ctrl, ErrorCode::InvalidName, e.to_string()).await;
            return Ok(());
        }
    };
    if let Err(e) = validate_services(&services) {
        reject(conn, &ctrl, ErrorCode::InvalidRequest, e).await;
        return Ok(());
    }
    if password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_LEN)
    {
        reject(
            conn,
            &ctrl,
            ErrorCode::InvalidRequest,
            format!("password longer than {MAX_PASSWORD_LEN} bytes"),
        )
        .await;
        return Ok(());
    }
    if let Err(code) =
        state
            .registry
            .check_available(&name, reconnect_secret.as_deref(), Instant::now())
    {
        reject(conn, &ctrl, code, register_error_message(code, &name)).await;
        return Ok(());
    }
    let password_hash = match password.filter(|p| !p.is_empty()) {
        Some(pw) => match tokio::task::spawn_blocking(move || hash_password(&pw)).await {
            Ok(Ok(hash)) => Some(hash),
            _ => {
                reject(
                    conn,
                    &ctrl,
                    ErrorCode::Internal,
                    "failed to process password",
                )
                .await;
                return Ok(());
            }
        },
        None => None,
    };
    let has_password = password_hash.is_some();
    let secret = random_secret();
    let tunnel = Arc::new(Tunnel::new(
        state.registry.next_tunnel_id(),
        TunnelParams {
            name: name.clone(),
            host: conn.clone(),
            host_out: ctrl.out.clone(),
            services,
            password_hash,
            reconnect_secret: secret.clone(),
            max_players: state.config.max_players_per_tunnel,
            max_udp_sessions: state.config.max_udp_sessions_per_tunnel,
        },
    ));
    let registration =
        match state
            .registry
            .register(tunnel.clone(), reconnect_secret.as_deref(), Instant::now())
        {
            Ok(r) => r,
            Err(code) => {
                reject(conn, &ctrl, code, register_error_message(code, &name)).await;
                return Ok(());
            }
        };
    if let Some(old) = registration.replaced {
        info!(tunnel = %name, "replacing previous connection of the same host");
        old.evicted.cancel();
    }
    ctrl.out
        .send(ServerMsg::Registered {
            name: name.clone(),
            reconnect_secret: secret,
        })
        .await
        .map_err(|_| "control stream closed".to_owned())?;
    info!(
        tunnel = %name,
        %remote,
        services = tunnel.services.len(),
        password = has_password,
        reclaimed = registration.reclaimed,
        "host registered"
    );

    let reason = host_loop(state, conn, &mut ctrl, &tunnel).await;

    let players = tunnel.player_count();
    tunnel.close();
    state.registry.release(&tunnel, Instant::now());
    info!(tunnel = %name, %remote, players, %reason, "host left");
    Ok(())
}

fn register_error_message(code: ErrorCode, name: &str) -> String {
    match code {
        ErrorCode::NameTaken => format!("the name '{name}' is already in use"),
        ErrorCode::ServerFull => "the server has reached its tunnel limit, try again later".into(),
        other => other.to_string(),
    }
}

async fn host_loop(
    state: &Arc<ServerState>,
    conn: &Connection,
    ctrl: &mut Control,
    tunnel: &Arc<Tunnel>,
) -> String {
    let mut sweep = interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => {
                goodbye(conn, ctrl, ServerMsg::ShuttingDown, close_code::SERVER_SHUTDOWN, "server shutting down").await;
                return "server shutdown".into();
            }
            _ = tunnel.evicted.cancelled() => {
                let msg = ServerMsg::Error {
                    code: ErrorCode::Replaced,
                    message: "this tunnel was taken over by a newer connection".into(),
                };
                goodbye(conn, ctrl, msg, close_code::REPLACED, "replaced").await;
                return "replaced by a newer connection".into();
            }
            msg = ctrl.inbound.recv() => match msg {
                Some(Ok(ClientMsg::Ping { nonce })) => {
                    let _ = ctrl.out.try_send(ServerMsg::Pong { nonce });
                }
                Some(Ok(other)) => {
                    warn!(tunnel = %tunnel.name, ?other, "unexpected message from host");
                    conn.close(VarInt::from_u32(close_code::PROTOCOL_ERROR), b"unexpected message");
                    return "protocol error".into();
                }
                Some(Err(e)) => {
                    conn.close(VarInt::from_u32(close_code::PROTOCOL_ERROR), b"invalid frame");
                    return format!("invalid frame: {e}");
                }
                None => return "control stream closed".into(),
            },
            dg = conn.read_datagram() => match dg {
                Ok(data) => relay::host_datagram(state, tunnel, data),
                Err(e) => return e.to_string(),
            },
            _ = sweep.tick() => {
                let n = tunnel.expire_udp(Instant::now(), state.config.udp_session_timeout);
                if n > 0 {
                    debug!(tunnel = %tunnel.name, expired = n, "expired UDP sessions");
                }
            }
        }
    }
}

async fn player_session(
    state: &Arc<ServerState>,
    conn: &Connection,
    mut ctrl: Control,
) -> Result<(), String> {
    let remote = conn.remote_address();
    let msg = recv_msg(&mut ctrl, state.config.handshake_timeout, "Join").await?;
    let ClientMsg::Join { name, password } = msg else {
        reject(conn, &ctrl, ErrorCode::InvalidRequest, "expected Join").await;
        return Ok(());
    };
    if !state.rate_limiter.check(remote.ip()) {
        warn!(%remote, "join rate limited");
        reject(
            conn,
            &ctrl,
            ErrorCode::RateLimited,
            "too many attempts, please wait a minute",
        )
        .await;
        return Ok(());
    }
    let Some(tunnel) = normalize_name(&name)
        .ok()
        .and_then(|n| state.registry.lookup(&n))
    else {
        let shown = truncate(name.trim(), 32);
        reject(
            conn,
            &ctrl,
            ErrorCode::HostNotFound,
            format!("no host named '{shown}' is online"),
        )
        .await;
        return Ok(());
    };
    if let Some(hash) = tunnel.password_hash() {
        let Some(pw) = password.filter(|p| !p.is_empty() && p.len() <= MAX_PASSWORD_LEN) else {
            reject(
                conn,
                &ctrl,
                ErrorCode::WrongPassword,
                "this tunnel requires a password",
            )
            .await;
            return Ok(());
        };
        let hash = hash.to_owned();
        let ok = tokio::task::spawn_blocking(move || verify_password(&pw, &hash))
            .await
            .unwrap_or(false);
        if !ok {
            info!(tunnel = %tunnel.name, %remote, "join with wrong password");
            reject(conn, &ctrl, ErrorCode::WrongPassword, "wrong password").await;
            return Ok(());
        }
    }
    let (player_id, kick) = match tunnel.add_player(conn.clone(), remote) {
        Ok(v) => v,
        Err(code) => {
            let message = match code {
                ErrorCode::TunnelFull => "this tunnel has reached its player limit".to_owned(),
                ErrorCode::HostNotFound => format!("host '{}' just went offline", tunnel.name),
                other => other.to_string(),
            };
            reject(conn, &ctrl, code, message).await;
            return Ok(());
        }
    };
    if ctrl
        .out
        .send(ServerMsg::Joined {
            host_name: tunnel.name.clone(),
            services: tunnel.services.clone(),
            player_id,
        })
        .await
        .is_err()
    {
        tunnel.remove_player(player_id);
        return Err("control stream closed".into());
    }
    info!(tunnel = %tunnel.name, player_id, %remote, "player joined");

    let reason = player_loop(state, conn, &mut ctrl, &tunnel, player_id, &kick).await;

    tunnel.remove_player(player_id);
    info!(tunnel = %tunnel.name, player_id, %remote, %reason, "player left");
    Ok(())
}

async fn player_loop(
    state: &Arc<ServerState>,
    conn: &Connection,
    ctrl: &mut Control,
    tunnel: &Arc<Tunnel>,
    player_id: u32,
    kick: &tokio_util::sync::CancellationToken,
) -> String {
    let remote = conn.remote_address();
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => {
                goodbye(conn, ctrl, ServerMsg::ShuttingDown, close_code::SERVER_SHUTDOWN, "server shutting down").await;
                return "server shutdown".into();
            }
            _ = kick.cancelled() => {
                goodbye(conn, ctrl, ServerMsg::HostGone, close_code::HOST_GONE, "host gone").await;
                return "host left".into();
            }
            msg = ctrl.inbound.recv() => match msg {
                Some(Ok(ClientMsg::Ping { nonce })) => {
                    let _ = ctrl.out.try_send(ServerMsg::Pong { nonce });
                }
                Some(Ok(other)) => {
                    warn!(tunnel = %tunnel.name, player_id, ?other, "unexpected message from player");
                    conn.close(VarInt::from_u32(close_code::PROTOCOL_ERROR), b"unexpected message");
                    return "protocol error".into();
                }
                Some(Err(e)) => {
                    conn.close(VarInt::from_u32(close_code::PROTOCOL_ERROR), b"invalid frame");
                    return format!("invalid frame: {e}");
                }
                None => return "control stream closed".into(),
            },
            stream = conn.accept_bi() => match stream {
                Ok((send, recv)) => {
                    // Detached: the relay ends on its own when either connection
                    // closes (all stream operations then fail).
                    tokio::spawn(relay::player_stream(
                        state.clone(),
                        tunnel.clone(),
                        player_id,
                        remote,
                        send,
                        recv,
                    ));
                }
                Err(e) => return e.to_string(),
            },
            dg = conn.read_datagram() => match dg {
                Ok(data) => relay::player_datagram(state, tunnel, player_id, data),
                Err(e) => return e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let h = hash_password("hunter2").unwrap();
        assert!(!h.contains("hunter2"));
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
        assert!(!verify_password("hunter2", "not a hash"));
    }

    #[test]
    fn secrets_are_random_hex() {
        let a = random_secret();
        let b = random_secret();
        assert_eq!(a.len(), 48);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate("äöü", 2), "äö");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
