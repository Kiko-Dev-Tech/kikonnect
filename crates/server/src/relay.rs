//! Data relaying: TCP-carrying streams and UDP-carrying datagrams.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use kikonnect_protocol::{
    read_frame, stream_code, write_frame, DatagramHeader, HostStreamHeader, ServiceKind,
    StreamHeader,
};
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::registry::{lock, Tunnel};
use crate::server::ServerState;

/// Maximum chunk size read from a stream at once.
const CHUNK_SIZE: usize = 64 * 1024;

fn reject_stream(send: &mut SendStream, recv: &mut RecvStream) {
    let _ = send.reset(VarInt::from_u32(stream_code::REJECTED));
    let _ = recv.stop(VarInt::from_u32(stream_code::REJECTED));
}

/// Relays one TCP connection: a player-opened stream to a newly opened host stream.
pub(crate) async fn player_stream(
    state: Arc<ServerState>,
    tunnel: Arc<Tunnel>,
    player_id: u32,
    player_addr: SocketAddr,
    mut p_send: SendStream,
    mut p_recv: RecvStream,
) {
    let hs = state.config.handshake_timeout;
    let header = match timeout(hs, read_frame::<_, StreamHeader>(&mut p_recv)).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            debug!(tunnel = %tunnel.name, player_id, "invalid stream header: {e}");
            reject_stream(&mut p_send, &mut p_recv);
            return;
        }
        Err(_) => {
            debug!(tunnel = %tunnel.name, player_id, "timed out waiting for stream header");
            reject_stream(&mut p_send, &mut p_recv);
            return;
        }
    };
    let valid = tunnel
        .service(header.service_id)
        .is_some_and(|s| s.kind == ServiceKind::Tcp);
    if !valid {
        debug!(tunnel = %tunnel.name, player_id, service_id = header.service_id, "stream for unknown TCP service");
        reject_stream(&mut p_send, &mut p_recv);
        return;
    }
    let conn_id = tunnel.next_conn_id();
    let (mut h_send, mut h_recv) = match timeout(hs, tunnel.host.open_bi()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(tunnel = %tunnel.name, "failed to open stream to host: {e}");
            reject_stream(&mut p_send, &mut p_recv);
            return;
        }
        Err(_) => {
            debug!(tunnel = %tunnel.name, "timed out opening stream to host");
            reject_stream(&mut p_send, &mut p_recv);
            return;
        }
    };
    let host_header = HostStreamHeader {
        service_id: header.service_id,
        conn_id,
        player_id,
        player_addr,
    };
    match timeout(hs, write_frame(&mut h_send, &host_header)).await {
        Ok(Ok(())) => {}
        _ => {
            debug!(tunnel = %tunnel.name, conn_id, "failed to send stream header to host");
            reject_stream(&mut p_send, &mut p_recv);
            reject_stream(&mut h_send, &mut h_recv);
            return;
        }
    }
    debug!(tunnel = %tunnel.name, conn_id, player_id, service_id = header.service_id, "TCP stream opened");

    let abort = CancellationToken::new();
    let (up, down) = tokio::join!(
        copy_stream(p_recv, h_send, abort.clone()),
        copy_stream(h_recv, p_send, abort.clone()),
    );
    debug!(
        tunnel = %tunnel.name,
        conn_id,
        to_host = ?up,
        to_player = ?down,
        "TCP stream closed"
    );
}

/// Copies one direction of a relayed stream. A clean end of `recv` finishes `send`
/// (half-close). On any error both streams are reset and the opposite direction is
/// aborted via `abort`.
async fn copy_stream(
    mut recv: RecvStream,
    mut send: SendStream,
    abort: CancellationToken,
) -> Result<u64, ()> {
    let mut total = 0u64;
    let result = loop {
        let chunk = tokio::select! {
            _ = abort.cancelled() => break Err(()),
            c = recv.read_chunk(CHUNK_SIZE, true) => c,
        };
        match chunk {
            Ok(Some(chunk)) => {
                total += chunk.bytes.len() as u64;
                let written = tokio::select! {
                    _ = abort.cancelled() => break Err(()),
                    w = send.write_chunk(chunk.bytes) => w,
                };
                if written.is_err() {
                    break Err(());
                }
            }
            Ok(None) => {
                let _ = send.finish();
                break Ok(total);
            }
            Err(_) => break Err(()),
        }
    };
    if result.is_err() {
        abort.cancel();
        let _ = send.reset(VarInt::from_u32(stream_code::ABORTED));
        let _ = recv.stop(VarInt::from_u32(stream_code::ABORTED));
    }
    result
}

/// Forwards a datagram from a player to the host, rewriting the session id.
pub(crate) fn player_datagram(state: &ServerState, tunnel: &Tunnel, player_id: u32, data: Bytes) {
    let Ok((hdr, payload)) = DatagramHeader::decode(&data) else {
        trace!(tunnel = %tunnel.name, player_id, "malformed datagram");
        return;
    };
    let valid = tunnel
        .service(hdr.service_id)
        .is_some_and(|s| s.kind == ServiceKind::Udp);
    if !valid {
        trace!(tunnel = %tunnel.name, player_id, service_id = hdr.service_id, "datagram for unknown UDP service");
        return;
    }
    let global = lock(&tunnel.udp).to_global(player_id, hdr.session_id, Instant::now());
    let Some(global) = global else {
        debug!(tunnel = %tunnel.name, player_id, "UDP session limit reached, dropping datagram");
        return;
    };
    let out = DatagramHeader::new(hdr.service_id, global).encode_with(payload);
    send_datagram(state, &tunnel.host, out);
}

/// Forwards a datagram from the host back to the player owning the session.
pub(crate) fn host_datagram(state: &ServerState, tunnel: &Tunnel, data: Bytes) {
    let Ok((hdr, payload)) = DatagramHeader::decode(&data) else {
        trace!(tunnel = %tunnel.name, "malformed datagram from host");
        return;
    };
    let target = lock(&tunnel.udp).to_player(hdr.session_id, Instant::now());
    let Some((player_id, local_id)) = target else {
        trace!(tunnel = %tunnel.name, session = hdr.session_id, "datagram for unknown session");
        return;
    };
    let Some(player) = tunnel.player_conn(player_id) else {
        return;
    };
    let out = DatagramHeader::new(hdr.service_id, local_id).encode_with(payload);
    send_datagram(state, &player, out);
}

fn send_datagram(state: &ServerState, conn: &Connection, data: Bytes) {
    match conn.max_datagram_size() {
        Some(max) if data.len() <= max => {
            if let Err(e) = conn.send_datagram(data) {
                trace!("failed to send datagram: {e}");
            }
        }
        Some(max) => {
            if let Some(total) = state.oversize.record() {
                warn!(
                    size = data.len(),
                    max,
                    total_dropped = total,
                    "dropping oversized UDP datagram"
                );
            }
        }
        None => trace!("peer does not support datagrams"),
    }
}
