//! Copying bytes between a local TCP connection and a QUIC stream pair.

use kikonnect_protocol::stream_code;
use quinn::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

const CHUNK_SIZE: usize = 64 * 1024;

/// Pipes `tcp` <-> (`send`, `recv`) until both directions finished.
///
/// A clean EOF in one direction is propagated as a half-close (`finish` on QUIC,
/// `shutdown(Write)` on TCP) while the other direction keeps flowing. An error in
/// either direction aborts both (QUIC streams are reset / stopped).
///
/// Returns the number of bytes copied `(tcp -> quic, quic -> tcp)`, or `Err(())`
/// for an aborted direction.
pub(crate) async fn tcp_over_quic(
    tcp: TcpStream,
    send: SendStream,
    recv: RecvStream,
) -> (Result<u64, ()>, Result<u64, ()>) {
    let (tcp_r, tcp_w) = tcp.into_split();
    let abort = CancellationToken::new();
    tokio::join!(
        tcp_to_quic(tcp_r, send, abort.clone()),
        quic_to_tcp(recv, tcp_w, abort.clone()),
    )
}

async fn tcp_to_quic(
    mut tcp: OwnedReadHalf,
    mut send: SendStream,
    abort: CancellationToken,
) -> Result<u64, ()> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut total = 0u64;
    let result = loop {
        let read = tokio::select! {
            _ = abort.cancelled() => break Err(()),
            r = tcp.read(&mut buf) => r,
        };
        match read {
            Ok(0) => {
                let _ = send.finish();
                break Ok(total);
            }
            Ok(n) => {
                total += n as u64;
                let written = tokio::select! {
                    _ = abort.cancelled() => break Err(()),
                    w = send.write_all(&buf[..n]) => w,
                };
                if written.is_err() {
                    break Err(());
                }
            }
            Err(_) => break Err(()),
        }
    };
    if result.is_err() {
        abort.cancel();
        let _ = send.reset(VarInt::from_u32(stream_code::ABORTED));
    }
    result
}

async fn quic_to_tcp(
    mut recv: RecvStream,
    mut tcp: OwnedWriteHalf,
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
                    w = tcp.write_all(&chunk.bytes) => w,
                };
                if written.is_err() {
                    break Err(());
                }
            }
            Ok(None) => {
                let _ = tcp.shutdown().await;
                break Ok(total);
            }
            Err(_) => break Err(()),
        }
    };
    if result.is_err() {
        abort.cancel();
        let _ = recv.stop(VarInt::from_u32(stream_code::ABORTED));
    }
    result
}
