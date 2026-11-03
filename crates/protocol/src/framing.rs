//! Length-prefixed frames: `u32` big-endian payload length followed by a postcard
//! encoded payload of at most [`MAX_FRAME_SIZE`] bytes.

use std::io;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::constants::MAX_FRAME_SIZE;

/// Errors while reading or writing frames.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The frame announced or produced a payload larger than [`MAX_FRAME_SIZE`].
    #[error("frame of {0} bytes exceeds the maximum of {MAX_FRAME_SIZE} bytes")]
    TooLarge(usize),
    /// The stream ended in the middle of a frame.
    #[error("stream ended in the middle of a frame")]
    UnexpectedEof,
    /// Serializing the message failed.
    #[error("failed to encode message: {0}")]
    Encode(postcard::Error),
    /// The payload could not be decoded as the expected message type.
    #[error("failed to decode message: {0}")]
    Decode(postcard::Error),
}

/// Encodes `msg` into a complete frame (length prefix + payload).
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    // Reserve the 4-byte prefix up front and patch it after serializing.
    let buf = postcard::to_extend(msg, vec![0u8; 4]).map_err(FrameError::Encode)?;
    let len = buf.len() - 4;
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = buf;
    // `len <= MAX_FRAME_SIZE` (64 KiB) always fits in a u32.
    let prefix = (len as u32).to_be_bytes();
    buf[..4].copy_from_slice(&prefix);
    Ok(buf)
}

/// Decodes a frame payload (without the length prefix).
pub fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FrameError> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(payload.len()));
    }
    postcard::from_bytes(payload).map_err(FrameError::Decode)
}

/// Writes one frame containing `msg`.
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: Serialize,
{
    let buf = encode_frame(msg)?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one frame.
///
/// Returns `Ok(None)` if the stream ended cleanly before the first byte of a frame.
///
/// This function is **not** cancel-safe: if the future is dropped mid-frame, the
/// stream is left in an undefined position. Run it in a dedicated task when it has
/// to be raced against other events.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin + ?Sized,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    while filled < len_buf.len() {
        let n = reader.read(&mut len_buf[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::UnexpectedEof)
            };
        }
        filled += n;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::UnexpectedEof
        } else {
            FrameError::Io(e)
        }
    })?;
    decode_payload(&payload).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::*;
    use std::net::SocketAddr;

    fn sample_client_msgs() -> Vec<ClientMsg> {
        vec![
            ClientMsg::Hello {
                protocol_version: crate::PROTOCOL_VERSION,
                role: Role::Host,
                client_version: "0.1.0".into(),
            },
            ClientMsg::Register {
                name: "kilian".into(),
                password: Some("pw".into()),
                services: vec![
                    ServiceDef {
                        id: 0,
                        kind: ServiceKind::Tcp,
                        label: "Minecraft".into(),
                        port: 25565,
                    },
                    ServiceDef {
                        id: 1,
                        kind: ServiceKind::Udp,
                        label: "Bedrock".into(),
                        port: 19132,
                    },
                ],
                reconnect_secret: None,
            },
            ClientMsg::Join {
                name: "kilian".into(),
                password: None,
            },
            ClientMsg::Ping { nonce: u64::MAX },
        ]
    }

    fn sample_server_msgs() -> Vec<ServerMsg> {
        let addr: SocketAddr = "[2001:db8::1]:4242".parse().unwrap();
        vec![
            ServerMsg::HelloOk {
                server_version: "0.1.0".into(),
            },
            ServerMsg::Registered {
                name: "kilian".into(),
                reconnect_secret: "abc".into(),
            },
            ServerMsg::Joined {
                host_name: "kilian".into(),
                services: vec![],
                player_id: 7,
            },
            ServerMsg::PlayerConnected { player_id: 1, addr },
            ServerMsg::PlayerDisconnected { player_id: 1 },
            ServerMsg::HostGone,
            ServerMsg::Pong { nonce: 42 },
            ServerMsg::Error {
                code: ErrorCode::WrongPassword,
                message: "nope".into(),
            },
            ServerMsg::ShuttingDown,
        ]
    }

    #[test]
    fn encode_decode_round_trip() {
        for msg in sample_client_msgs() {
            let frame = encode_frame(&msg).unwrap();
            let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            assert_eq!(len, frame.len() - 4);
            let back: ClientMsg = decode_payload(&frame[4..]).unwrap();
            assert_eq!(back, msg);
        }
        for msg in sample_server_msgs() {
            let frame = encode_frame(&msg).unwrap();
            let back: ServerMsg = decode_payload(&frame[4..]).unwrap();
            assert_eq!(back, msg);
        }
        let hdr = HostStreamHeader {
            service_id: 3,
            conn_id: 99,
            player_id: 5,
            player_addr: "1.2.3.4:5".parse().unwrap(),
        };
        let frame = encode_frame(&hdr).unwrap();
        assert_eq!(
            decode_payload::<HostStreamHeader>(&frame[4..]).unwrap(),
            hdr
        );
    }

    #[tokio::test]
    async fn async_round_trip_and_clean_eof() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msgs = sample_server_msgs();
        let to_send = msgs.clone();
        let writer = tokio::spawn(async move {
            for m in &to_send {
                write_frame(&mut a, m).await.unwrap();
            }
            // dropping `a` closes the stream
        });
        let mut got = Vec::new();
        while let Some(m) = read_frame::<_, ServerMsg>(&mut b).await.unwrap() {
            got.push(m);
        }
        writer.await.unwrap();
        assert_eq!(got, msgs);
    }

    #[tokio::test]
    async fn hello_is_stable_first_variant() {
        // A server must be able to decode the Hello of any client version, so the
        // encoding of Hello must start with variant index 0.
        let frame = encode_frame(&ClientMsg::Hello {
            protocol_version: 999,
            role: Role::Player,
            client_version: String::new(),
        })
        .unwrap();
        assert_eq!(frame[4], 0);
    }

    #[tokio::test]
    async fn rejects_oversized_frames() {
        let mut data = Vec::new();
        data.extend_from_slice(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes());
        let mut r = &data[..];
        let err = read_frame::<_, ServerMsg>(&mut r).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));

        let huge = ClientMsg::Hello {
            protocol_version: 1,
            role: Role::Host,
            client_version: "x".repeat(MAX_FRAME_SIZE + 1),
        };
        assert!(matches!(encode_frame(&huge), Err(FrameError::TooLarge(_))));
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error() {
        let frame = encode_frame(&ClientMsg::Ping { nonce: 1 }).unwrap();
        // Truncated length prefix.
        let mut r = &frame[..2];
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut r).await,
            Err(FrameError::UnexpectedEof)
        ));
        // Truncated payload.
        let mut r = &frame[..frame.len() - 1];
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut r).await,
            Err(FrameError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn garbage_payload_is_a_decode_error() {
        let mut data = vec![0, 0, 0, 2, 0xff, 0xff];
        let mut r = &data[..];
        assert!(matches!(
            read_frame::<_, ClientMsg>(&mut r).await,
            Err(FrameError::Decode(_))
        ));
        data.clear();
    }
}
