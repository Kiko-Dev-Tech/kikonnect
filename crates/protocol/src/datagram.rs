//! QUIC datagram format for UDP traffic:
//! `[service_id: u8][session_id: u32 big-endian][payload]`.

use bytes::{BufMut, Bytes, BytesMut};

/// Length of the datagram header in bytes.
pub const DATAGRAM_HEADER_LEN: usize = 5;

/// Header of a UDP-carrying QUIC datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramHeader {
    /// The UDP service the payload belongs to.
    pub service_id: u8,
    /// Session id. Between player and server it is the player-local session id;
    /// between server and host it is the tunnel-wide global session id.
    pub session_id: u32,
}

/// Errors while parsing a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramError {
    /// The datagram is shorter than the header.
    #[error("datagram of {0} bytes is shorter than the {DATAGRAM_HEADER_LEN}-byte header")]
    TooShort(usize),
}

impl DatagramHeader {
    /// Creates a header.
    pub fn new(service_id: u8, session_id: u32) -> Self {
        Self {
            service_id,
            session_id,
        }
    }

    /// Serializes the header followed by `payload` into a new buffer.
    pub fn encode_with(&self, payload: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(DATAGRAM_HEADER_LEN + payload.len());
        buf.put_u8(self.service_id);
        buf.put_u32(self.session_id);
        buf.put_slice(payload);
        buf.freeze()
    }

    /// Parses a datagram into its header and payload.
    pub fn decode(data: &[u8]) -> Result<(Self, &[u8]), DatagramError> {
        if data.len() < DATAGRAM_HEADER_LEN {
            return Err(DatagramError::TooShort(data.len()));
        }
        let service_id = data[0];
        let session_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Ok((
            Self::new(service_id, session_id),
            &data[DATAGRAM_HEADER_LEN..],
        ))
    }

    /// Like [`decode`](Self::decode), but returns the payload as a zero-copy slice of
    /// the original [`Bytes`].
    pub fn decode_bytes(data: &Bytes) -> Result<(Self, Bytes), DatagramError> {
        let (hdr, _) = Self::decode(data)?;
        Ok((hdr, data.slice(DATAGRAM_HEADER_LEN..)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let hdr = DatagramHeader::new(7, 0xDEAD_BEEF);
        let d = hdr.encode_with(b"hello");
        assert_eq!(
            &d[..],
            &[7, 0xDE, 0xAD, 0xBE, 0xEF, b'h', b'e', b'l', b'l', b'o']
        );
        let (h2, payload) = DatagramHeader::decode(&d).unwrap();
        assert_eq!(h2, hdr);
        assert_eq!(payload, b"hello");
        let (h3, p3) = DatagramHeader::decode_bytes(&d).unwrap();
        assert_eq!(h3, hdr);
        assert_eq!(&p3[..], b"hello");
    }

    #[test]
    fn empty_payload_and_too_short() {
        let d = DatagramHeader::new(1, 2).encode_with(&[]);
        assert_eq!(d.len(), DATAGRAM_HEADER_LEN);
        assert_eq!(DatagramHeader::decode(&d).unwrap().1.len(), 0);
        assert_eq!(
            DatagramHeader::decode(&d[..4]),
            Err(DatagramError::TooShort(4))
        );
    }
}
