//! Shared wire protocol for Kikonnect.
//!
//! This crate contains everything both the relay server and the clients need to
//! agree on:
//!
//! * [`constants`]: protocol version, ALPN, timeouts, limits and close codes.
//! * [`messages`]: control-stream messages ([`ClientMsg`], [`ServerMsg`]) and the
//!   headers that open TCP-carrying streams ([`StreamHeader`], [`HostStreamHeader`]).
//! * [`framing`]: length-prefixed (`u32` big-endian) postcard frames.
//! * [`datagram`]: the QUIC datagram header used for UDP traffic.
//! * [`name`]: tunnel name validation.
//! * [`oversize`]: a small counter for dropped oversized datagrams.
//!
//! # Compatibility
//!
//! [`ClientMsg::Hello`] is the first variant of [`ClientMsg`] and must stay the
//! first variant with the same fields forever, so that a server can always decode
//! a client's hello and reply with a clean
//! [`ErrorCode::VersionMismatch`] instead of a decoding error.

#![warn(missing_docs)]

pub mod constants;
pub mod datagram;
pub mod framing;
pub mod messages;
pub mod name;
pub mod oversize;

pub use constants::*;
pub use datagram::{DatagramError, DatagramHeader, DATAGRAM_HEADER_LEN};
pub use framing::{decode_payload, encode_frame, read_frame, write_frame, FrameError};
pub use messages::{
    validate_services, ClientMsg, ErrorCode, HostStreamHeader, Role, ServerMsg, ServiceDef,
    ServiceKind, StreamHeader,
};
pub use name::{normalize_name, NameError, RESERVED_NAMES};
pub use oversize::OversizeCounter;
