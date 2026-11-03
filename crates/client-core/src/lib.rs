//! Kikonnect client networking, independent of any UI.
//!
//! Two modes share one QUIC transport:
//!
//! * **Host** ([`host`]): registers a tunnel name at the relay server and forwards
//!   incoming TCP streams and UDP datagrams to local game servers.
//!   [`run_host`] adds automatic reconnects that reclaim the name.
//! * **Join** ([`player`]): joins a tunnel, binds local listeners for each of the
//!   host's services and forwards local game traffic through the relay.
//!
//! Every long-running function reports progress through a bounded
//! [`tokio::sync::mpsc`] channel of events (dropping events if the consumer falls
//! behind, never blocking networking) and stops when a
//! [`CancellationToken`](tokio_util::sync::CancellationToken) is cancelled.

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod host;
mod pipe;
pub mod player;
pub mod transport;
mod util;

pub use config::ClientConfig;
pub use error::ClientError;
pub use host::{run_host, HostConfig, HostEvent, HostSession, HostStatus, ReconnectPolicy};
pub use kikonnect_protocol as protocol;
pub use kikonnect_protocol::{ErrorCode, ServiceDef, ServiceKind};
pub use player::{JoinConfig, PlayerCommand, PlayerEvent, PlayerExit, PlayerSession};
pub use tokio_util::sync::CancellationToken;
