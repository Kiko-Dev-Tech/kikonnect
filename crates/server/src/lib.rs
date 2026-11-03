//! Kikonnect relay server.
//!
//! The server accepts QUIC connections from hosts and players, keeps an in-memory
//! registry of online tunnels and relays TCP streams and UDP datagrams between
//! players and hosts.
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use kikonnect_server::{tls, Server, ServerConfig};
//! use tokio_util::sync::CancellationToken;
//!
//! let (certs, key) = tls::load_pem("fullchain.pem".as_ref(), "privkey.pem".as_ref())?;
//! let server = Server::bind(ServerConfig::default(), tls::server_crypto(certs, key)?)?;
//! server.run(CancellationToken::new()).await?;
//! # Ok(()) }
//! ```

pub mod config;
mod connection;
pub mod health;
pub mod ratelimit;
pub mod registry;
mod relay;
pub mod reload;
pub mod server;
pub mod tls;
pub mod udp;

pub use config::ServerConfig;
pub use server::{CryptoUpdater, Server, ServerError};
