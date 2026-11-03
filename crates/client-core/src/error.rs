//! Client error type.

use std::io;

use kikonnect_protocol::ErrorCode;

/// Errors of client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The server address could not be parsed.
    #[error("invalid server address '{0}'")]
    InvalidAddress(String),
    /// The server address could not be resolved.
    #[error("could not resolve server address '{0}'")]
    Resolve(String),
    /// The tunnel name is invalid (checked locally before connecting).
    #[error("invalid name: {0}")]
    InvalidName(String),
    /// The host or join configuration is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// TLS setup failed.
    #[error("TLS error: {0}")]
    Tls(String),
    /// Connecting to the server failed.
    #[error("could not connect to server: {0}")]
    Connect(String),
    /// A step did not complete in time.
    #[error("timed out while {0}")]
    Timeout(&'static str),
    /// The server rejected a request.
    #[error("{message} ({code})")]
    Server {
        /// Machine readable error code.
        code: ErrorCode,
        /// Message from the server.
        message: String,
    },
    /// The server is shutting down.
    #[error("the server is shutting down")]
    ServerShutdown,
    /// The host of the joined tunnel left.
    #[error("the host left")]
    HostGone,
    /// The connection to the server was lost.
    #[error("connection lost: {0}")]
    ConnectionLost(String),
    /// The server sent something unexpected.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A local I/O error (e.g. binding a port).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl ClientError {
    /// Whether retrying the same operation later may succeed (used for automatic
    /// reconnects).
    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::InvalidAddress(_)
            | ClientError::InvalidName(_)
            | ClientError::InvalidConfig(_)
            | ClientError::Tls(_)
            | ClientError::HostGone => false,
            ClientError::Server { code, .. } => matches!(
                code,
                ErrorCode::RateLimited | ErrorCode::Internal | ErrorCode::ServerFull
            ),
            ClientError::Resolve(_)
            | ClientError::Connect(_)
            | ClientError::Timeout(_)
            | ClientError::ServerShutdown
            | ClientError::ConnectionLost(_)
            | ClientError::Protocol(_)
            | ClientError::Io(_) => true,
        }
    }

    /// The server error code, if this is a server rejection.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Server { code, .. } => Some(*code),
            _ => None,
        }
    }
}
