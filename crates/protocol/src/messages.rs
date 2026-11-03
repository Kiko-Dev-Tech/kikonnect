//! Control-stream messages and data-stream headers.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::constants::{MAX_LABEL_LEN, MAX_SERVICES};

/// Which side of a tunnel a client is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Shares local game servers.
    Host,
    /// Connects to a host's game servers.
    Player,
}

/// Transport of a forwarded service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceKind {
    /// TCP, carried over QUIC bidirectional streams.
    Tcp,
    /// UDP, carried over QUIC datagrams.
    Udp,
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceKind::Tcp => f.write_str("TCP"),
            ServiceKind::Udp => f.write_str("UDP"),
        }
    }
}

/// A service (local port) exposed by a host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceDef {
    /// Identifier, unique within the tunnel.
    pub id: u8,
    /// TCP or UDP.
    pub kind: ServiceKind,
    /// Human readable label, e.g. `"Minecraft"`.
    pub label: String,
    /// The host's local port. Players use it as the suggested local port.
    pub port: u16,
}

/// Validates a list of service definitions sent by a host.
///
/// Rules: 1 to [`MAX_SERVICES`] services, unique ids, non-zero ports, labels of at
/// most [`MAX_LABEL_LEN`] bytes, and no duplicate `(kind, port)` pairs.
pub fn validate_services(services: &[ServiceDef]) -> Result<(), String> {
    if services.is_empty() {
        return Err("at least one service is required".into());
    }
    if services.len() > MAX_SERVICES {
        return Err(format!("at most {MAX_SERVICES} services are allowed"));
    }
    let mut ids = HashSet::new();
    let mut ports = HashSet::new();
    for s in services {
        if !ids.insert(s.id) {
            return Err(format!("duplicate service id {}", s.id));
        }
        if s.port == 0 {
            return Err(format!("service '{}' has port 0", s.label));
        }
        if s.label.len() > MAX_LABEL_LEN {
            return Err(format!("service label longer than {MAX_LABEL_LEN} bytes"));
        }
        if !ports.insert((s.kind, s.port)) {
            return Err(format!("duplicate {} port {}", s.kind, s.port));
        }
    }
    Ok(())
}

/// Messages sent by a client on its control stream.
///
/// `Debug` is implemented manually so that passwords and secrets are never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// Always the first message. MUST remain the first variant (see crate docs).
    Hello {
        /// The client's [`crate::PROTOCOL_VERSION`].
        protocol_version: u16,
        /// Host or player.
        role: Role,
        /// Free-form client software version, for logs and error messages.
        client_version: String,
    },
    /// Host: register a tunnel under `name`.
    Register {
        /// Requested tunnel name (see [`crate::normalize_name`]).
        name: String,
        /// Optional join password players must provide.
        password: Option<String>,
        /// Services exposed through the tunnel.
        services: Vec<ServiceDef>,
        /// Secret from a previous `Registered` to reclaim the name during the grace
        /// period (or to replace a stale connection of the same host).
        reconnect_secret: Option<String>,
    },
    /// Player: join the tunnel called `name`.
    Join {
        /// Tunnel name.
        name: String,
        /// Join password, if the host set one.
        password: Option<String>,
    },
    /// Latency probe; answered with [`ServerMsg::Pong`].
    Ping {
        /// Opaque value echoed back by the server.
        nonce: u64,
    },
}

impl fmt::Debug for ClientMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientMsg::Hello {
                protocol_version,
                role,
                client_version,
            } => f
                .debug_struct("Hello")
                .field("protocol_version", protocol_version)
                .field("role", role)
                .field("client_version", client_version)
                .finish(),
            ClientMsg::Register {
                name,
                password,
                services,
                reconnect_secret,
            } => f
                .debug_struct("Register")
                .field("name", name)
                .field("password", &password.as_ref().map(|_| "<redacted>"))
                .field("services", services)
                .field(
                    "reconnect_secret",
                    &reconnect_secret.as_ref().map(|_| "<redacted>"),
                )
                .finish(),
            ClientMsg::Join { name, password } => f
                .debug_struct("Join")
                .field("name", name)
                .field("password", &password.as_ref().map(|_| "<redacted>"))
                .finish(),
            ClientMsg::Ping { nonce } => f.debug_struct("Ping").field("nonce", nonce).finish(),
        }
    }
}

/// Messages sent by the server on a client's control stream.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMsg {
    /// The `Hello` was accepted.
    HelloOk {
        /// Server software version, informational.
        server_version: String,
    },
    /// Host: the tunnel is online.
    Registered {
        /// The normalized tunnel name.
        name: String,
        /// Secret to reclaim the name after a disconnect.
        reconnect_secret: String,
    },
    /// Player: joined the tunnel.
    Joined {
        /// The normalized tunnel name.
        host_name: String,
        /// Services exposed by the host.
        services: Vec<ServiceDef>,
        /// This player's id within the tunnel.
        player_id: u32,
    },
    /// To host: a player joined.
    PlayerConnected {
        /// Player id within the tunnel.
        player_id: u32,
        /// The player's public address as seen by the server.
        addr: SocketAddr,
    },
    /// To host: a player left.
    PlayerDisconnected {
        /// Player id within the tunnel.
        player_id: u32,
    },
    /// To player: the host left; the tunnel is closed.
    HostGone,
    /// Answer to [`ClientMsg::Ping`].
    Pong {
        /// The nonce from the ping.
        nonce: u64,
    },
    /// The request failed. The server closes the connection afterwards.
    Error {
        /// Machine readable error.
        code: ErrorCode,
        /// Human readable explanation.
        message: String,
    },
    /// The server is shutting down; the connection will be closed.
    ShuttingDown,
}

impl fmt::Debug for ServerMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerMsg::HelloOk { server_version } => f
                .debug_struct("HelloOk")
                .field("server_version", server_version)
                .finish(),
            ServerMsg::Registered { name, .. } => f
                .debug_struct("Registered")
                .field("name", name)
                .field("reconnect_secret", &"<redacted>")
                .finish(),
            ServerMsg::Joined {
                host_name,
                services,
                player_id,
            } => f
                .debug_struct("Joined")
                .field("host_name", host_name)
                .field("services", services)
                .field("player_id", player_id)
                .finish(),
            ServerMsg::PlayerConnected { player_id, addr } => f
                .debug_struct("PlayerConnected")
                .field("player_id", player_id)
                .field("addr", addr)
                .finish(),
            ServerMsg::PlayerDisconnected { player_id } => f
                .debug_struct("PlayerDisconnected")
                .field("player_id", player_id)
                .finish(),
            ServerMsg::HostGone => f.write_str("HostGone"),
            ServerMsg::Pong { nonce } => f.debug_struct("Pong").field("nonce", nonce).finish(),
            ServerMsg::Error { code, message } => f
                .debug_struct("Error")
                .field("code", code)
                .field("message", message)
                .finish(),
            ServerMsg::ShuttingDown => f.write_str("ShuttingDown"),
        }
    }
}

/// Machine readable error codes in [`ServerMsg::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Client and server protocol versions are incompatible.
    VersionMismatch,
    /// The name is in use (or reserved for its previous host during the grace period).
    NameTaken,
    /// The name violates the naming rules.
    InvalidName,
    /// No host with that name is online.
    HostNotFound,
    /// The join password is wrong or missing.
    WrongPassword,
    /// The tunnel has reached its maximum number of players.
    TunnelFull,
    /// Too many requests from this IP address; try again later.
    RateLimited,
    /// Internal server error.
    Internal,
    /// The server has reached its maximum number of tunnels.
    ServerFull,
    /// The request was malformed (unexpected message, invalid services, ...).
    InvalidRequest,
    /// This host connection was replaced by a newer connection with the same
    /// reconnect secret.
    Replaced,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ErrorCode::VersionMismatch => "version mismatch",
            ErrorCode::NameTaken => "name taken",
            ErrorCode::InvalidName => "invalid name",
            ErrorCode::HostNotFound => "host not found",
            ErrorCode::WrongPassword => "wrong password",
            ErrorCode::TunnelFull => "tunnel full",
            ErrorCode::RateLimited => "rate limited",
            ErrorCode::Internal => "internal error",
            ErrorCode::ServerFull => "server full",
            ErrorCode::InvalidRequest => "invalid request",
            ErrorCode::Replaced => "replaced",
        };
        f.write_str(s)
    }
}

/// First frame on a bidirectional stream opened by a player for a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamHeader {
    /// The TCP service this connection is for.
    pub service_id: u8,
}

/// First frame on a bidirectional stream opened by the server towards the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostStreamHeader {
    /// The TCP service this connection is for.
    pub service_id: u8,
    /// Server-assigned connection id, unique within the tunnel.
    pub conn_id: u32,
    /// The player that opened the connection.
    pub player_id: u32,
    /// The player's public address.
    pub player_addr: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(id: u8, kind: ServiceKind, port: u16) -> ServiceDef {
        ServiceDef {
            id,
            kind,
            label: "x".into(),
            port,
        }
    }

    #[test]
    fn services_validation() {
        assert!(validate_services(&[]).is_err());
        assert!(validate_services(&[svc(0, ServiceKind::Tcp, 25565)]).is_ok());
        // Same port on TCP and UDP is fine.
        assert!(validate_services(&[
            svc(0, ServiceKind::Tcp, 25565),
            svc(1, ServiceKind::Udp, 25565)
        ])
        .is_ok());
        assert!(validate_services(&[
            svc(0, ServiceKind::Tcp, 25565),
            svc(0, ServiceKind::Udp, 19132)
        ])
        .is_err());
        assert!(validate_services(&[
            svc(0, ServiceKind::Tcp, 25565),
            svc(1, ServiceKind::Tcp, 25565)
        ])
        .is_err());
        assert!(validate_services(&[svc(0, ServiceKind::Tcp, 0)]).is_err());
        let many: Vec<_> = (0..=MAX_SERVICES as u8)
            .map(|i| svc(i, ServiceKind::Tcp, 1000 + u16::from(i)))
            .collect();
        assert!(validate_services(&many).is_err());
    }

    #[test]
    fn debug_redacts_secrets() {
        let msg = ClientMsg::Register {
            name: "kilian".into(),
            password: Some("hunter2".into()),
            services: vec![],
            reconnect_secret: Some("s3cret".into()),
        };
        let s = format!("{msg:?}");
        assert!(!s.contains("hunter2"));
        assert!(!s.contains("s3cret"));
        let s = format!(
            "{:?}",
            ClientMsg::Join {
                name: "kilian".into(),
                password: Some("hunter2".into())
            }
        );
        assert!(!s.contains("hunter2"));
        let s = format!(
            "{:?}",
            ServerMsg::Registered {
                name: "kilian".into(),
                reconnect_secret: "s3cret".into()
            }
        );
        assert!(!s.contains("s3cret"));
    }
}
