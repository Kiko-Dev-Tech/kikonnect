//! In-memory registry of tunnels (online hosts) and their players.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use kikonnect_protocol::{ErrorCode, ServerMsg, ServiceDef};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::udp::SessionMap;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Constant-time string comparison for secrets.
fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A connected player.
#[derive(Debug)]
struct PlayerEntry {
    conn: quinn::Connection,
    kick: CancellationToken,
}

#[derive(Debug, Default)]
struct TunnelInner {
    closed: bool,
    next_player_id: u32,
    players: HashMap<u32, PlayerEntry>,
}

/// An online tunnel: one host connection plus its players.
#[derive(Debug)]
pub struct Tunnel {
    /// Unique id of this tunnel instance (changes when a host reconnects).
    pub id: u64,
    /// Normalized tunnel name.
    pub name: String,
    /// The host's connection.
    pub host: quinn::Connection,
    host_out: mpsc::Sender<ServerMsg>,
    /// Services exposed by the host.
    pub services: Vec<ServiceDef>,
    password_hash: Option<String>,
    reconnect_secret: String,
    max_players: usize,
    inner: Mutex<TunnelInner>,
    /// UDP session mapping.
    pub(crate) udp: Mutex<SessionMap>,
    next_conn_id: AtomicU32,
    /// Cancelled when a newer connection of the same host took over this tunnel.
    pub evicted: CancellationToken,
}

/// Parameters for [`Tunnel::new`].
#[derive(Debug)]
pub struct TunnelParams {
    /// Normalized name.
    pub name: String,
    /// Host connection.
    pub host: quinn::Connection,
    /// Channel to the host's control stream writer.
    pub host_out: mpsc::Sender<ServerMsg>,
    /// Services.
    pub services: Vec<ServiceDef>,
    /// Argon2 PHC string of the join password.
    pub password_hash: Option<String>,
    /// Secret to reclaim the name.
    pub reconnect_secret: String,
    /// Player limit.
    pub max_players: usize,
    /// UDP session limit.
    pub max_udp_sessions: usize,
}

impl Tunnel {
    /// Creates a tunnel. `id` must be unique (see [`Registry::next_tunnel_id`]).
    pub fn new(id: u64, p: TunnelParams) -> Self {
        Self {
            id,
            name: p.name,
            host: p.host,
            host_out: p.host_out,
            services: p.services,
            password_hash: p.password_hash,
            reconnect_secret: p.reconnect_secret,
            max_players: p.max_players,
            inner: Mutex::new(TunnelInner {
                next_player_id: 1,
                ..Default::default()
            }),
            udp: Mutex::new(SessionMap::new(p.max_udp_sessions)),
            next_conn_id: AtomicU32::new(1),
            evicted: CancellationToken::new(),
        }
    }

    /// The Argon2 hash of the join password, if any.
    pub fn password_hash(&self) -> Option<&str> {
        self.password_hash.as_deref()
    }

    /// Looks up a service by id.
    pub fn service(&self, id: u8) -> Option<&ServiceDef> {
        self.services.iter().find(|s| s.id == id)
    }

    /// Allocates a new TCP connection id.
    pub fn next_conn_id(&self) -> u32 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Adds a player. Returns its id and a token that is cancelled when the player
    /// must be disconnected because the host left.
    pub fn add_player(
        &self,
        conn: quinn::Connection,
        addr: SocketAddr,
    ) -> Result<(u32, CancellationToken), ErrorCode> {
        let mut inner = lock(&self.inner);
        if inner.closed {
            return Err(ErrorCode::HostNotFound);
        }
        if inner.players.len() >= self.max_players {
            return Err(ErrorCode::TunnelFull);
        }
        let mut id = inner.next_player_id;
        while id == 0 || inner.players.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        inner.next_player_id = id.wrapping_add(1);
        let kick = CancellationToken::new();
        inner.players.insert(
            id,
            PlayerEntry {
                conn,
                kick: kick.clone(),
            },
        );
        // Best effort: never block on a slow host.
        let _ = self.host_out.try_send(ServerMsg::PlayerConnected {
            player_id: id,
            addr,
        });
        Ok((id, kick))
    }

    /// Removes a player and its UDP sessions, notifying the host.
    pub fn remove_player(&self, player_id: u32) {
        let removed = {
            let mut inner = lock(&self.inner);
            inner.players.remove(&player_id).is_some() && !inner.closed
        };
        lock(&self.udp).remove_player(player_id);
        if removed {
            let _ = self
                .host_out
                .try_send(ServerMsg::PlayerDisconnected { player_id });
        }
    }

    /// The connection of a player, if connected.
    pub fn player_conn(&self, player_id: u32) -> Option<quinn::Connection> {
        lock(&self.inner)
            .players
            .get(&player_id)
            .map(|p| p.conn.clone())
    }

    /// Number of connected players.
    pub fn player_count(&self) -> usize {
        lock(&self.inner).players.len()
    }

    /// Closes the tunnel: no new players, existing players are kicked.
    pub fn close(&self) {
        let players: Vec<PlayerEntry> = {
            let mut inner = lock(&self.inner);
            inner.closed = true;
            inner.players.drain().map(|(_, p)| p).collect()
        };
        for p in players {
            p.kick.cancel();
        }
        lock(&self.udp).clear();
    }

    /// Expires idle UDP sessions.
    pub fn expire_udp(&self, now: Instant, timeout: Duration) -> usize {
        lock(&self.udp).expire(now, timeout)
    }
}

#[derive(Debug)]
enum Slot {
    Active(Arc<Tunnel>),
    Grace { secret: String, until: Instant },
}

/// Registry of tunnel names.
#[derive(Debug)]
pub struct Registry {
    slots: Mutex<HashMap<String, Slot>>,
    next_id: AtomicU64,
    max_tunnels: usize,
    grace: Duration,
}

/// Outcome of a successful [`Registry::register`].
#[derive(Debug)]
pub struct Registration {
    /// A previous tunnel of the same host that was replaced and must be evicted.
    pub replaced: Option<Arc<Tunnel>>,
    /// Whether the name was reclaimed (grace period or replacement).
    pub reclaimed: bool,
}

impl Registry {
    /// Creates an empty registry.
    pub fn new(max_tunnels: usize, grace: Duration) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_tunnels,
            grace,
        }
    }

    /// Allocates a unique tunnel id.
    pub fn next_tunnel_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn decide(
        slots: &HashMap<String, Slot>,
        name: &str,
        secret: Option<&str>,
        now: Instant,
        max_tunnels: usize,
    ) -> Result<(bool, Option<Arc<Tunnel>>), ErrorCode> {
        let secret_ok = |s: &str| secret.is_some_and(|given| secret_eq(given, s));
        match slots.get(name) {
            Some(Slot::Active(t)) => {
                if secret_ok(&t.reconnect_secret) {
                    Ok((true, Some(t.clone())))
                } else {
                    Err(ErrorCode::NameTaken)
                }
            }
            Some(Slot::Grace { secret: s, until }) if *until > now => {
                if secret_ok(s) {
                    Ok((true, None))
                } else {
                    Err(ErrorCode::NameTaken)
                }
            }
            _ => {
                let active = slots
                    .values()
                    .filter(|s| matches!(s, Slot::Active(_)))
                    .count();
                if active >= max_tunnels {
                    Err(ErrorCode::ServerFull)
                } else {
                    Ok((false, None))
                }
            }
        }
    }

    /// Checks whether `name` could be registered right now (cheap pre-check before
    /// expensive work such as password hashing).
    pub fn check_available(
        &self,
        name: &str,
        secret: Option<&str>,
        now: Instant,
    ) -> Result<(), ErrorCode> {
        let slots = lock(&self.slots);
        Self::decide(&slots, name, secret, now, self.max_tunnels).map(|_| ())
    }

    /// Registers `tunnel` under its name.
    pub fn register(
        &self,
        tunnel: Arc<Tunnel>,
        secret: Option<&str>,
        now: Instant,
    ) -> Result<Registration, ErrorCode> {
        let mut slots = lock(&self.slots);
        let (reclaimed, replaced) =
            Self::decide(&slots, &tunnel.name, secret, now, self.max_tunnels)?;
        slots.insert(tunnel.name.clone(), Slot::Active(tunnel));
        Ok(Registration {
            replaced,
            reclaimed,
        })
    }

    /// Releases the name of `tunnel` (if it still owns it) into the grace period.
    pub fn release(&self, tunnel: &Tunnel, now: Instant) {
        let mut slots = lock(&self.slots);
        if let Some(Slot::Active(t)) = slots.get(&tunnel.name) {
            if t.id == tunnel.id {
                slots.insert(
                    tunnel.name.clone(),
                    Slot::Grace {
                        secret: tunnel.reconnect_secret.clone(),
                        until: now + self.grace,
                    },
                );
            }
        }
    }

    /// Looks up an online tunnel.
    pub fn lookup(&self, name: &str) -> Option<Arc<Tunnel>> {
        match lock(&self.slots).get(name) {
            Some(Slot::Active(t)) => Some(t.clone()),
            _ => None,
        }
    }

    /// Drops expired grace reservations.
    pub fn cleanup(&self, now: Instant) {
        lock(&self.slots).retain(|_, s| match s {
            Slot::Active(_) => true,
            Slot::Grace { until, .. } => *until > now,
        });
    }

    /// Number of online tunnels.
    pub fn active_count(&self) -> usize {
        lock(&self.slots)
            .values()
            .filter(|s| matches!(s, Slot::Active(_)))
            .count()
    }

    /// All online tunnels.
    pub fn active_tunnels(&self) -> Vec<Arc<Tunnel>> {
        lock(&self.slots)
            .values()
            .filter_map(|s| match s {
                Slot::Active(t) => Some(t.clone()),
                Slot::Grace { .. } => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::secret_eq;

    #[test]
    fn secret_comparison() {
        assert!(secret_eq("abc", "abc"));
        assert!(!secret_eq("abc", "abd"));
        assert!(!secret_eq("abc", "abcd"));
        assert!(secret_eq("", ""));
    }
}
