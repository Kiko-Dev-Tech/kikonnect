//! UI-independent view state, updated from worker events.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use kikonnect_client_core::{
    HostEvent, HostStatus, PlayerEvent, PlayerExit, ServiceDef, ServiceKind,
};

use crate::worker::Event;

/// A player connected to the hosted tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayerRow {
    pub player_id: u32,
    pub addr: SocketAddr,
    pub since: SystemTime,
}

/// Host tab state.
#[derive(Debug, Default)]
pub struct HostState {
    /// `None` while not running.
    pub status: Option<HostStatus>,
    /// A stop was requested and the task has not finished yet.
    pub stopping: bool,
    pub players: Vec<PlayerRow>,
    pub latency: Option<Duration>,
    /// Message of the last failure (kept after the host stopped).
    pub last_error: Option<String>,
}

impl HostState {
    /// Whether a host task is active (including reconnect waits).
    pub fn running(&self) -> bool {
        self.status.is_some() || self.stopping
    }

    /// The name others can join, if online.
    pub fn online_name(&self) -> Option<&str> {
        match &self.status {
            Some(HostStatus::Online { name }) => Some(name),
            _ => None,
        }
    }
}

/// One service of the joined tunnel.
#[derive(Debug, Clone)]
pub struct JoinService {
    pub def: ServiceDef,
    /// Text of the editable local port field.
    pub port_text: String,
    /// Where the service is currently reachable locally.
    pub local: Option<SocketAddr>,
    pub error: Option<String>,
}

impl JoinService {
    /// The "connect your game to ..." line, once the listener is up.
    pub fn instruction(&self) -> Option<String> {
        let local = self.local?;
        let proto = match self.def.kind {
            ServiceKind::Tcp => "TCP",
            ServiceKind::Udp => "UDP",
        };
        let mut text = format!("Connect your game to localhost:{} ({proto})", local.port());
        if local.port() != self.def.port {
            text.push_str(&format!(
                " - port {} was busy, using {} instead",
                self.def.port,
                local.port()
            ));
        }
        Some(text)
    }
}

/// Phase of the join tab.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum JoinPhase {
    #[default]
    Idle,
    Connecting,
    Joined,
}

/// Join tab state.
#[derive(Debug, Default)]
pub struct JoinState {
    pub phase: JoinPhase,
    pub stopping: bool,
    pub host_name: String,
    pub services: Vec<JoinService>,
    pub latency: Option<Duration>,
    pub message: Option<String>,
}

/// All state derived from worker events.
#[derive(Debug, Default)]
pub struct State {
    pub host: HostState,
    pub join: JoinState,
}

impl State {
    /// Applies one worker event.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Host(e) => self.apply_host(e),
            Event::HostEnded => {
                self.host.status = None;
                self.host.stopping = false;
                self.host.players.clear();
                self.host.latency = None;
            }
            Event::Joined {
                host_name,
                services,
            } => {
                self.join.phase = JoinPhase::Joined;
                self.join.host_name = host_name;
                self.join.message = None;
                self.join.services = services
                    .into_iter()
                    .map(|def| JoinService {
                        port_text: def.port.to_string(),
                        def,
                        local: None,
                        error: None,
                    })
                    .collect();
            }
            Event::JoinFailed(msg) => {
                self.join = JoinState {
                    message: Some(msg),
                    ..JoinState::default()
                };
            }
            Event::Player(e) => self.apply_player(e),
            Event::JoinEnded(result) => {
                let message = match result {
                    Ok(PlayerExit::Cancelled) => None,
                    Ok(PlayerExit::HostGone) => Some("The host left.".to_owned()),
                    Err(e) => Some(e),
                };
                self.join = JoinState {
                    message,
                    ..JoinState::default()
                };
            }
        }
    }

    fn apply_host(&mut self, event: HostEvent) {
        let host = &mut self.host;
        match event {
            HostEvent::Status(status) => {
                host.last_error = match &status {
                    HostStatus::Failed(msg) => Some(msg.clone()),
                    _ => None,
                };
                if !matches!(status, HostStatus::Online { .. }) {
                    host.players.clear();
                    host.latency = None;
                }
                // Terminal states are cleared by `HostEnded`; keep the failure visible.
                host.status = match status {
                    HostStatus::Stopped => None,
                    other => Some(other),
                };
            }
            HostEvent::PlayerConnected {
                player_id,
                addr,
                since,
            } => {
                host.players.retain(|p| p.player_id != player_id);
                host.players.push(PlayerRow {
                    player_id,
                    addr,
                    since,
                });
            }
            HostEvent::PlayerDisconnected { player_id } => {
                host.players.retain(|p| p.player_id != player_id);
            }
            HostEvent::Latency(rtt) => host.latency = Some(rtt),
        }
    }

    fn apply_player(&mut self, event: PlayerEvent) {
        let join = &mut self.join;
        match event {
            PlayerEvent::Forwarding {
                service_id,
                local_addr,
            } => {
                if let Some(s) = join.services.iter_mut().find(|s| s.def.id == service_id) {
                    s.local = Some(local_addr);
                    s.port_text = local_addr.port().to_string();
                    s.error = None;
                }
            }
            PlayerEvent::ForwardFailed { service_id, error } => {
                if let Some(s) = join.services.iter_mut().find(|s| s.def.id == service_id) {
                    s.local = None;
                    s.error = Some(error);
                }
            }
            PlayerEvent::Latency(rtt) => join.latency = Some(rtt),
            PlayerEvent::HostGone => join.message = Some("The host left.".to_owned()),
        }
    }
}

/// Human readable "5 min ago" style duration.
pub fn format_ago(since: SystemTime, now: SystemTime) -> String {
    let secs = now.duration_since(since).map(|d| d.as_secs()).unwrap_or(0);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{} min ago", secs / 60),
        _ => format!("{} h {} min ago", secs / 3600, secs % 3600 / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(id: u8, port: u16) -> ServiceDef {
        ServiceDef {
            id,
            kind: ServiceKind::Tcp,
            label: "Minecraft".into(),
            port,
        }
    }

    #[test]
    fn host_lifecycle() {
        let mut s = State::default();
        assert!(!s.host.running());
        s.apply(Event::Host(HostEvent::Status(HostStatus::Connecting)));
        assert!(s.host.running());
        s.apply(Event::Host(HostEvent::Status(HostStatus::Online {
            name: "kilian".into(),
        })));
        assert_eq!(s.host.online_name(), Some("kilian"));
        let addr: SocketAddr = "1.2.3.4:5".parse().unwrap();
        s.apply(Event::Host(HostEvent::PlayerConnected {
            player_id: 1,
            addr,
            since: SystemTime::now(),
        }));
        assert_eq!(s.host.players.len(), 1);
        s.apply(Event::Host(HostEvent::Status(HostStatus::Reconnecting {
            attempt: 1,
            delay: Duration::from_secs(1),
            reason: "lost".into(),
        })));
        assert!(s.host.players.is_empty(), "players cleared when offline");
        s.apply(Event::Host(HostEvent::Status(HostStatus::Failed(
            "boom".into(),
        ))));
        s.apply(Event::HostEnded);
        assert!(!s.host.running());
        assert_eq!(s.host.last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn join_flow_and_busy_port_hint() {
        let mut s = State::default();
        s.apply(Event::Joined {
            host_name: "kilian".into(),
            services: vec![svc(0, 25565)],
        });
        assert_eq!(s.join.phase, JoinPhase::Joined);
        assert!(s.join.services[0].instruction().is_none());
        s.apply(Event::Player(PlayerEvent::Forwarding {
            service_id: 0,
            local_addr: "127.0.0.1:25566".parse().unwrap(),
        }));
        let text = s.join.services[0].instruction().unwrap();
        assert!(text.contains("localhost:25566"));
        assert!(text.contains("25565 was busy"));
        s.apply(Event::JoinEnded(Ok(PlayerExit::HostGone)));
        assert_eq!(s.join.phase, JoinPhase::Idle);
        assert_eq!(s.join.message.as_deref(), Some("The host left."));
    }

    #[test]
    fn ago_format() {
        let now = SystemTime::now();
        assert_eq!(format_ago(now - Duration::from_secs(5), now), "5s ago");
        assert_eq!(format_ago(now - Duration::from_secs(120), now), "2 min ago");
        assert_eq!(
            format_ago(now - Duration::from_secs(3720), now),
            "1 h 2 min ago"
        );
    }
}
