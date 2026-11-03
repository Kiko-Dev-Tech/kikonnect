//! UDP session id mapping.
//!
//! Each player numbers its UDP sessions locally. The server maps every
//! `(player_id, local_session_id)` pair to a session id that is unique within the
//! tunnel before forwarding datagrams to the host, and maps replies back.

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
struct GlobalEntry {
    player_id: u32,
    local_id: u32,
    last_active: Instant,
}

/// Bidirectional mapping between player-local and tunnel-global session ids.
#[derive(Debug)]
pub struct SessionMap {
    by_player: HashMap<(u32, u32), u32>,
    by_global: HashMap<u32, GlobalEntry>,
    next_global: u32,
    max_sessions: usize,
}

impl SessionMap {
    /// Creates an empty map holding at most `max_sessions` sessions.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            by_player: HashMap::new(),
            by_global: HashMap::new(),
            next_global: 1,
            max_sessions,
        }
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.by_global.len()
    }

    /// Whether there are no sessions.
    pub fn is_empty(&self) -> bool {
        self.by_global.is_empty()
    }

    /// Returns the global id for a player's local session, creating a mapping if
    /// necessary. Returns `None` if the session limit is reached.
    pub fn to_global(&mut self, player_id: u32, local_id: u32, now: Instant) -> Option<u32> {
        if let Some(&global) = self.by_player.get(&(player_id, local_id)) {
            if let Some(entry) = self.by_global.get_mut(&global) {
                entry.last_active = now;
            }
            return Some(global);
        }
        if self.by_global.len() >= self.max_sessions {
            return None;
        }
        // Find a free id. There are at most `max_sessions` (<< 2^32) ids in use, so
        // this terminates quickly.
        let mut global = self.next_global;
        while global == 0 || self.by_global.contains_key(&global) {
            global = global.wrapping_add(1);
        }
        self.next_global = global.wrapping_add(1);
        self.by_player.insert((player_id, local_id), global);
        self.by_global.insert(
            global,
            GlobalEntry {
                player_id,
                local_id,
                last_active: now,
            },
        );
        Some(global)
    }

    /// Maps a global session id back to `(player_id, local_session_id)`.
    pub fn to_player(&mut self, global: u32, now: Instant) -> Option<(u32, u32)> {
        let entry = self.by_global.get_mut(&global)?;
        entry.last_active = now;
        Some((entry.player_id, entry.local_id))
    }

    /// Removes sessions idle for longer than `timeout`. Returns how many were removed.
    pub fn expire(&mut self, now: Instant, timeout: Duration) -> usize {
        let before = self.by_global.len();
        let by_player = &mut self.by_player;
        self.by_global.retain(|_, e| {
            let keep = now.saturating_duration_since(e.last_active) < timeout;
            if !keep {
                by_player.remove(&(e.player_id, e.local_id));
            }
            keep
        });
        before - self.by_global.len()
    }

    /// Removes all sessions of a player. Returns how many were removed.
    pub fn remove_player(&mut self, player_id: u32) -> usize {
        let before = self.by_global.len();
        let by_player = &mut self.by_player;
        self.by_global.retain(|_, e| {
            let keep = e.player_id != player_id;
            if !keep {
                by_player.remove(&(e.player_id, e.local_id));
            }
            keep
        });
        before - self.by_global.len()
    }

    /// Removes all sessions.
    pub fn clear(&mut self) {
        self.by_player.clear();
        self.by_global.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_both_directions_and_is_unique_per_player() {
        let mut m = SessionMap::new(16);
        let now = Instant::now();
        // Two players use the same local session id 1.
        let g1 = m.to_global(1, 1, now).unwrap();
        let g2 = m.to_global(2, 1, now).unwrap();
        assert_ne!(g1, g2);
        assert_eq!(m.to_global(1, 1, now), Some(g1));
        assert_eq!(m.to_player(g1, now), Some((1, 1)));
        assert_eq!(m.to_player(g2, now), Some((2, 1)));
        assert_eq!(m.to_player(9999, now), None);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn limit_is_enforced() {
        let mut m = SessionMap::new(2);
        let now = Instant::now();
        assert!(m.to_global(1, 1, now).is_some());
        assert!(m.to_global(1, 2, now).is_some());
        assert!(m.to_global(1, 3, now).is_none());
        // Existing sessions still resolve.
        assert!(m.to_global(1, 1, now).is_some());
    }

    #[test]
    fn expiry_respects_activity() {
        let mut m = SessionMap::new(16);
        let t0 = Instant::now();
        let a = m.to_global(1, 1, t0).unwrap();
        let b = m.to_global(1, 2, t0).unwrap();
        // Touch `a` via a reply at t0 + 40s.
        m.to_player(a, t0 + Duration::from_secs(40));
        assert_eq!(
            m.expire(t0 + Duration::from_secs(61), Duration::from_secs(60)),
            1
        );
        assert_eq!(m.to_player(b, t0), None);
        assert!(m.to_player(a, t0 + Duration::from_secs(61)).is_some());
        // The local id of the expired session gets a fresh global id.
        let b2 = m.to_global(1, 2, t0 + Duration::from_secs(62)).unwrap();
        assert_ne!(b2, a);
    }

    #[test]
    fn remove_player_only_removes_that_player() {
        let mut m = SessionMap::new(16);
        let now = Instant::now();
        let a = m.to_global(1, 1, now).unwrap();
        m.to_global(1, 2, now).unwrap();
        let c = m.to_global(2, 1, now).unwrap();
        assert_eq!(m.remove_player(1), 2);
        assert_eq!(m.to_player(a, now), None);
        assert_eq!(m.to_player(c, now), Some((2, 1)));
        m.clear();
        assert!(m.is_empty());
    }

    #[test]
    fn global_ids_skip_zero_and_in_use_ids_on_wrap() {
        let mut m = SessionMap::new(16);
        let now = Instant::now();
        m.next_global = u32::MAX;
        let a = m.to_global(1, 1, now).unwrap();
        assert_eq!(a, u32::MAX);
        let b = m.to_global(1, 2, now).unwrap();
        assert_eq!(b, 1, "0 is skipped after wrapping");
        m.next_global = u32::MAX;
        let c = m.to_global(1, 3, now).unwrap();
        assert_eq!(c, 2, "ids in use are skipped");
    }
}
