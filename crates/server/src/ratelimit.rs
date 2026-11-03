//! Per-IP token bucket rate limiter for `Register` and `Join`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Upper bound on tracked IPs. When exceeded, full buckets are purged; if that is
/// not enough, new IPs are rate limited until entries expire.
const MAX_TRACKED_IPS: usize = 100_000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token bucket rate limiter keyed by source IP.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// Creates a limiter allowing bursts of `burst` requests and refilling
    /// `per_minute` tokens per minute. `per_minute == 0` disables limiting.
    pub fn new(burst: u32, per_minute: u32) -> Self {
        Self {
            capacity: f64::from(burst.max(1)),
            refill_per_sec: f64::from(per_minute) / 60.0,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn enabled(&self) -> bool {
        self.refill_per_sec > 0.0
    }

    /// Takes one token for `ip`. Returns `false` if the request must be rejected.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// Like [`check`](Self::check) with an explicit clock, for tests.
    pub fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled() {
            return true;
        }
        let ip = ip.to_canonical();
        let mut buckets = lock(&self.buckets);
        if buckets.len() >= MAX_TRACKED_IPS && !buckets.contains_key(&ip) {
            self.purge_full(&mut buckets, now);
            if buckets.len() >= MAX_TRACKED_IPS {
                return false;
            }
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Removes buckets that have refilled completely (they carry no information).
    pub fn cleanup(&self, now: Instant) {
        let mut buckets = lock(&self.buckets);
        self.purge_full(&mut buckets, now);
    }

    fn purge_full(&self, buckets: &mut HashMap<IpAddr, Bucket>, now: Instant) {
        buckets.retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
            b.tokens + elapsed * self.refill_per_sec < self.capacity
        });
    }

    /// Number of tracked IPs.
    pub fn tracked(&self) -> usize {
        lock(&self.buckets).len()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_refill() {
        let rl = RateLimiter::new(3, 60); // 1 token per second
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(rl.check_at(ip, t0));
        assert!(rl.check_at(ip, t0));
        assert!(rl.check_at(ip, t0));
        assert!(!rl.check_at(ip, t0));
        assert!(!rl.check_at(ip, t0 + Duration::from_millis(500)));
        assert!(rl.check_at(ip, t0 + Duration::from_millis(1600)));
        assert!(!rl.check_at(ip, t0 + Duration::from_millis(1700)));
        // Long pause refills only up to capacity.
        let t1 = t0 + Duration::from_secs(100);
        assert!(rl.check_at(ip, t1));
        assert!(rl.check_at(ip, t1));
        assert!(rl.check_at(ip, t1));
        assert!(!rl.check_at(ip, t1));
    }

    #[test]
    fn ips_are_independent_and_v4_mapped_is_canonical() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let a_mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(rl.check_at(a, t0));
        assert!(!rl.check_at(a_mapped, t0));
        assert!(rl.check_at(b, t0));
    }

    #[test]
    fn disabled_limiter_allows_everything() {
        let rl = RateLimiter::new(1, 0);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..100 {
            assert!(rl.check(ip));
        }
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn cleanup_removes_full_buckets() {
        let rl = RateLimiter::new(2, 60);
        let t0 = Instant::now();
        rl.check_at("10.0.0.1".parse().unwrap(), t0);
        rl.check_at("10.0.0.2".parse().unwrap(), t0);
        assert_eq!(rl.tracked(), 2);
        rl.cleanup(t0);
        assert_eq!(rl.tracked(), 2);
        rl.cleanup(t0 + Duration::from_secs(5));
        assert_eq!(rl.tracked(), 0);
    }
}
