use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_TRACKED: usize = 10_000;

/// Per-IP failed-login limiter (in memory).
#[derive(Default)]
pub struct LoginLimiter {
    entries: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginLimiter {
    /// Returns `Err(seconds_remaining)` when the IP is currently locked out.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((count, start)) = map.get(&ip) {
            let elapsed = start.elapsed();
            if *count >= MAX_FAILURES && elapsed < WINDOW {
                return Err((WINDOW - elapsed).as_secs().max(1));
            }
        }
        Ok(())
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_TRACKED {
            map.retain(|_, (_, start)| start.elapsed() < WINDOW);
        }
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    pub fn reset(&self, ip: IpAddr) {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_max_failures() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(l.check(ip).is_ok());
            l.record_failure(ip);
        }
        assert!(l.check(ip).is_err());
        l.reset(ip);
        assert!(l.check(ip).is_ok());
    }
}
