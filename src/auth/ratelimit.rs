use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_FAILURES: u32 = 5;
/// One account, from any number of addresses. Higher than for one address, since anyone can spend
/// these and lock its owner out of signing in for the window.
const MAX_ACCOUNT_FAILURES: u32 = 20;
const WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_TRACKED: usize = 10_000;

#[derive(PartialEq, Eq, Hash, Clone)]
enum Key {
    Address(IpAddr),
    Account(String),
    /// The second step, where the password is known already, so a guess is worth far more.
    SecondStep(i64),
}

/// The address a client is counted under. Anyone with IPv6 usually has a whole /64 to pick from.
fn address_key(ip: IpAddr) -> Key {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut bytes = v6.octets();
            bytes[8..].fill(0);
            Key::Address(IpAddr::from(bytes))
        }
        v4 => Key::Address(v4),
    }
}

fn account_key(username: &str) -> Key {
    Key::Account(username.trim().to_lowercase())
}

/// Failed sign-in limiter (in memory). A try counts from before its password is checked, which takes
/// long enough that otherwise any number could be under way at once before the first one was counted.
#[derive(Default)]
pub struct LoginLimiter {
    entries: Mutex<HashMap<Key, (u32, Instant)>>,
}

impl LoginLimiter {
    fn locked(map: &HashMap<Key, (u32, Instant)>, key: &Key, max: u32) -> Option<u64> {
        let (count, start) = map.get(key)?;
        let elapsed = start.elapsed();
        (*count >= max && elapsed < WINDOW).then(|| (WINDOW - elapsed).as_secs().max(1))
    }

    fn count(map: &mut HashMap<Key, (u32, Instant)>, key: Key) {
        if map.len() >= MAX_TRACKED {
            map.retain(|_, (_, start)| start.elapsed() < WINDOW);
        }
        // Everything is live: forget whatever is closest to being forgotten anyway.
        if map.len() >= MAX_TRACKED {
            let oldest = map.iter().min_by_key(|(_, (_, start))| *start).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                map.remove(&k);
            }
        }
        let entry = map.entry(key).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    fn uncount(map: &mut HashMap<Key, (u32, Instant)>, key: &Key) {
        if let Some(entry) = map.get_mut(key) {
            entry.0 = entry.0.saturating_sub(1);
        }
    }

    /// `Err(seconds_remaining)` if this client's address is locked out.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Self::locked(&map, &address_key(ip), MAX_FAILURES).map_or(Ok(()), Err)
    }

    /// A password is about to be checked. `Err(seconds_remaining)` if it mustn't be.
    ///
    /// The limit per account doesn't apply on this machine. That's how an admin gets back in, over
    /// an SSH tunnel, while someone elsewhere is using it up, and the limit per address still does.
    pub fn begin_password(&self, ip: IpAddr, username: &str) -> Result<(), u64> {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let address = address_key(ip);
        let local = ip.to_canonical().is_loopback();
        if let Some(wait) = Self::locked(&map, &address, MAX_FAILURES) {
            return Err(wait);
        }
        if !local {
            if let Some(wait) = Self::locked(&map, &account_key(username), MAX_ACCOUNT_FAILURES) {
                return Err(wait);
            }
            Self::count(&mut map, account_key(username));
        }
        Self::count(&mut map, address);
        Ok(())
    }

    /// The password was right, so that try doesn't count. Failures before it still do: a client can't
    /// clear its guesses at someone else's account by signing in to its own.
    pub fn password_ok(&self, ip: IpAddr, username: &str) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Self::uncount(&mut map, &address_key(ip));
        if !ip.to_canonical().is_loopback() {
            map.remove(&account_key(username));
        }
    }

    /// A code is about to be checked for this account, wherever from.
    pub fn begin_second_step(&self, ip: IpAddr, user_id: i64) -> Result<(), u64> {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let address = address_key(ip);
        let key = Key::SecondStep(user_id);
        for (k, max) in [(&address, MAX_FAILURES), (&key, MAX_FAILURES)] {
            if let Some(wait) = Self::locked(&map, k, max) {
                return Err(wait);
            }
        }
        Self::count(&mut map, address);
        Self::count(&mut map, key);
        Ok(())
    }

    pub fn second_step_ok(&self, ip: IpAddr, user_id: i64) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Self::uncount(&mut map, &address_key(ip));
        map.remove(&Key::SecondStep(user_id));
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
            assert!(l.begin_password(ip, "admin").is_ok());
        }
        assert!(l.check(ip).is_err());
        assert!(l.begin_password(ip, "admin").is_err());
    }

    #[test]
    fn a_right_password_gives_back_only_its_own_try() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..4 {
            l.begin_password(ip, "someone").unwrap();
        }
        l.begin_password(ip, "me").unwrap();
        l.password_ok(ip, "me");
        l.begin_password(ip, "someone").unwrap();
        assert!(l.check(ip).is_err());
    }

    #[test]
    fn an_account_can_be_locked_from_many_addresses_but_not_for_this_machine() {
        let l = LoginLimiter::default();
        for i in 0..MAX_ACCOUNT_FAILURES {
            let ip: IpAddr = format!("10.0.1.{i}").parse().unwrap();
            l.begin_password(ip, "Admin").unwrap();
        }
        let elsewhere: IpAddr = "10.0.2.1".parse().unwrap();
        assert!(l.begin_password(elsewhere, "admin").is_err());
        assert!(l.begin_password(elsewhere, "someone-else").is_ok());
        assert!(l.begin_password("127.0.0.1".parse().unwrap(), "admin").is_ok());
    }

    #[test]
    fn addresses_are_counted_by_network() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(address_key(a) == address_key(b));
        assert!(address_key(a) != address_key(other));
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(address_key(v4) == address_key(mapped));
    }

    #[test]
    fn the_second_step_is_limited_per_account_and_a_right_code_clears_it() {
        let l = LoginLimiter::default();
        for i in 0..MAX_FAILURES {
            let ip: IpAddr = format!("10.0.3.{i}").parse().unwrap();
            l.begin_second_step(ip, 7).unwrap();
        }
        let ip: IpAddr = "10.0.3.100".parse().unwrap();
        assert!(l.begin_second_step(ip, 7).is_err());
        assert!(l.begin_second_step(ip, 8).is_ok());
        l.second_step_ok(ip, 7);
        assert!(l.begin_second_step(ip, 7).is_ok());
    }

    #[test]
    fn the_table_stays_bounded() {
        let l = LoginLimiter::default();
        for i in 0..(MAX_TRACKED + 50) {
            let ip = IpAddr::from([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            let _ = l.begin_password(ip, "x");
        }
        assert!(l.entries.lock().unwrap().len() <= MAX_TRACKED);
    }
}
