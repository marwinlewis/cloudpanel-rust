//! The address ranges Cloudflare connects from, which decide who may name the client with
//! `CF-Connecting-IP`. Anyone who reaches the server directly can send that header, so it only
//! counts on a connection from one of these ranges. Cloudflare replaces whatever a visitor sent.
//!
//! The list comes from Cloudflare's API and is refreshed daily, because a range missing here
//! would group that edge's visitors under one address again. The built-in copy is only for the
//! time before the first refresh succeeds, and the panel reports which list it is using.

use super::panel_cert;
use crate::db;
use crate::state::SharedState;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub const SETTING: &str = "cloudflare_ranges";
pub const DEFAULT_URL: &str = "https://api.cloudflare.com/client/v4/ips";

/// From https://www.cloudflare.com/ips/, checked against the API on 2026-11-07.
const BUILT_IN: [&str; 22] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

const REFRESH_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);
const STALE_AFTER_DAYS: i64 = 7;
const MAX_RANGES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    /// Parses one range, refusing any that can't be Cloudflare's. A list saying `0.0.0.0/0`, or
    /// one covering this machine, would let anybody choose their own address.
    fn parse(s: &str) -> Option<Net> {
        let (addr, prefix) = s.trim().split_once('/')?;
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let (plausible, tidy) = match addr {
            IpAddr::V4(ip) => (
                (8..=32).contains(&prefix) && public_v4(ip),
                u32::from(ip) & !mask_v4(prefix) == 0,
            ),
            IpAddr::V6(ip) => (
                (24..=128).contains(&prefix) && public_v6(ip),
                u128::from(ip) & !mask_v6(prefix) == 0,
            ),
        };
        (plausible && tidy).then_some(Net { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => (u32::from(net) ^ u32::from(ip)) & mask_v4(self.prefix) == 0,
            (IpAddr::V6(net), IpAddr::V6(ip)) => (u128::from(net) ^ u128::from(ip)) & mask_v6(self.prefix) == 0,
            _ => false,
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

// Clamped because Net::parse works these out before refusing a bad prefix, and a shift by the
// full width would overflow.
fn mask_v4(prefix: u8) -> u32 {
    u32::MAX << (32 - u32::from(prefix.clamp(1, 32)))
}

fn mask_v6(prefix: u8) -> u128 {
    u128::MAX << (128 - u32::from(prefix.clamp(1, 128)))
}

fn public_v4(ip: Ipv4Addr) -> bool {
    !(ip.octets()[0] == 0 || ip.is_loopback() || ip.is_private() || ip.is_link_local())
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.to_ipv4_mapped().is_some()
        || first & 0xfe00 == 0xfc00 // unique local
        || first & 0xffc0 == 0xfe80) // link local
}

/// A whole list, in a fixed order so an unchanged list renders the same nginx config. All of it
/// must be good: a list that is partly wrong can't be trusted for the rest.
fn checked<S: AsRef<str>>(cidrs: &[S]) -> Result<Vec<Net>, String> {
    if cidrs.len() > MAX_RANGES {
        return Err(format!("{} ranges is too many", cidrs.len()));
    }
    let mut nets = Vec::with_capacity(cidrs.len());
    for c in cidrs {
        let c = c.as_ref();
        nets.push(Net::parse(c).ok_or_else(|| format!("refusing the range '{c}'"))?);
    }
    if !nets.iter().any(|n| n.addr.is_ipv4()) || !nets.iter().any(|n| n.addr.is_ipv6()) {
        return Err("the list needs both IPv4 and IPv6 ranges".into());
    }
    nets.sort_unstable();
    nets.dedup();
    Ok(nets)
}

/// The ranges in use. `updated_at` is None while they are still the built-in copy.
#[derive(Clone, Debug, PartialEq)]
pub struct Ranges {
    nets: Vec<Net>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    cidrs: Vec<String>,
    updated_at: DateTime<Utc>,
}

impl Ranges {
    pub fn built_in() -> Self {
        Ranges {
            nets: checked(&BUILT_IN).unwrap_or_default(),
            updated_at: None,
        }
    }

    pub fn load(conn: &rusqlite::Connection) -> Self {
        db::get_setting(conn, SETTING)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str::<Stored>(&v).ok())
            .and_then(|s| {
                Some(Ranges {
                    nets: checked(&s.cidrs).ok()?,
                    updated_at: Some(s.updated_at),
                })
            })
            .unwrap_or_else(Self::built_in)
    }

    /// Does this connection come from Cloudflare? A listener on `[::]` sees IPv4 peers as
    /// `::ffff:a.b.c.d`.
    pub fn contains(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.nets.iter().any(|n| n.contains(peer))
    }

    pub fn cidrs(&self) -> Vec<String> {
        self.nets.iter().map(Net::to_string).collect()
    }

    /// For the settings page, so an out-of-date list doesn't go unnoticed.
    pub fn status(&self, now: DateTime<Utc>) -> serde_json::Value {
        let stale = self
            .updated_at
            .map_or(true, |t| now - t > ChronoDuration::days(STALE_AFTER_DAYS));
        json!({
            "ranges": self.nets.len(),
            "updated_at": self.updated_at,
            "built_in": self.updated_at.is_none(),
            "stale": stale,
        })
    }
}

#[derive(Deserialize)]
struct ApiResponse {
    success: bool,
    result: Option<ApiResult>,
}

#[derive(Deserialize)]
struct ApiResult {
    ipv4_cidrs: Vec<String>,
    ipv6_cidrs: Vec<String>,
}

fn parse_response(body: &str) -> Result<Vec<Net>, String> {
    let r: ApiResponse = serde_json::from_str(body).map_err(|e| format!("unexpected answer: {e}"))?;
    let result = r.result.filter(|_| r.success).ok_or("Cloudflare reported an error")?;
    checked(&[result.ipv4_cidrs, result.ipv6_cidrs].concat())
}

async fn fetch(url: &str) -> Result<Vec<Net>, String> {
    let res = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("{url} returned {}", res.status()));
    }
    parse_response(&res.text().await.map_err(|e| e.to_string())?)
}

/// Fetch the list and put it to use, here and in nginx. Nothing changes if anything fails
/// before that. nginx keeps its previous config if it refuses the new one.
async fn refresh(state: &SharedState) -> Result<(), String> {
    let nets = fetch(&state.config.cloudflare_ips_url).await?;
    let st = state.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let now = Utc::now();
        let ranges = Ranges {
            nets,
            updated_at: Some(now),
        };
        let conn = st.pool.get().map_err(|e| e.to_string())?;
        let stored = Stored {
            cidrs: ranges.cidrs(),
            updated_at: now,
        };
        db::set_json(&conn, SETTING, &stored).map_err(|e| e.to_string())?;
        *st.cloudflare.write().unwrap_or_else(|e| e.into_inner()) = ranges.clone();
        let tls = st.tls.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        panel_cert::sync_vhost(&st.config, &conn, tls, &st.proxy_secret, &ranges);
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Keep the list current for as long as the panel runs. It starts with the stored list, so this
/// can't hold anything up, and a failure only means the last good list stays in use.
pub fn start(state: SharedState) {
    tokio::spawn(async move {
        // Let the server finish starting first.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let wait = match refresh(&state).await {
                Ok(()) => REFRESH_EVERY,
                Err(e) => {
                    let since = state
                        .cloudflare
                        .read()
                        .unwrap_or_else(|e| e.into_inner())
                        .updated_at
                        .map_or("the built-in list".to_string(), |t| format!("the list from {t}"));
                    tracing::warn!("could not refresh Cloudflare's address ranges, keeping {since}: {e}");
                    RETRY_AFTER
                }
            };
            tokio::time::sleep(wait).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_built_in_list_is_complete_and_passes_its_own_checks() {
        assert_eq!(Ranges::built_in().nets.len(), BUILT_IN.len());
    }

    #[test]
    fn membership_follows_the_prefix() {
        let r = Ranges::built_in();
        assert!(r.contains(ip("173.245.48.1")));
        assert!(r.contains(ip("173.245.63.255")));
        assert!(!r.contains(ip("173.245.64.0")));
        assert!(r.contains(ip("2606:4700::1")));
        assert!(!r.contains(ip("2606:4701::1")));
        // The IPv6 form an IPv4 client has on a dual-stack listener.
        assert!(r.contains(ip("::ffff:173.245.48.1")));
        assert!(!r.contains(ip("::ffff:203.0.113.9")));
        for other in ["203.0.113.9", "127.0.0.1", "::1", "10.0.0.1"] {
            assert!(!r.contains(ip(other)), "{other}");
        }
    }

    #[test]
    fn reads_the_api_answer() {
        let nets = parse_response(
            r#"{"result":{"ipv4_cidrs":["198.51.100.0/24","173.245.48.0/20"],"ipv6_cidrs":["2606:4700::/32"],"etag":"x"},"success":true,"errors":[],"messages":[]}"#,
        )
        .unwrap();
        // In a fixed order, whatever order they came in.
        let text: Vec<_> = nets.iter().map(Net::to_string).collect();
        assert_eq!(text, ["173.245.48.0/20", "198.51.100.0/24", "2606:4700::/32"]);
    }

    #[test]
    fn refuses_a_list_that_would_let_anyone_choose_their_address() {
        let answer = |v4: &str, v6: &str| {
            parse_response(&format!(
                r#"{{"success":true,"result":{{"ipv4_cidrs":[{v4}],"ipv6_cidrs":[{v6}]}}}}"#
            ))
        };
        let v4 = r#""173.245.48.0/20""#;
        let v6 = r#""2606:4700::/32""#;
        assert!(answer(v4, v6).is_ok());
        for bad in [
            r#""0.0.0.0/0""#,
            r#""128.0.0.0/1""#,
            r#""0.0.0.0/8""#,
            // This machine, which would include its site users.
            r#""127.0.0.0/8""#,
            r#""10.0.0.0/8""#,
            r#""192.168.0.0/16""#,
            r#""169.254.0.0/16""#,
            // Host bits set, no prefix, not an address, and an attempt at nginx config.
            r#""173.245.48.1/20""#,
            r#""173.245.48.0""#,
            r#""example.com/24""#,
            r#""1.2.3.0/24; }""#,
        ] {
            assert!(answer(&format!("{v4},{bad}"), v6).is_err(), "{bad}");
        }
        for bad in [
            r#""::/0""#,
            r#""2000::/3""#,
            r#""::1/128""#,
            r#""::ffff:0:0/96""#,
            r#""fc00::/7""#,
            r#""fd00::/32""#,
            r#""fe80::/32""#,
        ] {
            assert!(answer(v4, &format!("{v6},{bad}")).is_err(), "{bad}");
        }
        // An empty or one-sided list would stop trusting real traffic.
        assert!(answer("", "").is_err());
        assert!(answer(v4, "").is_err());
        assert!(answer("", v6).is_err());
        assert!(parse_response(
            r#"{"success":false,"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":["2606:4700::/32"]}}"#
        )
        .is_err());
        assert!(parse_response(r#"{"success":false,"result":null,"errors":[{"code":1}]}"#).is_err());
        assert!(parse_response("<html>Sorry, you have been blocked</html>").is_err());
        let huge: Vec<String> = (0..300).map(|i| format!("\"{}.0.0.0/8\"", i % 90 + 11)).collect();
        assert!(answer(&huge.join(","), v6).is_err());
    }

    #[test]
    fn a_stored_list_survives_a_restart_and_a_bad_one_is_ignored() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .unwrap();
        assert_eq!(Ranges::load(&conn), Ranges::built_in());

        let t: DateTime<Utc> = "2026-11-01T00:00:00Z".parse().unwrap();
        let good = Stored {
            cidrs: vec!["198.51.100.0/24".into(), "2001:db8::/32".into()],
            updated_at: t,
        };
        db::set_json(&conn, SETTING, &good).unwrap();
        let r = Ranges::load(&conn);
        assert_eq!(r.cidrs(), good.cidrs);
        assert_eq!(r.updated_at, Some(t));
        assert!(r.contains(ip("198.51.100.7")));
        assert!(!r.contains(ip("173.245.48.1")));

        let bad = Stored {
            cidrs: vec!["0.0.0.0/0".into(), "::/0".into()],
            updated_at: t,
        };
        db::set_json(&conn, SETTING, &bad).unwrap();
        assert_eq!(Ranges::load(&conn), Ranges::built_in());
        db::set_setting(&conn, SETTING, "not json").unwrap();
        assert_eq!(Ranges::load(&conn), Ranges::built_in());
    }

    #[test]
    fn reports_an_out_of_date_list() {
        let now: DateTime<Utc> = "2026-11-10T00:00:00Z".parse().unwrap();
        let s = Ranges::built_in().status(now);
        assert_eq!(s["built_in"], true);
        assert_eq!(s["stale"], true);
        assert_eq!(s["ranges"], 22);

        let mut r = Ranges::built_in();
        r.updated_at = Some(now - ChronoDuration::days(1));
        let s = r.status(now);
        assert_eq!(s["built_in"], false);
        assert_eq!(s["stale"], false);

        r.updated_at = Some(now - ChronoDuration::days(8));
        assert_eq!(r.status(now)["stale"], true);
    }
}
