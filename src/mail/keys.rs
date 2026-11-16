//! API keys: `cp_<id>_<secret>`. The id finds the key, and only a SHA-256 of the whole key is
//! stored. A slow password hash would add nothing here: the secret is 190 random bits, not
//! something a person chose, and it is checked on every message.

use super::store::{self, ApiKey};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const PREFIX: &str = "cp_";
const ID_LEN: usize = 12;
const SECRET_LEN: usize = 32;

fn hash(full: &str) -> String {
    Sha256::digest(full.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Split a presented key into its id, or None when it can't be one of ours.
pub fn parse(full: &str) -> Option<&str> {
    let rest = full.strip_prefix(PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    let ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_alphanumeric());
    (ok(id, ID_LEN) && ok(secret, SECRET_LEN)).then_some(id)
}

/// A new key. Returns the stored record and the full key, which is shown once.
pub fn generate(name: &str, permission: &str, domain: Option<String>, hourly_limit: u32) -> (ApiKey, String) {
    let id = crate::auth::random_password(ID_LEN);
    let secret = crate::auth::random_password(SECRET_LEN);
    let full = format!("{PREFIX}{id}_{secret}");
    let key = ApiKey {
        id,
        name: name.to_string(),
        secret_hash: hash(&full),
        permission: permission.to_string(),
        domain,
        hourly_limit,
        created_at: super::now(),
        last_used_at: None,
    };
    (key, full)
}

/// The key a client presented, if it exists and matches.
pub fn authenticate(conn: &Connection, presented: &str) -> Option<ApiKey> {
    let presented = presented.trim();
    let id = parse(presented)?;
    let key = store::get_key(conn, id).ok()??;
    ct_eq(hash(presented).as_bytes(), key.secret_hash.as_bytes()).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_authenticate() {
        let c = store::open_memory();
        let (key, full) = generate("gmail", "sending", None, 10);
        store::add_key(&c, &key).unwrap();
        assert!(full.starts_with("cp_"));
        assert_eq!(parse(&full), Some(key.id.as_str()));
        assert_eq!(authenticate(&c, &full).unwrap().id, key.id);
        assert_eq!(authenticate(&c, &format!(" {full}\n")).unwrap().id, key.id);
        // Same id, other secret.
        let forged = format!("cp_{}_{}", key.id, "A".repeat(SECRET_LEN));
        assert!(authenticate(&c, &forged).is_none());
        assert!(authenticate(&c, "re_123").is_none());
        store::remove_key(&c, &key.id).unwrap();
        assert!(authenticate(&c, &full).is_none());
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse("cp_short_secret").is_none());
        assert!(parse(&format!("cp_{}_{}", "a".repeat(12), "b".repeat(31))).is_none());
        assert!(parse(&format!("cp_{}-{}", "a".repeat(12), "b".repeat(32))).is_none());
    }
}
