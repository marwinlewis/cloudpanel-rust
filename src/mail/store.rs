//! The mail service's SQLite database: domains, API keys, forwards, sent-message log, events and
//! webhooks. It is separate from the panel's database and owned by the service's user.

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    verified INTEGER NOT NULL DEFAULT 0,
    dkim_public TEXT NOT NULL,
    last_check TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    permission TEXT NOT NULL DEFAULT 'sending',
    domain TEXT,
    hourly_limit INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS forwards (
    address TEXT PRIMARY KEY,
    forward_to TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    source TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    recipients TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    message_id TEXT NOT NULL,
    queue_id TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_message_id ON messages(message_id);
CREATE INDEX IF NOT EXISTS messages_queue_id ON messages(queue_id);
CREATE INDEX IF NOT EXISTS messages_created ON messages(created_at);
CREATE INDEX IF NOT EXISTS messages_key ON messages(key_id, created_at);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    recipient TEXT,
    detail TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_message ON events(message);
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    events TEXT NOT NULL,
    secret TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_outbox (
    id TEXT PRIMARY KEY,
    webhook TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"#;

pub type Result<T> = rusqlite::Result<T>;

/// Open (and create) the database.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

#[cfg(test)]
pub fn open_memory() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    conn
}

// ---------- Domains ----------

#[derive(Debug, Clone, Serialize)]
pub struct Domain {
    pub name: String,
    pub verified: bool,
    pub dkim_public: String,
    pub last_check: Option<String>,
    pub created_at: String,
}

fn domain_row(r: &Row) -> Result<Domain> {
    Ok(Domain {
        name: r.get(0)?,
        verified: r.get(1)?,
        dkim_public: r.get(2)?,
        last_check: r.get(3)?,
        created_at: r.get(4)?,
    })
}

const DOMAIN_COLS: &str = "name, verified, dkim_public, last_check, created_at";

pub fn add_domain(conn: &Connection, name: &str, dkim_public: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO domains (name, dkim_public, created_at) VALUES (?1, ?2, ?3)",
        params![name, dkim_public, super::now()],
    )?;
    Ok(())
}

pub fn get_domain(conn: &Connection, name: &str) -> Result<Option<Domain>> {
    conn.query_row(
        &format!("SELECT {DOMAIN_COLS} FROM domains WHERE name = ?1"),
        [name],
        domain_row,
    )
    .optional()
}

pub fn list_domains(conn: &Connection) -> Result<Vec<Domain>> {
    let mut st = conn.prepare(&format!("SELECT {DOMAIN_COLS} FROM domains ORDER BY name"))?;
    let rows = st.query_map([], domain_row)?;
    rows.collect()
}

pub fn set_domain_verified(conn: &Connection, name: &str, verified: bool) -> Result<()> {
    conn.execute(
        "UPDATE domains SET verified = ?2, last_check = ?3 WHERE name = ?1",
        params![name, verified, super::now()],
    )?;
    Ok(())
}

pub fn remove_domain(conn: &Connection, name: &str) -> Result<bool> {
    Ok(conn.execute("DELETE FROM domains WHERE name = ?1", [name])? > 0)
}

// ---------- API keys ----------

#[derive(Debug, Clone, Serialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    #[serde(skip)]
    pub secret_hash: String,
    /// `full` or `sending`. Both can send; `full` is kept for parity with Resend's key types.
    pub permission: String,
    /// When set, the key may only send from this domain.
    pub domain: Option<String>,
    pub hourly_limit: u32,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

fn key_row(r: &Row) -> Result<ApiKey> {
    Ok(ApiKey {
        id: r.get(0)?,
        name: r.get(1)?,
        secret_hash: r.get(2)?,
        permission: r.get(3)?,
        domain: r.get(4)?,
        hourly_limit: r.get(5)?,
        created_at: r.get(6)?,
        last_used_at: r.get(7)?,
    })
}

const KEY_COLS: &str = "id, name, secret_hash, permission, domain, hourly_limit, created_at, last_used_at";

pub fn add_key(conn: &Connection, key: &ApiKey) -> Result<()> {
    conn.execute(
        "INSERT INTO api_keys (id, name, secret_hash, permission, domain, hourly_limit, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            key.id,
            key.name,
            key.secret_hash,
            key.permission,
            key.domain,
            key.hourly_limit,
            key.created_at
        ],
    )?;
    Ok(())
}

pub fn get_key(conn: &Connection, id: &str) -> Result<Option<ApiKey>> {
    conn.query_row(&format!("SELECT {KEY_COLS} FROM api_keys WHERE id = ?1"), [id], key_row)
        .optional()
}

pub fn list_keys(conn: &Connection) -> Result<Vec<ApiKey>> {
    let mut st = conn.prepare(&format!("SELECT {KEY_COLS} FROM api_keys ORDER BY created_at"))?;
    let rows = st.query_map([], key_row)?;
    rows.collect()
}

pub fn touch_key(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE api_keys SET last_used_at = ?2 WHERE id = ?1",
        params![id, super::now()],
    )?;
    Ok(())
}

pub fn remove_key(conn: &Connection, id: &str) -> Result<bool> {
    Ok(conn.execute("DELETE FROM api_keys WHERE id = ?1", [id])? > 0)
}

// ---------- Forwards ----------

#[derive(Debug, Clone, Serialize)]
pub struct Forward {
    pub address: String,
    pub forward_to: String,
    pub created_at: String,
}

pub fn add_forward(conn: &Connection, address: &str, to: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO forwards (address, forward_to, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(address) DO UPDATE SET forward_to = excluded.forward_to",
        params![address, to, super::now()],
    )?;
    Ok(())
}

pub fn list_forwards(conn: &Connection) -> Result<Vec<Forward>> {
    let mut st = conn.prepare("SELECT address, forward_to, created_at FROM forwards ORDER BY address")?;
    let rows = st.query_map([], |r| {
        Ok(Forward {
            address: r.get(0)?,
            forward_to: r.get(1)?,
            created_at: r.get(2)?,
        })
    })?;
    rows.collect()
}

pub fn remove_forward(conn: &Connection, address: &str) -> Result<bool> {
    Ok(conn.execute("DELETE FROM forwards WHERE address = ?1", [address])? > 0)
}

// ---------- Messages and events ----------

#[derive(Debug, Clone, Serialize)]
pub struct MessageLog {
    pub id: String,
    pub key_id: String,
    pub source: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub message_id: String,
    pub queue_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

fn message_row(r: &Row) -> Result<MessageLog> {
    let to: String = r.get(4)?;
    Ok(MessageLog {
        id: r.get(0)?,
        key_id: r.get(1)?,
        source: r.get(2)?,
        from: r.get(3)?,
        to: serde_json::from_str(&to).unwrap_or_default(),
        subject: r.get(5)?,
        message_id: r.get(6)?,
        queue_id: r.get(7)?,
        status: r.get(8)?,
        created_at: r.get(9)?,
        updated_at: r.get(10)?,
    })
}

const MESSAGE_COLS: &str =
    "id, key_id, source, from_addr, recipients, subject, message_id, queue_id, status, created_at, updated_at";

pub fn add_message(conn: &Connection, m: &MessageLog) -> Result<()> {
    conn.execute(
        "INSERT INTO messages (id, key_id, source, from_addr, recipients, subject, message_id, queue_id, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            m.id,
            m.key_id,
            m.source,
            m.from,
            serde_json::to_string(&m.to).unwrap_or_else(|_| "[]".into()),
            m.subject,
            m.message_id,
            m.queue_id,
            m.status,
            m.created_at,
            m.updated_at
        ],
    )?;
    Ok(())
}

pub fn get_message(conn: &Connection, id: &str) -> Result<Option<MessageLog>> {
    conn.query_row(
        &format!("SELECT {MESSAGE_COLS} FROM messages WHERE id = ?1"),
        [id],
        message_row,
    )
    .optional()
}

/// The newest message with this Message-ID still waiting for Postfix to name it.
pub fn message_by_message_id(conn: &Connection, message_id: &str) -> Result<Option<MessageLog>> {
    conn.query_row(
        &format!("SELECT {MESSAGE_COLS} FROM messages WHERE message_id = ?1 AND queue_id IS NULL ORDER BY created_at DESC LIMIT 1"),
        [message_id],
        message_row,
    )
    .optional()
}

pub fn message_by_queue_id(conn: &Connection, queue_id: &str) -> Result<Option<MessageLog>> {
    conn.query_row(
        &format!("SELECT {MESSAGE_COLS} FROM messages WHERE queue_id = ?1 ORDER BY created_at DESC LIMIT 1"),
        [queue_id],
        message_row,
    )
    .optional()
}

pub fn list_messages(conn: &Connection, limit: u32, status: Option<&str>) -> Result<Vec<MessageLog>> {
    let mut st = conn.prepare(&format!(
        "SELECT {MESSAGE_COLS} FROM messages WHERE (?1 IS NULL OR status = ?1) ORDER BY created_at DESC, rowid DESC LIMIT ?2"
    ))?;
    let rows = st.query_map(params![status, limit], message_row)?;
    rows.collect()
}

pub fn set_queue_id(conn: &Connection, id: &str, queue_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE messages SET queue_id = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, queue_id, super::now()],
    )?;
    Ok(())
}

pub fn set_status(conn: &Connection, id: &str, status: &str) -> Result<()> {
    conn.execute(
        "UPDATE messages SET status = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, status, super::now()],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub kind: String,
    pub recipient: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

pub fn add_event(
    conn: &Connection,
    message: &str,
    kind: &str,
    recipient: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO events (message, kind, recipient, detail, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![message, kind, recipient, detail, super::now()],
    )?;
    Ok(())
}

pub fn events_for(conn: &Connection, message: &str) -> Result<Vec<Event>> {
    let mut st =
        conn.prepare("SELECT kind, recipient, detail, created_at FROM events WHERE message = ?1 ORDER BY id")?;
    let rows = st.query_map([message], |r| {
        Ok(Event {
            kind: r.get(0)?,
            recipient: r.get(1)?,
            detail: r.get(2)?,
            created_at: r.get(3)?,
        })
    })?;
    rows.collect()
}

/// Messages sent by a key since `since` (RFC 3339), for the hourly limit after a restart.
pub fn count_sent_since(conn: &Connection, key_id: &str, since: &str) -> Result<u32> {
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE key_id = ?1 AND created_at >= ?2",
        params![key_id, since],
        |r| r.get(0),
    )
}

/// Drop message logs (and their events) older than `days`.
pub fn prune(conn: &Connection, days: i64) -> Result<usize> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    conn.execute("DELETE FROM messages WHERE created_at < ?1", [cutoff])
}

// ---------- Webhooks ----------

#[derive(Debug, Clone, Serialize)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    #[serde(skip)]
    pub secret: String,
    pub created_at: String,
}

fn webhook_row(r: &Row) -> Result<Webhook> {
    let events: String = r.get(2)?;
    Ok(Webhook {
        id: r.get(0)?,
        url: r.get(1)?,
        events: events.split(',').filter(|s| !s.is_empty()).map(String::from).collect(),
        secret: r.get(3)?,
        created_at: r.get(4)?,
    })
}

pub fn add_webhook(conn: &Connection, w: &Webhook) -> Result<()> {
    conn.execute(
        "INSERT INTO webhooks (id, url, events, secret, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![w.id, w.url, w.events.join(","), w.secret, w.created_at],
    )?;
    Ok(())
}

pub fn list_webhooks(conn: &Connection) -> Result<Vec<Webhook>> {
    let mut st = conn.prepare("SELECT id, url, events, secret, created_at FROM webhooks ORDER BY created_at")?;
    let rows = st.query_map([], webhook_row)?;
    rows.collect()
}

pub fn get_webhook(conn: &Connection, id: &str) -> Result<Option<Webhook>> {
    conn.query_row(
        "SELECT id, url, events, secret, created_at FROM webhooks WHERE id = ?1",
        [id],
        webhook_row,
    )
    .optional()
}

pub fn remove_webhook(conn: &Connection, id: &str) -> Result<bool> {
    Ok(conn.execute("DELETE FROM webhooks WHERE id = ?1", [id])? > 0)
}

#[derive(Debug, Clone)]
pub struct Outgoing {
    pub id: String,
    pub webhook: String,
    pub payload: String,
    pub attempts: u32,
}

pub fn enqueue_webhook(conn: &Connection, webhook: &str, payload: &str) -> Result<()> {
    let now = super::now();
    conn.execute(
        "INSERT INTO webhook_outbox (id, webhook, payload, next_at, created_at) VALUES (?1, ?2, ?3, ?4, ?4)",
        params![
            format!("msg_{}", super::new_id().replace('-', "")),
            webhook,
            payload,
            now
        ],
    )?;
    Ok(())
}

pub fn due_webhooks(conn: &Connection, limit: u32) -> Result<Vec<Outgoing>> {
    let mut st = conn.prepare(
        "SELECT id, webhook, payload, attempts FROM webhook_outbox WHERE next_at <= ?1 ORDER BY next_at LIMIT ?2",
    )?;
    let rows = st.query_map(params![super::now(), limit], |r| {
        Ok(Outgoing {
            id: r.get(0)?,
            webhook: r.get(1)?,
            payload: r.get(2)?,
            attempts: r.get(3)?,
        })
    })?;
    rows.collect()
}

pub fn webhook_done(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM webhook_outbox WHERE id = ?1", [id])?;
    Ok(())
}

pub fn webhook_retry(conn: &Connection, id: &str, next_at: &str) -> Result<()> {
    conn.execute(
        "UPDATE webhook_outbox SET attempts = attempts + 1, next_at = ?2 WHERE id = ?1",
        params![id, next_at],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str, mid: &str) -> MessageLog {
        let now = crate::mail::now();
        MessageLog {
            id: id.into(),
            key_id: "k".into(),
            source: "api".into(),
            from: "a@example.com".into(),
            to: vec!["b@example.org".into()],
            subject: "Hi".into(),
            message_id: mid.into(),
            queue_id: None,
            status: "queued".into(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[test]
    fn message_lifecycle() {
        let c = open_memory();
        add_message(&c, &msg("m1", "<x@h>")).unwrap();
        let m = message_by_message_id(&c, "<x@h>").unwrap().unwrap();
        assert_eq!(m.to, vec!["b@example.org".to_string()]);
        set_queue_id(&c, "m1", "ABC123").unwrap();
        assert!(message_by_message_id(&c, "<x@h>").unwrap().is_none());
        assert_eq!(message_by_queue_id(&c, "ABC123").unwrap().unwrap().id, "m1");
        add_event(&c, "m1", "delivered", Some("b@example.org"), None).unwrap();
        set_status(&c, "m1", "delivered").unwrap();
        assert_eq!(events_for(&c, "m1").unwrap().len(), 1);
        assert_eq!(list_messages(&c, 10, Some("delivered")).unwrap().len(), 1);
        assert_eq!(list_messages(&c, 10, Some("bounced")).unwrap().len(), 0);
        assert_eq!(count_sent_since(&c, "k", "2000-01-01T00:00:00Z").unwrap(), 1);
    }

    #[test]
    fn forwards_upsert() {
        let c = open_memory();
        add_forward(&c, "me@example.com", "a@gmail.com").unwrap();
        add_forward(&c, "me@example.com", "b@gmail.com").unwrap();
        let f = list_forwards(&c).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].forward_to, "b@gmail.com");
    }

    #[test]
    fn webhook_outbox_cascades() {
        let c = open_memory();
        let w = Webhook {
            id: "w1".into(),
            url: "https://example.com/hook".into(),
            events: vec!["email.bounced".into()],
            secret: "s".into(),
            created_at: crate::mail::now(),
        };
        add_webhook(&c, &w).unwrap();
        enqueue_webhook(&c, "w1", "{}").unwrap();
        assert_eq!(due_webhooks(&c, 10).unwrap().len(), 1);
        remove_webhook(&c, "w1").unwrap();
        assert_eq!(due_webhooks(&c, 10).unwrap().len(), 0);
    }
}
