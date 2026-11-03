pub mod models;
pub mod schema;

use chrono::Utc;
use models::{CronJob, FirewallRule, Site, User};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::Path;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_db(db_path: &Path) -> Result<DbPool, Box<dyn std::error::Error>> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let manager = SqliteConnectionManager::file(db_path)
        .with_init(|c| c.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;"));
    let pool = Pool::builder().max_size(8).build(manager)?;

    let conn = pool.get()?;
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    conn.execute_batch(schema::CREATE_TABLES)?;
    for (table, column, def) in schema::MIGRATIONS {
        if !has_column(&conn, table, column)? {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {def};"))?;
        }
    }
    crate::fsutil::set_mode(db_path, 0o600)?;

    Ok(pool)
}

fn has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _) if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
    )
}

// ---------- Users ----------

const USER_COLS: &str = "id, username, password_hash, email, role, token_version, created_at, updated_at";

fn user_from_row(row: &Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        email: row.get(3)?,
        role: row.get(4)?,
        token_version: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

pub fn find_user_by_username(conn: &Connection, username: &str) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE username = ?1"),
        params![username],
        user_from_row,
    )
    .optional()
}

pub fn find_user_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE id = ?1"),
        params![id],
        user_from_row,
    )
    .optional()
}

pub fn create_user(
    conn: &Connection,
    username: &str,
    password_hash: &str,
    email: &str,
    role: &str,
) -> rusqlite::Result<i64> {
    let now = Utc::now();
    conn.execute(
        "INSERT INTO users (username, password_hash, email, role, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![username, password_hash, email, role, now],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn count_users(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
}

/// Set a new password hash and revoke all existing sessions. Returns the new token version.
pub fn set_user_password(conn: &Connection, username: &str, password_hash: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "UPDATE users SET password_hash = ?1, token_version = token_version + 1, updated_at = ?2
         WHERE username = ?3 RETURNING token_version",
        params![password_hash, Utc::now(), username],
        |r| r.get(0),
    )
    .optional()
}

pub fn bump_token_version(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE users SET token_version = token_version + 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

// ---------- Sites ----------

const SITE_COLS: &str = "id, domain, site_type, target_port, document_root, system_user, include_www, ssl_enabled, \
                         ssl_auto_renew, ssl_cert_path, ssl_key_path, is_active, created_at, updated_at";

fn site_from_row(row: &Row) -> rusqlite::Result<Site> {
    Ok(Site {
        id: row.get(0)?,
        domain: row.get(1)?,
        site_type: row.get(2)?,
        target_port: row.get(3)?,
        document_root: row.get(4)?,
        system_user: row.get(5)?,
        include_www: row.get(6)?,
        ssl_enabled: row.get(7)?,
        ssl_auto_renew: row.get(8)?,
        ssl_cert_path: row.get(9)?,
        ssl_key_path: row.get(10)?,
        is_active: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

pub fn list_sites(conn: &Connection) -> rusqlite::Result<Vec<Site>> {
    let mut stmt = conn.prepare(&format!("SELECT {SITE_COLS} FROM sites ORDER BY domain ASC"))?;
    let rows = stmt.query_map([], site_from_row)?;
    rows.collect()
}

pub fn find_site_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<Site>> {
    conn.query_row(
        &format!("SELECT {SITE_COLS} FROM sites WHERE id = ?1"),
        params![id],
        site_from_row,
    )
    .optional()
}

pub struct NewSite<'a> {
    pub domain: &'a str,
    pub site_type: &'a str,
    pub target_port: Option<u16>,
    pub document_root: Option<&'a str>,
    pub system_user: &'a str,
    pub include_www: bool,
}

pub fn create_site(conn: &Connection, s: &NewSite) -> rusqlite::Result<i64> {
    let now = Utc::now();
    conn.execute(
        "INSERT INTO sites (domain, site_type, target_port, document_root, system_user, include_www,
                            ssl_enabled, ssl_auto_renew, is_active, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 1, 1, ?7, ?7)",
        params![
            s.domain,
            s.site_type,
            s.target_port,
            s.document_root,
            s.system_user,
            s.include_www,
            now
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_site(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM sites WHERE id = ?1", params![id])? > 0)
}

pub fn update_site_ssl(
    conn: &Connection,
    id: i64,
    ssl_enabled: bool,
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> rusqlite::Result<bool> {
    let affected = conn.execute(
        "UPDATE sites SET ssl_enabled = ?1, ssl_cert_path = ?2, ssl_key_path = ?3, updated_at = ?4 WHERE id = ?5",
        params![ssl_enabled, cert_path, key_path, Utc::now(), id],
    )?;
    Ok(affected > 0)
}

// ---------- Firewall ----------

fn rule_from_row(row: &Row) -> rusqlite::Result<FirewallRule> {
    Ok(FirewallRule {
        id: row.get(0)?,
        port: row.get(1)?,
        protocol: row.get(2)?,
        action: row.get(3)?,
        comment: row.get(4)?,
        created_at: row.get(5)?,
    })
}

pub fn list_firewall_rules(conn: &Connection) -> rusqlite::Result<Vec<FirewallRule>> {
    let mut stmt =
        conn.prepare("SELECT id, port, protocol, action, comment, created_at FROM firewall_rules ORDER BY port ASC")?;
    let rows = stmt.query_map([], rule_from_row)?;
    rows.collect()
}

pub fn find_firewall_rule(conn: &Connection, id: i64) -> rusqlite::Result<Option<FirewallRule>> {
    conn.query_row(
        "SELECT id, port, protocol, action, comment, created_at FROM firewall_rules WHERE id = ?1",
        params![id],
        rule_from_row,
    )
    .optional()
}

pub fn firewall_rule_exists(conn: &Connection, port: u16, protocol: &str, action: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM firewall_rules WHERE port = ?1 AND protocol = ?2 AND action = ?3)",
        params![port, protocol, action],
        |r| r.get(0),
    )
}

pub fn create_firewall_rule(
    conn: &Connection,
    port: u16,
    protocol: &str,
    action: &str,
    comment: Option<&str>,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO firewall_rules (port, protocol, action, comment, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![port, protocol, action, comment, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_firewall_rule(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM firewall_rules WHERE id = ?1", params![id])? > 0)
}

// ---------- Cron ----------

pub fn list_cron_jobs(conn: &Connection) -> rusqlite::Result<Vec<CronJob>> {
    let mut stmt = conn
        .prepare("SELECT id, site_id, schedule, command, user, is_active, created_at FROM cron_jobs ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| {
        Ok(CronJob {
            id: row.get(0)?,
            site_id: row.get(1)?,
            schedule: row.get(2)?,
            command: row.get(3)?,
            user: row.get(4)?,
            is_active: row.get(5)?,
            created_at: row.get(6)?,
        })
    })?;
    rows.collect()
}

pub fn create_cron_job(
    conn: &Connection,
    site_id: Option<i64>,
    schedule: &str,
    command: &str,
    user: &str,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO cron_jobs (site_id, schedule, command, user, is_active, created_at) VALUES (?1, ?2, ?3, ?4, 1, ?5)",
        params![site_id, schedule, command, user, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_cron_job(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM cron_jobs WHERE id = ?1", params![id])? > 0)
}
