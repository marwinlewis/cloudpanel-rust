pub mod models;
pub mod schema;

use chrono::{DateTime, Utc};
use models::*;
use r2d2::Pool;
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::{Path, PathBuf};

pub type DbPool = Pool<SqliteManager>;

/// Opens the pool's connections. Every connection needs these settings, as SQLite keeps them per
/// connection. This is all the panel needs from a pool adapter, and writing it here keeps the
/// SQLite version from being held back by when an adapter crate catches up with rusqlite.
#[derive(Debug)]
pub struct SqliteManager {
    path: PathBuf,
}

impl r2d2::ManageConnection for SqliteManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> rusqlite::Result<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")?;
        Ok(conn)
    }

    fn is_valid(&self, conn: &mut Connection) -> rusqlite::Result<()> {
        conn.execute_batch("")
    }

    fn has_broken(&self, _conn: &mut Connection) -> bool {
        false
    }
}

pub fn init_db(db_path: &Path) -> Result<DbPool, Box<dyn std::error::Error>> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let manager = SqliteManager {
        path: db_path.to_path_buf(),
    };
    let pool = Pool::builder().max_size(8).build(manager)?;

    let conn = pool.get()?;
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    migrate(&conn)?;
    crate::fsutil::set_mode(db_path, 0o600)?;

    Ok(pool)
}

/// Create the base schema and apply every pending versioned migration.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(schema::CREATE_TABLES)?;
    for (table, column, def) in schema::LEGACY_COLUMNS {
        if !has_column(conn, table, column)? {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {def};"))?;
        }
    }
    let current: usize = get_setting(conn, "schema_version")?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    for (i, sql) in schema::MIGRATIONS.iter().enumerate().skip(current) {
        // Foreign keys must be off while tables are rebuilt.
        conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        set_setting(&tx, "schema_version", &(i + 1).to_string())?;
        tx.commit()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        tracing::info!("database migrated to schema version {}", i + 1);
    }
    Ok(())
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
            || err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
    )
}

// ---------- Settings ----------

pub fn get_setting(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", params![key], |r| r.get(0))
        .optional()
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn delete_setting(conn: &Connection, key: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
    Ok(())
}

/// Read a JSON setting, falling back to `T::default()`.
pub fn get_json<T: serde::de::DeserializeOwned + Default>(conn: &Connection, key: &str) -> rusqlite::Result<T> {
    Ok(get_setting(conn, key)?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

pub fn set_json<T: serde::Serialize>(conn: &Connection, key: &str, value: &T) -> rusqlite::Result<()> {
    set_setting(conn, key, &serde_json::to_string(value).unwrap_or_default())
}

// ---------- Users ----------

const USER_COLS: &str = "id, username, password_hash, email, role, token_version, totp_secret, totp_enabled, \
                         recovery_codes, created_at, updated_at";

fn user_from_row(row: &Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        email: row.get(3)?,
        role: row.get(4)?,
        token_version: row.get(5)?,
        totp_secret: row.get(6)?,
        totp_enabled: row.get(7)?,
        recovery_codes: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
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

pub fn list_users(conn: &Connection) -> rusqlite::Result<Vec<User>> {
    let mut stmt = conn.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))?;
    let rows = stmt.query_map([], user_from_row)?;
    rows.collect()
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

pub fn count_admins(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |row| row.get(0))
}

/// Update email/role. A role change revokes the user's sessions.
pub fn update_user(conn: &Connection, id: i64, email: &str, role: &str) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE users SET email = ?1,
             token_version = token_version + (CASE WHEN role != ?2 THEN 1 ELSE 0 END),
             role = ?2, updated_at = ?3
         WHERE id = ?4",
        params![email, role, Utc::now(), id],
    )?;
    Ok(n > 0)
}

pub fn delete_user(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM users WHERE id = ?1", params![id])? > 0)
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

/// A signed-out session's token, by its hash, kept until it would have expired anyway.
pub fn revoke_token(conn: &Connection, hash: &str, expires_at: DateTime<Utc>) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO revoked_tokens (hash, expires_at) VALUES (?1, ?2)",
        params![hash, expires_at],
    )?;
    Ok(())
}

pub fn is_token_revoked(conn: &Connection, hash: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE hash = ?1)",
        params![hash],
        |r| r.get(0),
    )
}

pub fn prune_revoked_tokens(conn: &Connection, now: DateTime<Utc>) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?1", params![now])
}

pub fn bump_token_version(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE users SET token_version = token_version + 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

/// Store a pending (not yet enabled) TOTP secret.
pub fn set_totp_pending(conn: &Connection, id: i64, secret: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE users SET totp_secret = ?1, totp_enabled = 0 WHERE id = ?2",
        params![secret, id],
    )?;
    Ok(())
}

pub fn enable_totp(conn: &Connection, id: i64, recovery_codes_json: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE users SET totp_enabled = 1, recovery_codes = ?1, updated_at = ?2 WHERE id = ?3",
        params![recovery_codes_json, Utc::now(), id],
    )?;
    Ok(())
}

pub fn disable_totp(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE users SET totp_enabled = 0, totp_secret = NULL, recovery_codes = '[]', updated_at = ?1 WHERE id = ?2",
        params![Utc::now(), id],
    )? > 0)
}

pub fn set_recovery_codes(conn: &Connection, id: i64, json: &str) -> rusqlite::Result<()> {
    conn.execute("UPDATE users SET recovery_codes = ?1 WHERE id = ?2", params![json, id])?;
    Ok(())
}

// ---------- Site access ----------

pub fn user_site_ids(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT site_id FROM user_sites WHERE user_id = ?1 ORDER BY site_id")?;
    let rows = stmt.query_map(params![user_id], |r| r.get(0))?;
    rows.collect()
}

pub fn user_has_site(conn: &Connection, user_id: i64, site_id: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM user_sites WHERE user_id = ?1 AND site_id = ?2)",
        params![user_id, site_id],
        |r| r.get(0),
    )
}

pub fn set_user_sites(conn: &Connection, user_id: i64, site_ids: &[i64]) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM user_sites WHERE user_id = ?1", params![user_id])?;
    for sid in site_ids {
        conn.execute(
            "INSERT OR IGNORE INTO user_sites (user_id, site_id) SELECT ?1, id FROM sites WHERE id = ?2",
            params![user_id, sid],
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub fn grant_site(conn: &Connection, user_id: i64, site_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO user_sites (user_id, site_id) VALUES (?1, ?2)",
        params![user_id, site_id],
    )?;
    Ok(())
}

// ---------- Sites ----------

const SITE_COLS: &str = "id, domain, site_type, target_port, document_root, system_user, include_www, ssl_enabled, \
                         ssl_auto_renew, ssl_cert_path, ssl_key_path, is_active, app_command, app_workdir, app_env, \
                         app_enabled, home_dir, websocket, max_body_mb, custom_directives, basic_auth_enabled, \
                         basic_auth_allow, created_at, updated_at, app_manager, app_pm2, www_redirect, php_version, \
                         vhost_managed, maintenance_mode, maintenance_message, maintenance_allow";

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
        app_command: row.get(12)?,
        app_workdir: row.get(13)?,
        app_env: row.get(14)?,
        app_enabled: row.get(15)?,
        home_dir: row.get(16)?,
        websocket: row.get(17)?,
        max_body_mb: row.get(18)?,
        custom_directives: row.get(19)?,
        basic_auth_enabled: row.get(20)?,
        basic_auth_allow: row.get(21)?,
        created_at: row.get(22)?,
        updated_at: row.get(23)?,
        app_manager: row.get(24)?,
        app_pm2: row.get(25)?,
        www_redirect: row.get(26)?,
        php_version: row.get(27)?,
        vhost_managed: row.get(28)?,
        maintenance_mode: row.get(29)?,
        maintenance_message: row.get(30)?,
        maintenance_allow: row.get(31)?,
    })
}

pub fn list_sites(conn: &Connection) -> rusqlite::Result<Vec<Site>> {
    let mut stmt = conn.prepare(&format!("SELECT {SITE_COLS} FROM sites ORDER BY domain ASC"))?;
    let rows = stmt.query_map([], site_from_row)?;
    rows.collect()
}

pub fn list_sites_for_user(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<Site>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SITE_COLS} FROM sites WHERE id IN (SELECT site_id FROM user_sites WHERE user_id = ?1) ORDER BY domain"
    ))?;
    let rows = stmt.query_map(params![user_id], site_from_row)?;
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
    pub www_redirect: bool,
    pub home_dir: Option<&'a str>,
    pub app_command: Option<&'a str>,
    pub app_manager: &'a str,
    pub php_version: Option<&'a str>,
    pub maintenance_mode: bool,
}

pub fn create_site(conn: &Connection, s: &NewSite) -> rusqlite::Result<i64> {
    let now = Utc::now();
    conn.execute(
        "INSERT INTO sites (domain, site_type, target_port, document_root, system_user, include_www,
                            ssl_enabled, ssl_auto_renew, is_active, home_dir, app_command, created_at, updated_at,
                            www_redirect, app_manager, php_version, maintenance_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 1, 1, ?7, ?8, ?9, ?9, ?10, ?11, ?12, ?13)",
        params![
            s.domain,
            s.site_type,
            s.target_port,
            s.document_root,
            s.system_user,
            s.include_www,
            s.home_dir,
            s.app_command,
            now,
            s.www_redirect,
            s.app_manager,
            s.php_version,
            s.maintenance_mode
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Persist every mutable field of a site.
pub fn save_site(conn: &Connection, s: &Site) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE sites SET target_port = ?1, document_root = ?2, include_www = ?3, ssl_enabled = ?4,
             ssl_cert_path = ?5, ssl_key_path = ?6, is_active = ?7, app_command = ?8, app_workdir = ?9,
             app_env = ?10, app_enabled = ?11, websocket = ?12, max_body_mb = ?13, custom_directives = ?14,
             basic_auth_enabled = ?15, basic_auth_allow = ?16, updated_at = ?17,
             app_manager = ?19, app_pm2 = ?20, www_redirect = ?21,
             maintenance_mode = ?22, maintenance_message = ?23, maintenance_allow = ?24
         WHERE id = ?18",
        params![
            s.target_port,
            s.document_root,
            s.include_www,
            s.ssl_enabled,
            s.ssl_cert_path,
            s.ssl_key_path,
            s.is_active,
            s.app_command,
            s.app_workdir,
            s.app_env,
            s.app_enabled,
            s.websocket,
            s.max_body_mb,
            s.custom_directives,
            s.basic_auth_enabled,
            s.basic_auth_allow,
            Utc::now(),
            s.id,
            s.app_manager,
            s.app_pm2,
            s.www_redirect,
            s.maintenance_mode,
            s.maintenance_message,
            s.maintenance_allow
        ],
    )?;
    Ok(n > 0)
}

pub fn delete_site(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM sites WHERE id = ?1", params![id])? > 0)
}

// ---------- Basic auth ----------

pub fn list_basic_auth_users(conn: &Connection, site_id: i64) -> rusqlite::Result<Vec<BasicAuthUser>> {
    let mut stmt = conn.prepare(
        "SELECT id, site_id, username, password_hash FROM basic_auth_users WHERE site_id = ?1 ORDER BY username",
    )?;
    let rows = stmt.query_map(params![site_id], |r| {
        Ok(BasicAuthUser {
            id: r.get(0)?,
            site_id: r.get(1)?,
            username: r.get(2)?,
            password_hash: r.get(3)?,
        })
    })?;
    rows.collect()
}

pub fn upsert_basic_auth_user(conn: &Connection, site_id: i64, username: &str, hash: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO basic_auth_users (site_id, username, password_hash) VALUES (?1, ?2, ?3)
         ON CONFLICT(site_id, username) DO UPDATE SET password_hash = excluded.password_hash",
        params![site_id, username, hash],
    )?;
    Ok(())
}

pub fn delete_basic_auth_user(conn: &Connection, site_id: i64, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "DELETE FROM basic_auth_users WHERE id = ?1 AND site_id = ?2",
        params![id, site_id],
    )? > 0)
}

// ---------- SSH users ----------

fn ssh_user_from_row(r: &Row) -> rusqlite::Result<SshUser> {
    Ok(SshUser {
        id: r.get(0)?,
        site_id: r.get(1)?,
        username: r.get(2)?,
        sftp_only: r.get(3)?,
        is_owner: r.get(4)?,
        created_at: r.get(5)?,
    })
}

pub fn list_ssh_users(conn: &Connection, site_id: i64) -> rusqlite::Result<Vec<SshUser>> {
    let mut stmt = conn.prepare(
        "SELECT id, site_id, username, sftp_only, is_owner, created_at FROM ssh_users WHERE site_id = ?1
         ORDER BY is_owner DESC, username",
    )?;
    let rows = stmt.query_map(params![site_id], ssh_user_from_row)?;
    rows.collect()
}

pub fn find_ssh_user(conn: &Connection, site_id: i64, id: i64) -> rusqlite::Result<Option<SshUser>> {
    conn.query_row(
        "SELECT id, site_id, username, sftp_only, is_owner, created_at FROM ssh_users WHERE id = ?1 AND site_id = ?2",
        params![id, site_id],
        ssh_user_from_row,
    )
    .optional()
}

pub fn create_ssh_user(
    conn: &Connection,
    site_id: i64,
    username: &str,
    sftp_only: bool,
    is_owner: bool,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO ssh_users (site_id, username, sftp_only, is_owner, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![site_id, username, sftp_only, is_owner, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn set_ssh_user_sftp_only(conn: &Connection, id: i64, sftp_only: bool) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE ssh_users SET sftp_only = ?1 WHERE id = ?2",
        params![sftp_only, id],
    )?;
    Ok(())
}

pub fn delete_ssh_user(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM ssh_users WHERE id = ?1", params![id])? > 0)
}

pub fn list_ssh_keys(conn: &Connection, ssh_user_id: i64) -> rusqlite::Result<Vec<SshKey>> {
    let mut stmt = conn.prepare(
        "SELECT id, ssh_user_id, name, public_key, fingerprint, created_at FROM ssh_keys WHERE ssh_user_id = ?1
         ORDER BY id",
    )?;
    let rows = stmt.query_map(params![ssh_user_id], |r| {
        Ok(SshKey {
            id: r.get(0)?,
            ssh_user_id: r.get(1)?,
            name: r.get(2)?,
            public_key: r.get(3)?,
            fingerprint: r.get(4)?,
            created_at: r.get(5)?,
        })
    })?;
    rows.collect()
}

pub fn add_ssh_key(
    conn: &Connection,
    ssh_user_id: i64,
    name: &str,
    public_key: &str,
    fingerprint: &str,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO ssh_keys (ssh_user_id, name, public_key, fingerprint, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ssh_user_id, name, public_key, fingerprint, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_ssh_key(conn: &Connection, ssh_user_id: i64, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "DELETE FROM ssh_keys WHERE id = ?1 AND ssh_user_id = ?2",
        params![id, ssh_user_id],
    )? > 0)
}

// ---------- Firewall ----------

const RULE_COLS: &str = "id, port, port_end, protocol, action, source, comment, created_at";

fn rule_from_row(row: &Row) -> rusqlite::Result<FirewallRule> {
    Ok(FirewallRule {
        id: row.get(0)?,
        port: row.get(1)?,
        port_end: row.get(2)?,
        protocol: row.get(3)?,
        action: row.get(4)?,
        source: row.get(5)?,
        comment: row.get(6)?,
        created_at: row.get(7)?,
    })
}

pub fn list_firewall_rules(conn: &Connection) -> rusqlite::Result<Vec<FirewallRule>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {RULE_COLS} FROM firewall_rules ORDER BY port IS NULL DESC, port ASC, id ASC"
    ))?;
    let rows = stmt.query_map([], rule_from_row)?;
    rows.collect()
}

pub fn find_firewall_rule(conn: &Connection, id: i64) -> rusqlite::Result<Option<FirewallRule>> {
    conn.query_row(
        &format!("SELECT {RULE_COLS} FROM firewall_rules WHERE id = ?1"),
        params![id],
        rule_from_row,
    )
    .optional()
}

pub struct NewRule<'a> {
    pub port: Option<u16>,
    pub port_end: Option<u16>,
    pub protocol: &'a str,
    pub action: &'a str,
    pub source: Option<&'a str>,
    pub comment: Option<&'a str>,
}

pub fn firewall_rule_exists(conn: &Connection, r: &NewRule) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM firewall_rules WHERE port IS ?1 AND port_end IS ?2 AND protocol = ?3
             AND action = ?4 AND source IS ?5)",
        params![r.port, r.port_end, r.protocol, r.action, r.source],
        |r| r.get(0),
    )
}

/// Forget a rule with the same match as `r` but this `action`.
pub fn delete_firewall_rule_with_action(conn: &Connection, r: &NewRule, action: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM firewall_rules WHERE port IS ?1 AND port_end IS ?2 AND protocol = ?3
             AND action = ?4 AND source IS ?5",
        params![r.port, r.port_end, r.protocol, action, r.source],
    )
}

pub fn create_firewall_rule(conn: &Connection, r: &NewRule) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO firewall_rules (port, port_end, protocol, action, source, comment, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            r.port,
            r.port_end,
            r.protocol,
            r.action,
            r.source,
            r.comment,
            Utc::now()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_firewall_rule(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM firewall_rules WHERE id = ?1", params![id])? > 0)
}

// ---------- Cron ----------

const CRON_COLS: &str = "id, site_id, name, schedule, command, user, is_active, created_at";

fn cron_from_row(row: &Row) -> rusqlite::Result<CronJob> {
    Ok(CronJob {
        id: row.get(0)?,
        site_id: row.get(1)?,
        name: row.get(2)?,
        schedule: row.get(3)?,
        command: row.get(4)?,
        user: row.get(5)?,
        is_active: row.get(6)?,
        created_at: row.get(7)?,
    })
}

pub fn list_cron_jobs(conn: &Connection) -> rusqlite::Result<Vec<CronJob>> {
    let mut stmt = conn.prepare(&format!("SELECT {CRON_COLS} FROM cron_jobs ORDER BY id ASC"))?;
    let rows = stmt.query_map([], cron_from_row)?;
    rows.collect()
}

pub fn find_cron_job(conn: &Connection, id: i64) -> rusqlite::Result<Option<CronJob>> {
    conn.query_row(
        &format!("SELECT {CRON_COLS} FROM cron_jobs WHERE id = ?1"),
        params![id],
        cron_from_row,
    )
    .optional()
}

pub struct CronInput<'a> {
    pub site_id: Option<i64>,
    pub name: Option<&'a str>,
    pub schedule: &'a str,
    pub command: &'a str,
    pub user: &'a str,
    pub is_active: bool,
}

pub fn create_cron_job(conn: &Connection, j: &CronInput) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO cron_jobs (site_id, name, schedule, command, user, is_active, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            j.site_id,
            j.name,
            j.schedule,
            j.command,
            j.user,
            j.is_active,
            Utc::now()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update_cron_job(conn: &Connection, id: i64, j: &CronInput) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE cron_jobs SET site_id = ?1, name = ?2, schedule = ?3, command = ?4, user = ?5, is_active = ?6
         WHERE id = ?7",
        params![j.site_id, j.name, j.schedule, j.command, j.user, j.is_active, id],
    )? > 0)
}

pub fn delete_cron_job(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM cron_jobs WHERE id = ?1", params![id])? > 0)
}

pub fn record_cron_run(
    conn: &Connection,
    job_id: i64,
    started_at: DateTime<Utc>,
    duration_ms: i64,
    exit_code: Option<i32>,
    output: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO cron_runs (job_id, started_at, duration_ms, exit_code, output) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![job_id, started_at, duration_ms, exit_code, output],
    )?;
    // Keep the last 20 runs per job.
    conn.execute(
        "DELETE FROM cron_runs WHERE job_id = ?1 AND id NOT IN
             (SELECT id FROM cron_runs WHERE job_id = ?1 ORDER BY id DESC LIMIT 20)",
        params![job_id],
    )?;
    Ok(())
}

pub fn list_cron_runs(conn: &Connection, job_id: i64) -> rusqlite::Result<Vec<CronRun>> {
    let mut stmt = conn.prepare(
        "SELECT id, job_id, started_at, duration_ms, exit_code, output FROM cron_runs WHERE job_id = ?1
         ORDER BY id DESC",
    )?;
    let rows = stmt.query_map(params![job_id], |r| {
        Ok(CronRun {
            id: r.get(0)?,
            job_id: r.get(1)?,
            started_at: r.get(2)?,
            duration_ms: r.get(3)?,
            exit_code: r.get(4)?,
            output: r.get(5)?,
        })
    })?;
    rows.collect()
}

/// Latest run per job: (job_id, started_at, exit_code).
/// (job_id, started_at, exit_code)
pub type CronRunSummary = (i64, DateTime<Utc>, Option<i64>);

pub fn last_cron_runs(conn: &Connection) -> rusqlite::Result<Vec<CronRunSummary>> {
    let mut stmt = conn.prepare(
        "SELECT job_id, started_at, exit_code FROM cron_runs WHERE id IN (SELECT MAX(id) FROM cron_runs GROUP BY job_id)",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    rows.collect()
}

// ---------- Events (audit log) ----------

pub struct NewEvent<'a> {
    pub user_id: Option<i64>,
    pub username: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub action: &'a str,
    pub target: Option<&'a str>,
    pub detail: Option<&'a str>,
}

pub fn insert_event(conn: &Connection, e: &NewEvent) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO events (user_id, username, ip, action, target, detail, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![e.user_id, e.username, e.ip, e.action, e.target, e.detail, Utc::now()],
    )?;
    Ok(())
}

#[derive(Default)]
pub struct EventFilter {
    pub username: Option<String>,
    pub action: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub before_id: Option<i64>,
    pub limit: i64,
}

pub fn list_events(conn: &Connection, f: &EventFilter) -> rusqlite::Result<Vec<Event>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, username, ip, action, target, detail, created_at FROM events
         WHERE (?1 IS NULL OR username = ?1)
           AND (?2 IS NULL OR action LIKE ?2 || '%')
           AND (?3 IS NULL OR created_at >= ?3)
           AND (?4 IS NULL OR created_at <= ?4)
           AND (?5 IS NULL OR id < ?5)
         ORDER BY id DESC LIMIT ?6",
    )?;
    let rows = stmt.query_map(
        params![f.username, f.action, f.since, f.until, f.before_id, f.limit],
        |r| {
            Ok(Event {
                id: r.get(0)?,
                user_id: r.get(1)?,
                username: r.get(2)?,
                ip: r.get(3)?,
                action: r.get(4)?,
                target: r.get(5)?,
                detail: r.get(6)?,
                created_at: r.get(7)?,
            })
        },
    )?;
    rows.collect()
}

pub fn prune_events(conn: &Connection, older_than: DateTime<Utc>) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM events WHERE created_at < ?1", params![older_than])
}

// ---------- Jobs ----------

fn job_from_row(r: &Row) -> rusqlite::Result<Job> {
    Ok(Job {
        id: r.get(0)?,
        kind: r.get(1)?,
        target: r.get(2)?,
        status: r.get(3)?,
        output: r.get(4)?,
        user_id: r.get(5)?,
        started_at: r.get(6)?,
        finished_at: r.get(7)?,
    })
}

const JOB_COLS: &str = "id, kind, target, status, output, user_id, started_at, finished_at";

pub fn create_job(conn: &Connection, kind: &str, target: Option<&str>, user_id: Option<i64>) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO jobs (kind, target, status, output, user_id, started_at) VALUES (?1, ?2, 'running', '', ?3, ?4)",
        params![kind, target, user_id, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn append_job_output(conn: &Connection, id: i64, chunk: &str, cap: usize) -> rusqlite::Result<()> {
    // Keep the tail when the output grows past the cap.
    conn.execute(
        "UPDATE jobs SET output = substr(output || ?1, -?2) WHERE id = ?3",
        params![chunk, cap as i64, id],
    )?;
    Ok(())
}

pub fn finish_job(conn: &Connection, id: i64, ok: bool) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE jobs SET status = ?1, finished_at = ?2 WHERE id = ?3",
        params![if ok { "succeeded" } else { "failed" }, Utc::now(), id],
    )?;
    Ok(())
}

pub fn find_job(conn: &Connection, id: i64) -> rusqlite::Result<Option<Job>> {
    conn.query_row(
        &format!("SELECT {JOB_COLS} FROM jobs WHERE id = ?1"),
        params![id],
        job_from_row,
    )
    .optional()
}

pub fn list_jobs(conn: &Connection, limit: i64) -> rusqlite::Result<Vec<Job>> {
    let mut stmt = conn.prepare(&format!("SELECT {JOB_COLS} FROM jobs ORDER BY id DESC LIMIT ?1"))?;
    let rows = stmt.query_map(params![limit], job_from_row)?;
    rows.collect()
}

pub fn running_job_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM jobs WHERE status = 'running'", [], |r| r.get(0))
}

/// Jobs left "running" by a previous process can never finish; mark them failed.
pub fn fail_stale_jobs(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE jobs SET status = 'failed', output = output || '\n[interrupted: panel restarted]', finished_at = ?1
         WHERE status = 'running'",
        params![Utc::now()],
    )
}

pub fn prune_jobs(conn: &Connection, older_than: DateTime<Utc>) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM jobs WHERE status != 'running' AND started_at < ?1",
        params![older_than],
    )
}

// ---------- Databases ----------

pub fn list_databases(conn: &Connection, site_id: Option<i64>) -> rusqlite::Result<Vec<Database>> {
    let mut stmt = conn.prepare(
        "SELECT id, site_id, engine, name, created_at FROM databases WHERE (?1 IS NULL OR site_id = ?1)
         ORDER BY engine, name",
    )?;
    let rows = stmt.query_map(params![site_id], |r| {
        Ok(Database {
            id: r.get(0)?,
            site_id: r.get(1)?,
            engine: r.get(2)?,
            name: r.get(3)?,
            created_at: r.get(4)?,
            users: vec![],
        })
    })?;
    let mut dbs: Vec<Database> = rows.collect::<Result<_, _>>()?;
    for d in &mut dbs {
        d.users = list_database_users(conn, d.id)?;
    }
    Ok(dbs)
}

pub fn find_database(conn: &Connection, id: i64) -> rusqlite::Result<Option<Database>> {
    let db = conn
        .query_row(
            "SELECT id, site_id, engine, name, created_at FROM databases WHERE id = ?1",
            params![id],
            |r| {
                Ok(Database {
                    id: r.get(0)?,
                    site_id: r.get(1)?,
                    engine: r.get(2)?,
                    name: r.get(3)?,
                    created_at: r.get(4)?,
                    users: vec![],
                })
            },
        )
        .optional()?;
    match db {
        Some(mut d) => {
            d.users = list_database_users(conn, d.id)?;
            Ok(Some(d))
        }
        None => Ok(None),
    }
}

pub fn create_database(conn: &Connection, site_id: i64, engine: &str, name: &str) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO databases (site_id, engine, name, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![site_id, engine, name, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_database(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM databases WHERE id = ?1", params![id])? > 0)
}

pub fn list_database_users(conn: &Connection, database_id: i64) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT username FROM database_users WHERE database_id = ?1 ORDER BY username")?;
    let rows = stmt.query_map(params![database_id], |r| r.get(0))?;
    rows.collect()
}

pub fn add_database_user(conn: &Connection, database_id: i64, username: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO database_users (database_id, username, created_at) VALUES (?1, ?2, ?3)",
        params![database_id, username, Utc::now()],
    )?;
    Ok(())
}

pub fn delete_database_user(conn: &Connection, database_id: i64, username: &str) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "DELETE FROM database_users WHERE database_id = ?1 AND username = ?2",
        params![database_id, username],
    )? > 0)
}

pub fn database_user_exists(conn: &Connection, engine: &str, username: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM database_users u JOIN databases d ON d.id = u.database_id
             WHERE d.engine = ?1 AND u.username = ?2)",
        params![engine, username],
        |r| r.get(0),
    )
}

// ---------- Backups ----------

pub fn get_backup_policy(conn: &Connection, site_id: i64) -> rusqlite::Result<BackupPolicy> {
    Ok(conn
        .query_row(
            "SELECT site_id, frequency, hour, retention, remote_enabled, last_run FROM backup_policies WHERE site_id = ?1",
            params![site_id],
            policy_from_row,
        )
        .optional()?
        .unwrap_or(BackupPolicy {
            site_id,
            frequency: "off".into(),
            hour: 3,
            retention: 7,
            remote_enabled: false,
            last_run: None,
        }))
}

fn policy_from_row(r: &Row) -> rusqlite::Result<BackupPolicy> {
    Ok(BackupPolicy {
        site_id: r.get(0)?,
        frequency: r.get(1)?,
        hour: r.get(2)?,
        retention: r.get(3)?,
        remote_enabled: r.get(4)?,
        last_run: r.get(5)?,
    })
}

pub fn list_backup_policies(conn: &Connection) -> rusqlite::Result<Vec<BackupPolicy>> {
    let mut stmt = conn.prepare(
        "SELECT site_id, frequency, hour, retention, remote_enabled, last_run FROM backup_policies
         WHERE frequency != 'off'",
    )?;
    let rows = stmt.query_map([], policy_from_row)?;
    rows.collect()
}

pub fn save_backup_policy(conn: &Connection, p: &BackupPolicy) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO backup_policies (site_id, frequency, hour, retention, remote_enabled, last_run)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(site_id) DO UPDATE SET frequency = excluded.frequency, hour = excluded.hour,
             retention = excluded.retention, remote_enabled = excluded.remote_enabled, last_run = excluded.last_run",
        params![
            p.site_id,
            p.frequency,
            p.hour,
            p.retention,
            p.remote_enabled,
            p.last_run
        ],
    )?;
    Ok(())
}

fn backup_from_row(r: &Row) -> rusqlite::Result<Backup> {
    let path: String = r.get(3)?;
    let file_name = Path::new(&path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Backup {
        id: r.get(0)?,
        site_id: r.get(1)?,
        domain: r.get(2)?,
        path,
        file_name,
        size: r.get(4)?,
        status: r.get(5)?,
        remote_key: r.get(6)?,
        error: r.get(7)?,
        created_at: r.get(8)?,
    })
}

const BACKUP_COLS: &str = "id, site_id, domain, path, size, status, remote_key, error, created_at";

pub fn list_backups(conn: &Connection, site_id: Option<i64>) -> rusqlite::Result<Vec<Backup>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {BACKUP_COLS} FROM backups WHERE (?1 IS NULL OR site_id = ?1) ORDER BY id DESC"
    ))?;
    let rows = stmt.query_map(params![site_id], backup_from_row)?;
    rows.collect()
}

pub fn find_backup(conn: &Connection, id: i64) -> rusqlite::Result<Option<Backup>> {
    conn.query_row(
        &format!("SELECT {BACKUP_COLS} FROM backups WHERE id = ?1"),
        params![id],
        backup_from_row,
    )
    .optional()
}

pub fn create_backup(conn: &Connection, site_id: Option<i64>, domain: &str, path: &str) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO backups (site_id, domain, path, size, status, created_at) VALUES (?1, ?2, ?3, 0, 'running', ?4)",
        params![site_id, domain, path, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn finish_backup(
    conn: &Connection,
    id: i64,
    size: i64,
    error: Option<&str>,
    remote_key: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE backups SET size = ?1, status = ?2, error = ?3, remote_key = ?4 WHERE id = ?5",
        params![
            size,
            if error.is_some() { "failed" } else { "ok" },
            error,
            remote_key,
            id
        ],
    )?;
    Ok(())
}

pub fn delete_backup(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM backups WHERE id = ?1", params![id])? > 0)
}

// ---------- Alerts ----------

fn channel_from_row(r: &Row) -> rusqlite::Result<AlertChannel> {
    Ok(AlertChannel {
        id: r.get(0)?,
        kind: r.get(1)?,
        name: r.get(2)?,
        config: r.get(3)?,
        enabled: r.get(4)?,
        created_at: r.get(5)?,
    })
}

pub fn list_alert_channels(conn: &Connection) -> rusqlite::Result<Vec<AlertChannel>> {
    let mut stmt =
        conn.prepare("SELECT id, kind, name, config, enabled, created_at FROM alert_channels ORDER BY id")?;
    let rows = stmt.query_map([], channel_from_row)?;
    rows.collect()
}

pub fn find_alert_channel(conn: &Connection, id: i64) -> rusqlite::Result<Option<AlertChannel>> {
    conn.query_row(
        "SELECT id, kind, name, config, enabled, created_at FROM alert_channels WHERE id = ?1",
        params![id],
        channel_from_row,
    )
    .optional()
}

pub fn create_alert_channel(conn: &Connection, kind: &str, name: &str, config: &str) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO alert_channels (kind, name, config, enabled, created_at) VALUES (?1, ?2, ?3, 1, ?4)",
        params![kind, name, config, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn set_alert_channel_enabled(conn: &Connection, id: i64, enabled: bool) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE alert_channels SET enabled = ?1 WHERE id = ?2",
        params![enabled, id],
    )? > 0)
}

pub fn delete_alert_channel(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM alert_channels WHERE id = ?1", params![id])? > 0)
}

/// Alert state: (firing, since, last_sent).
pub type AlertState = (bool, Option<DateTime<Utc>>, Option<DateTime<Utc>>);

pub fn get_alert_state(conn: &Connection, key: &str) -> rusqlite::Result<AlertState> {
    Ok(conn
        .query_row(
            "SELECT firing, since, last_sent FROM alert_state WHERE key = ?1",
            params![key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .unwrap_or((false, None, None)))
}

pub fn set_alert_state(
    conn: &Connection,
    key: &str,
    firing: bool,
    since: Option<DateTime<Utc>>,
    last_sent: Option<DateTime<Utc>>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO alert_state (key, firing, since, last_sent) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO UPDATE SET firing = excluded.firing, since = excluded.since, last_sent = excluded.last_sent",
        params![key, firing, since, last_sent],
    )?;
    Ok(())
}

// ---------- WireGuard ----------

const WG_COLS: &str = "id, name, address, public_key, private_key, preshared_key, allowed_ips, server_allowed_ips, \
                       extra, enabled, imported, created_at";

fn wg_from_row(r: &Row) -> rusqlite::Result<WireguardClient> {
    Ok(WireguardClient {
        id: r.get(0)?,
        name: r.get(1)?,
        address: r.get(2)?,
        public_key: r.get(3)?,
        private_key: r.get(4)?,
        preshared_key: r.get(5)?,
        allowed_ips: r.get(6)?,
        server_allowed_ips: r.get(7)?,
        extra: r.get(8)?,
        enabled: r.get(9)?,
        imported: r.get(10)?,
        created_at: r.get(11)?,
    })
}

pub fn list_wireguard_clients(conn: &Connection) -> rusqlite::Result<Vec<WireguardClient>> {
    let mut stmt = conn.prepare(&format!("SELECT {WG_COLS} FROM wireguard_clients ORDER BY id"))?;
    let rows = stmt.query_map([], wg_from_row)?;
    rows.collect()
}

pub fn find_wireguard_client(conn: &Connection, id: i64) -> rusqlite::Result<Option<WireguardClient>> {
    conn.query_row(
        &format!("SELECT {WG_COLS} FROM wireguard_clients WHERE id = ?1"),
        params![id],
        wg_from_row,
    )
    .optional()
}

pub struct NewWireguardClient<'a> {
    pub name: &'a str,
    pub address: Option<&'a str>,
    pub public_key: &'a str,
    pub private_key: Option<&'a str>,
    pub preshared_key: Option<&'a str>,
    pub allowed_ips: &'a str,
    pub server_allowed_ips: &'a str,
    pub extra: &'a str,
    pub enabled: bool,
    pub imported: bool,
}

pub fn create_wireguard_client(conn: &Connection, c: &NewWireguardClient) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO wireguard_clients (name, address, public_key, private_key, preshared_key, allowed_ips,
             server_allowed_ips, extra, enabled, imported, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            c.name,
            c.address,
            c.public_key,
            c.private_key,
            c.preshared_key,
            c.allowed_ips,
            c.server_allowed_ips,
            c.extra,
            c.enabled,
            c.imported,
            Utc::now()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Saves what can change after creation: the name, routes, enabled flag and a private key added
/// to an imported peer.
pub fn save_wireguard_client(conn: &Connection, c: &WireguardClient) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE wireguard_clients SET name = ?1, private_key = ?2, allowed_ips = ?3, server_allowed_ips = ?4,
             enabled = ?5 WHERE id = ?6",
        params![
            c.name,
            c.private_key,
            c.allowed_ips,
            c.server_allowed_ips,
            c.enabled,
            c.id
        ],
    )? > 0)
}

pub fn delete_wireguard_client(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM wireguard_clients WHERE id = ?1", params![id])? > 0)
}

// ---------- Object storage (Garage) ----------

const STORAGE_BUCKET_COLS: &str = "b.id, b.garage_id, b.name, b.site_id, s.domain, b.created_at";

fn storage_bucket_row(r: &Row) -> rusqlite::Result<StorageBucket> {
    Ok(StorageBucket {
        id: r.get(0)?,
        garage_id: r.get(1)?,
        name: r.get(2)?,
        site_id: r.get(3)?,
        site_domain: r.get(4)?,
        created_at: r.get(5)?,
    })
}

/// Every bucket, or only those of one site.
pub fn list_storage_buckets(conn: &Connection, site_id: Option<i64>) -> rusqlite::Result<Vec<StorageBucket>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {STORAGE_BUCKET_COLS} FROM storage_buckets b LEFT JOIN sites s ON s.id = b.site_id
         WHERE (?1 IS NULL OR b.site_id = ?1) ORDER BY b.name"
    ))?;
    let rows = stmt.query_map(params![site_id], storage_bucket_row)?;
    rows.collect()
}

pub fn find_storage_bucket(conn: &Connection, id: i64) -> rusqlite::Result<Option<StorageBucket>> {
    conn.query_row(
        &format!(
            "SELECT {STORAGE_BUCKET_COLS} FROM storage_buckets b LEFT JOIN sites s ON s.id = b.site_id WHERE b.id = ?1"
        ),
        params![id],
        storage_bucket_row,
    )
    .optional()
}

pub fn create_storage_bucket(
    conn: &Connection,
    garage_id: &str,
    name: &str,
    site_id: Option<i64>,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO storage_buckets (garage_id, name, site_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![garage_id, name, site_id, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn set_storage_bucket_site(conn: &Connection, id: i64, site_id: Option<i64>) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE storage_buckets SET site_id = ?2 WHERE id = ?1",
        params![id, site_id],
    )? > 0)
}

pub fn delete_storage_bucket(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM storage_buckets WHERE id = ?1", params![id])? > 0)
}

const STORAGE_KEY_COLS: &str = "k.id, k.garage_key_id, k.name, k.site_id, s.domain, k.created_at";

fn storage_key_row(r: &Row) -> rusqlite::Result<StorageKey> {
    Ok(StorageKey {
        id: r.get(0)?,
        garage_key_id: r.get(1)?,
        name: r.get(2)?,
        site_id: r.get(3)?,
        site_domain: r.get(4)?,
        created_at: r.get(5)?,
    })
}

pub fn list_storage_keys(conn: &Connection, site_id: Option<i64>) -> rusqlite::Result<Vec<StorageKey>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {STORAGE_KEY_COLS} FROM storage_keys k LEFT JOIN sites s ON s.id = k.site_id
         WHERE (?1 IS NULL OR k.site_id = ?1) ORDER BY k.name, k.id"
    ))?;
    let rows = stmt.query_map(params![site_id], storage_key_row)?;
    rows.collect()
}

pub fn find_storage_key(conn: &Connection, id: i64) -> rusqlite::Result<Option<StorageKey>> {
    conn.query_row(
        &format!("SELECT {STORAGE_KEY_COLS} FROM storage_keys k LEFT JOIN sites s ON s.id = k.site_id WHERE k.id = ?1"),
        params![id],
        storage_key_row,
    )
    .optional()
}

pub fn create_storage_key(
    conn: &Connection,
    garage_key_id: &str,
    name: &str,
    site_id: Option<i64>,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO storage_keys (garage_key_id, name, site_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![garage_key_id, name, site_id, Utc::now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn set_storage_key_site(conn: &Connection, id: i64, site_id: Option<i64>) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE storage_keys SET site_id = ?2 WHERE id = ?1",
        params![id, site_id],
    )? > 0)
}

pub fn delete_storage_key(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM storage_keys WHERE id = ?1", params![id])? > 0)
}

/// Bring the panel's list in line with what Garage has: adopt buckets and keys made elsewhere
/// (unlinked, so only admins see them), forget those deleted elsewhere, follow renames.
pub fn sync_storage(
    conn: &Connection,
    buckets: &[(String, String)],
    keys: &[(String, String)],
) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    let known: Vec<StorageBucket> = list_storage_buckets(&tx, None)?;
    for b in &known {
        match buckets.iter().find(|(id, _)| *id == b.garage_id) {
            None => {
                delete_storage_bucket(&tx, b.id)?;
            }
            Some((_, name)) if *name != b.name => {
                tx.execute(
                    "UPDATE storage_buckets SET name = ?2 WHERE id = ?1",
                    params![b.id, name],
                )?;
            }
            _ => {}
        }
    }
    for (id, name) in buckets {
        if !known.iter().any(|b| b.garage_id == *id) {
            tx.execute(
                "INSERT OR IGNORE INTO storage_buckets (garage_id, name, site_id, created_at) VALUES (?1, ?2, NULL, ?3)",
                params![id, name, Utc::now()],
            )?;
        }
    }
    let known: Vec<StorageKey> = list_storage_keys(&tx, None)?;
    for k in &known {
        match keys.iter().find(|(id, _)| *id == k.garage_key_id) {
            None => {
                delete_storage_key(&tx, k.id)?;
            }
            Some((_, name)) if *name != k.name => {
                tx.execute("UPDATE storage_keys SET name = ?2 WHERE id = ?1", params![k.id, name])?;
            }
            _ => {}
        }
    }
    for (id, name) in keys {
        if !known.iter().any(|k| k.garage_key_id == *id) {
            create_storage_key(&tx, id, name, None)?;
        }
    }
    tx.commit()
}

#[cfg(test)]
pub fn test_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    migrate(&conn).unwrap();
    conn
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pooled_connection_gets_the_settings() {
        let dir = tempfile::tempdir().unwrap();
        let pool = init_db(&dir.path().join("cp.db")).unwrap();
        // Holding them all at once forces the pool to hand out different connections.
        let conns: Vec<_> = (0..pool.max_size()).map(|_| pool.get().unwrap()).collect();
        for c in &conns {
            let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
            let busy: i64 = c.query_row("PRAGMA busy_timeout", [], |r| r.get(0)).unwrap();
            let journal: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
            assert_eq!((fk, busy, journal.as_str()), (1, 5000, "wal"));
        }
    }

    #[test]
    fn deleting_a_site_cascades_through_the_pool() {
        let dir = tempfile::tempdir().unwrap();
        let pool = init_db(&dir.path().join("cp.db")).unwrap();
        let c = pool.get().unwrap();
        c.execute(
            "INSERT INTO sites (domain, site_type) VALUES ('a.example.com', 'static')",
            [],
        )
        .unwrap();
        let id = c.last_insert_rowid();
        create_database(&c, id, "sqlite", "a").unwrap();
        assert!(delete_site(&c, id).unwrap());
        let left: i64 = c.query_row("SELECT COUNT(*) FROM databases", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0, "foreign keys must be enforced");
    }

    #[test]
    fn migrations_are_idempotent() {
        let conn = test_conn();
        migrate(&conn).unwrap();
        assert_eq!(
            get_setting(&conn, "schema_version").unwrap().unwrap(),
            schema::MIGRATIONS.len().to_string()
        );
    }

    #[test]
    fn legacy_firewall_rows_survive_rebuild() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(schema::CREATE_TABLES).unwrap();
        conn.execute(
            "INSERT INTO firewall_rules (port, protocol, action, comment, created_at) VALUES (3306, 'tcp', 'allow', 'db', ?1)",
            params![Utc::now()],
        )
        .unwrap();
        migrate(&conn).unwrap();
        let rules = list_firewall_rules(&conn).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].port, Some(3306));
        assert_eq!(rules[0].source, None);
    }

    #[test]
    fn job_output_is_capped_to_tail() {
        let conn = test_conn();
        let id = create_job(&conn, "test", None, None).unwrap();
        append_job_output(&conn, id, "abcdef", 4).unwrap();
        append_job_output(&conn, id, "gh", 4).unwrap();
        assert_eq!(find_job(&conn, id).unwrap().unwrap().output, "efgh");
    }
}
