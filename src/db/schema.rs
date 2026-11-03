pub const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'admin',
    totp_secret TEXT,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    site_type TEXT NOT NULL, -- 'nodejs', 'python', 'static', 'docker_proxy', 'reverse_proxy'
    target_port INTEGER,
    document_root TEXT,
    system_user TEXT NOT NULL DEFAULT 'cloudpanel',
    include_www BOOLEAN NOT NULL DEFAULT 0,
    ssl_enabled BOOLEAN NOT NULL DEFAULT 0,
    ssl_auto_renew BOOLEAN NOT NULL DEFAULT 1,
    ssl_cert_path TEXT,
    ssl_key_path TEXT,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp', -- 'tcp', 'udp', 'any'
    action TEXT NOT NULL DEFAULT 'allow', -- 'allow', 'deny'
    comment TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cron_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    schedule TEXT NOT NULL,
    command TEXT NOT NULL,
    user TEXT NOT NULL DEFAULT 'root',
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sites_type ON sites(site_type);
CREATE INDEX IF NOT EXISTS idx_cron_site ON cron_jobs(site_id);
"#;

/// Columns added after the first release: (table, column, definition).
pub const MIGRATIONS: &[(&str, &str, &str)] = &[
    ("users", "token_version", "INTEGER NOT NULL DEFAULT 0"),
    ("sites", "include_www", "BOOLEAN NOT NULL DEFAULT 0"),
];
