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
    site_type TEXT NOT NULL, -- 'nodejs', 'python', 'static', 'php', 'docker_proxy', 'reverse_proxy'
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

/// Columns added before versioned migrations existed: (table, column, definition).
/// Applied idempotently on every start so databases from v0.1 upgrade cleanly.
pub const LEGACY_COLUMNS: &[(&str, &str, &str)] = &[
    ("users", "token_version", "INTEGER NOT NULL DEFAULT 0"),
    ("sites", "include_www", "BOOLEAN NOT NULL DEFAULT 0"),
];

/// Versioned migrations. Entry `i` brings the schema to version `i + 1`.
/// Never edit or reorder an entry once released; append new ones.
pub const MIGRATIONS: &[&str] = &[
    // 1: RBAC, audit log, background jobs
    r#"
    CREATE TABLE user_sites (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, site_id)
    );
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        ip TEXT,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT,
        created_at DATETIME NOT NULL
    );
    CREATE INDEX idx_events_created ON events(created_at);
    CREATE INDEX idx_events_action ON events(action);
    CREATE TABLE jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        target TEXT,
        status TEXT NOT NULL, -- running, succeeded, failed
        output TEXT NOT NULL DEFAULT '',
        user_id INTEGER,
        started_at DATETIME NOT NULL,
        finished_at DATETIME
    );
    "#,
    // 2: hosting (site users, ssh, apps, site management)
    r#"
    ALTER TABLE sites ADD COLUMN app_command TEXT;
    ALTER TABLE sites ADD COLUMN app_workdir TEXT;
    ALTER TABLE sites ADD COLUMN app_env TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE sites ADD COLUMN app_enabled BOOLEAN NOT NULL DEFAULT 0;
    ALTER TABLE sites ADD COLUMN home_dir TEXT;
    ALTER TABLE sites ADD COLUMN websocket BOOLEAN NOT NULL DEFAULT 1;
    ALTER TABLE sites ADD COLUMN max_body_mb INTEGER NOT NULL DEFAULT 128;
    ALTER TABLE sites ADD COLUMN custom_directives TEXT NOT NULL DEFAULT '';
    ALTER TABLE sites ADD COLUMN basic_auth_enabled BOOLEAN NOT NULL DEFAULT 0;
    ALTER TABLE sites ADD COLUMN basic_auth_allow TEXT NOT NULL DEFAULT '';
    CREATE TABLE basic_auth_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        UNIQUE(site_id, username)
    );
    CREATE TABLE ssh_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        username TEXT NOT NULL UNIQUE,
        sftp_only BOOLEAN NOT NULL DEFAULT 0,
        is_owner BOOLEAN NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL
    );
    CREATE TABLE ssh_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ssh_user_id INTEGER NOT NULL REFERENCES ssh_users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        created_at DATETIME NOT NULL
    );
    "#,
    // 3: databases & backups
    r#"
    CREATE TABLE databases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        engine TEXT NOT NULL, -- mariadb, mongodb, sqlite
        name TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        UNIQUE(engine, name)
    );
    CREATE TABLE database_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        database_id INTEGER NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        UNIQUE(database_id, username)
    );
    CREATE TABLE backup_policies (
        site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
        frequency TEXT NOT NULL DEFAULT 'off', -- off, daily, weekly
        hour INTEGER NOT NULL DEFAULT 3,
        retention INTEGER NOT NULL DEFAULT 7,
        remote_enabled BOOLEAN NOT NULL DEFAULT 0,
        last_run DATETIME
    );
    CREATE TABLE backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL,
        domain TEXT NOT NULL,
        path TEXT NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL, -- running, ok, failed
        remote_key TEXT,
        error TEXT,
        created_at DATETIME NOT NULL
    );
    "#,
    // 4: security (2FA, richer firewall)
    r#"
    ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN recovery_codes TEXT NOT NULL DEFAULT '[]';
    CREATE TABLE firewall_rules_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        port INTEGER,
        port_end INTEGER,
        protocol TEXT NOT NULL DEFAULT 'tcp',
        action TEXT NOT NULL DEFAULT 'allow',
        source TEXT,
        comment TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO firewall_rules_new (id, port, protocol, action, comment, created_at)
        SELECT id, port, protocol, action, comment, created_at FROM firewall_rules;
    DROP TABLE firewall_rules;
    ALTER TABLE firewall_rules_new RENAME TO firewall_rules;
    "#,
    // 5: extras (cron runs, alerts)
    r#"
    ALTER TABLE cron_jobs ADD COLUMN name TEXT;
    CREATE TABLE cron_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL REFERENCES cron_jobs(id) ON DELETE CASCADE,
        started_at DATETIME NOT NULL,
        duration_ms INTEGER NOT NULL,
        exit_code INTEGER,
        output TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_cron_runs_job ON cron_runs(job_id, id);
    CREATE TABLE alert_channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL, -- email, webhook, slack, discord
        name TEXT NOT NULL,
        config TEXT NOT NULL, -- encrypted JSON
        enabled BOOLEAN NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL
    );
    CREATE TABLE alert_state (
        key TEXT PRIMARY KEY,
        firing BOOLEAN NOT NULL DEFAULT 0,
        since DATETIME,
        last_sent DATETIME
    );
    "#,
    // 6: PM2 process manager, www redirect. Existing rows keep systemd and their www behaviour.
    r#"
    ALTER TABLE sites ADD COLUMN app_manager TEXT NOT NULL DEFAULT 'systemd';
    ALTER TABLE sites ADD COLUMN app_pm2 TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE sites ADD COLUMN www_redirect BOOLEAN NOT NULL DEFAULT 0;
    "#,
    // 7: PHP sites, and sites imported from CloudPanel CE, whose nginx config the panel must not
    // regenerate because it can't reproduce what CE wrote.
    r#"
    ALTER TABLE sites ADD COLUMN php_version TEXT;
    ALTER TABLE sites ADD COLUMN vhost_managed BOOLEAN NOT NULL DEFAULT 1;
    "#,
    // 8: sessions ended by signing out, until they would have expired anyway.
    r#"
    CREATE TABLE revoked_tokens (
        hash TEXT PRIMARY KEY,
        expires_at DATETIME NOT NULL
    );
    "#,
    // 9: WireGuard clients. Keys are encrypted; an imported peer has no private key.
    r#"
    CREATE TABLE wireguard_clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        address TEXT UNIQUE,
        public_key TEXT NOT NULL UNIQUE,
        private_key TEXT,
        preshared_key TEXT,
        allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0',
        server_allowed_ips TEXT NOT NULL DEFAULT '',
        extra TEXT NOT NULL DEFAULT '',
        enabled BOOLEAN NOT NULL DEFAULT 1,
        imported BOOLEAN NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL
    );
    "#,
    // 10: Garage buckets and access keys. Garage holds them and their grants; the panel only
    // records which site each belongs to. Deleting a site keeps its buckets, unlinked.
    r#"
    CREATE TABLE storage_buckets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        garage_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL
    );
    CREATE TABLE storage_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        garage_key_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL
    );
    CREATE INDEX storage_buckets_site ON storage_buckets(site_id);
    CREATE INDEX storage_keys_site ON storage_keys(site_id);
    "#,
];
