//! Import from a CloudPanel CE panel database (`/home/clp/htdocs/app/data/db.sq3`) into this
//! panel's records. See `migrate-from-ce.sh`, which runs it on a copy of that file.
//!
//! This only writes this panel's own database. It never touches nginx, PHP-FPM, MySQL or a site's
//! files, so the sites keep running on exactly what CE set up. Imported sites have
//! `vhost_managed = false`, which stops the panel from regenerating their nginx config. What the
//! panel records about a site's root and certificate is read from that config, not from CE's
//! database, because the CE vhost editor lets the two differ and the file is what nginx serves.
//!
//! Running it again adds only what's new, so it can follow up on changes made in CE in between.

use super::cmd::{run_with, CmdOpts};
use super::sysusers;
use crate::auth::{hash_password, random_password};
use crate::config::Config;
use crate::db;
use crate::validate;
use chrono::Utc;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// What was found in a CE vhost.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct VhostFacts {
    pub root: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub serves_www: bool,
}

/// The value of a one-line directive, without comments or the `;`.
fn directive_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(name)?;
    if !rest.starts_with([' ', '\t']) {
        return None;
    }
    let value = rest.split(';').next()?.trim();
    (!value.is_empty()).then_some(value)
}

/// Read the facts this panel records from a CE vhost. The first of each directive wins: CE puts
/// the public server first, and the PHP vhost's second server on port 8080 repeats the root.
pub fn parse_vhost(text: &str, domain: &str) -> VhostFacts {
    let www = format!("www.{domain}");
    let mut facts = VhostFacts::default();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if facts.root.is_none() {
            facts.root = directive_value(line, "root").map(str::to_string);
        }
        if facts.cert.is_none() {
            facts.cert = directive_value(line, "ssl_certificate").map(str::to_string);
        }
        if facts.key.is_none() {
            facts.key = directive_value(line, "ssl_certificate_key").map(str::to_string);
        }
        if let Some(names) = directive_value(line, "server_name") {
            facts.serves_www |= names.split_whitespace().any(|n| n == www);
        }
    }
    facts
}

/// This panel's name for a CE site type.
pub fn map_site_type(ce_type: &str) -> Option<&'static str> {
    match ce_type {
        "php" => Some("php"),
        "static" => Some("static"),
        "nodejs" => Some("nodejs"),
        "python" => Some("python"),
        "reverse-proxy" => Some("reverse_proxy"),
        _ => None,
    }
}

/// The port of a reverse proxy to this machine. A site proxying anywhere else has none, as this
/// panel only models local targets. Its vhost keeps working regardless.
pub fn local_proxy_port(url: &str) -> Option<u16> {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split('/').next()?;
    let (host, port) = authority.rsplit_once(':')?;
    if host != "127.0.0.1" && host != "localhost" {
        return None;
    }
    port.parse().ok()
}

/// A CE role in this panel's terms. CE's `ROLE_ADMIN` administers the server; the others only see
/// their assigned sites.
pub fn map_role(ce_role: &str) -> &'static str {
    if ce_role.to_ascii_lowercase().contains("admin") && !ce_role.to_ascii_lowercase().contains("site") {
        crate::db::models::ROLE_ADMIN
    } else {
        crate::db::models::ROLE_SITE_MANAGER
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub sites_imported: Vec<String>,
    pub sites_existing: Vec<String>,
    /// PHP sites left out because PHP isn't enabled. They keep running, unmanaged.
    pub php_skipped: Vec<String>,
    pub problems: Vec<String>,
    pub databases: usize,
    pub database_users: usize,
    pub ssh_users: usize,
    /// (username, new password) for accounts created now. CE's password hashes can't be reused.
    pub users_created: Vec<(String, String)>,
    pub users_existing: Vec<String>,
    /// Things that carry on working but that this panel doesn't show.
    pub notes: Vec<String>,
}

struct CeSite {
    id: i64,
    domain: String,
    site_type: String,
    user: String,
    reverse_proxy_url: Option<String>,
    php_version: Option<String>,
    app_port: Option<u16>,
}

fn read_sites(ce: &Connection) -> rusqlite::Result<Vec<CeSite>> {
    let mut stmt = ce.prepare(
        "SELECT s.id, s.domain_name, s.type, s.user, s.reverse_proxy_url, p.php_version,
                COALESCE(n.port, py.port)
         FROM site s
         LEFT JOIN php_settings p ON p.site_id = s.id
         LEFT JOIN nodejs_settings n ON n.site_id = s.id
         LEFT JOIN python_settings py ON py.site_id = s.id
         ORDER BY s.id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(CeSite {
            id: r.get(0)?,
            domain: r.get(1)?,
            site_type: r.get(2)?,
            user: r.get(3)?,
            reverse_proxy_url: r.get(4)?,
            php_version: r.get(5)?,
            app_port: r.get::<_, Option<i64>>(6)?.and_then(|p| u16::try_from(p).ok()),
        })
    })?;
    rows.collect()
}

fn count(ce: &Connection, sql: &str) -> i64 {
    ce.query_row(sql, [], |r| r.get(0)).unwrap_or(0)
}

/// Import one site. Returns this panel's site id, or `None` with the reason in the report.
fn import_site(config: &Config, tx: &Connection, ce: &CeSite, report: &mut Report) -> rusqlite::Result<Option<i64>> {
    if let Some(id) = tx
        .query_row("SELECT id FROM sites WHERE domain = ?1", [&ce.domain], |r| r.get(0))
        .optional()?
    {
        report.sites_existing.push(ce.domain.clone());
        return Ok(Some(id));
    }
    let Some(site_type) = map_site_type(&ce.site_type) else {
        report.problems.push(format!(
            "{}: unknown site type '{}', not imported",
            ce.domain, ce.site_type
        ));
        return Ok(None);
    };
    if site_type == "php" && !config.php_enabled {
        report.php_skipped.push(ce.domain.clone());
        return Ok(None);
    }
    if let Err(e) = validate::domain(&ce.domain) {
        report.problems.push(format!("{}: {e}, not imported", ce.domain));
        return Ok(None);
    }
    let vhost_path = config.nginx_sites_enabled.join(format!("{}.conf", ce.domain));
    let Ok(vhost) = fs::read_to_string(&vhost_path) else {
        report.problems.push(format!(
            "{}: {} can't be read, not imported",
            ce.domain,
            vhost_path.display()
        ));
        return Ok(None);
    };
    if !sysusers::user_exists(&ce.user) {
        report.problems.push(format!(
            "{}: Linux user '{}' doesn't exist, not imported",
            ce.domain, ce.user
        ));
        return Ok(None);
    }
    let facts = parse_vhost(&vhost, &ce.domain);
    let target_port = match site_type {
        "reverse_proxy" => {
            let port = ce.reverse_proxy_url.as_deref().and_then(local_proxy_port);
            if port.is_none() {
                report.notes.push(format!(
                    "{}: proxies to {}, which the panel can't show as a local port. Its nginx config still does this.",
                    ce.domain,
                    ce.reverse_proxy_url.as_deref().unwrap_or("an unknown address")
                ));
            }
            port
        }
        _ => ce.app_port,
    };
    let php_version = (site_type == "php").then(|| ce.php_version.clone()).flatten();
    let home = format!("{}/{}", validate::absolute(&config.home_dir).display(), ce.user);
    // A vhost naming a certificate that isn't on disk couldn't load anyway, so record it as no TLS.
    let tls = facts
        .cert
        .as_deref()
        .zip(facts.key.as_deref())
        .filter(|(c, k)| Path::new(c).exists() && Path::new(k).exists());
    let now = Utc::now();
    tx.execute(
        "INSERT INTO sites (domain, site_type, target_port, document_root, system_user, include_www, www_redirect,
                            ssl_enabled, ssl_auto_renew, ssl_cert_path, ssl_key_path, is_active, home_dir,
                            app_enabled, php_version, vhost_managed, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, 0, ?8, ?9, 1, ?10, 0, ?11, 0, ?12, ?12)",
        params![
            ce.domain,
            site_type,
            target_port,
            facts.root,
            ce.user,
            facts.serves_www,
            tls.is_some(),
            tls.map(|t| t.0),
            tls.map(|t| t.1),
            home,
            php_version,
            now,
        ],
    )?;
    let id = tx.last_insert_rowid();
    db::create_ssh_user(tx, id, &ce.user, false, true)?;
    report.sites_imported.push(ce.domain.clone());
    Ok(Some(id))
}

fn import_databases(
    ce: &Connection,
    tx: &Connection,
    ce_site: i64,
    site: i64,
    report: &mut Report,
) -> rusqlite::Result<()> {
    let mut stmt = ce.prepare("SELECT id, name FROM \"database\" WHERE site_id = ?1")?;
    let dbs: Vec<(i64, String)> = stmt
        .query_map([ce_site], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut users = ce.prepare("SELECT user_name FROM database_user WHERE database_id = ?1")?;
    for (ce_db, name) in dbs {
        let id: i64 = match tx
            .query_row(
                "SELECT id FROM databases WHERE engine = 'mariadb' AND name = ?1",
                [&name],
                |r| r.get(0),
            )
            .optional()?
        {
            Some(id) => id,
            None => {
                report.databases += 1;
                db::create_database(tx, site, "mariadb", &name)?
            }
        };
        let names: Vec<String> = users.query_map([ce_db], |r| r.get(0))?.collect::<Result<_, _>>()?;
        for user in names {
            let added = tx.execute(
                "INSERT OR IGNORE INTO database_users (database_id, username, created_at) VALUES (?1, ?2, ?3)",
                params![id, user, Utc::now()],
            )?;
            report.database_users += added;
        }
    }
    Ok(())
}

fn import_ssh_users(
    ce: &Connection,
    tx: &Connection,
    ce_site: i64,
    site: i64,
    report: &mut Report,
) -> rusqlite::Result<()> {
    let mut stmt = ce.prepare("SELECT user_name FROM ssh_user WHERE site_id = ?1")?;
    let names: Vec<String> = stmt.query_map([ce_site], |r| r.get(0))?.collect::<Result<_, _>>()?;
    for name in names {
        if !sysusers::user_exists(&name) {
            report
                .problems
                .push(format!("SSH user '{name}' has no Linux account, not imported"));
            continue;
        }
        let added = tx.execute(
            "INSERT OR IGNORE INTO ssh_users (site_id, username, sftp_only, is_owner, created_at)
             VALUES (?1, ?2, 0, 0, ?3)",
            params![site, name, Utc::now()],
        )?;
        report.ssh_users += added;
    }
    Ok(())
}

fn import_users(
    ce: &Connection,
    tx: &Connection,
    ids: &HashMap<i64, i64>,
    report: &mut Report,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stmt = ce.prepare("SELECT id, user_name, email, role FROM user ORDER BY id")?;
    let users: Vec<(i64, String, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    let mut sites = ce.prepare("SELECT site_id FROM user_sites WHERE user_id = ?1")?;
    for (ce_id, username, email, role) in users {
        let taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1 OR email = ?2)",
            params![username, email],
            |r| r.get(0),
        )?;
        if taken {
            report.users_existing.push(username);
            continue;
        }
        let password = random_password(20);
        let id = db::create_user(tx, &username, &hash_password(&password)?, &email, map_role(&role))?;
        let ce_sites: Vec<i64> = sites.query_map([ce_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
        let site_ids: Vec<i64> = ce_sites.iter().filter_map(|s| ids.get(s).copied()).collect();
        db::set_user_sites(tx, id, &site_ids)?;
        report.users_created.push((username, password));
    }
    Ok(())
}

fn collect_notes(ce: &Connection, report: &mut Report) {
    let mut note = |sql: &str, text: &str| {
        let n = count(ce, sql);
        if n > 0 {
            report.notes.push(format!("{n} {text}"));
        }
    };
    note(
        "SELECT COUNT(*) FROM cron_job",
        "cron job(s) stay in their site users' crontabs and keep running. The panel doesn't list them.",
    );
    note(
        "SELECT COUNT(*) FROM ftp_user",
        "FTP user(s) keep working through ProFTPD. The panel doesn't list them.",
    );
    note(
        "SELECT COUNT(*) FROM firewall_rule",
        "CE firewall rule(s) stay in place in UFW. Check that they appear under Firewall.",
    );
    note(
        "SELECT COUNT(*) FROM basic_auth WHERE is_active = 1",
        "site(s) with basic auth keep it through their nginx config. The panel doesn't show it as enabled.",
    );
    note(
        "SELECT COUNT(*) FROM site WHERE varnish_cache = 1 AND type = 'php'",
        "PHP site(s) have CE's Varnish setting on. Their nginx config is unchanged, so requests take the same path.",
    );
}

/// Run the import. With `dry_run`, everything is checked and reported and then rolled back.
pub fn run(
    config: &Config,
    conn: &mut Connection,
    source: &Path,
    dry_run: bool,
) -> Result<Report, Box<dyn std::error::Error>> {
    let ce = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut report = Report::default();
    let tx = conn.transaction()?;
    let mut ids = HashMap::new();
    let sites = read_sites(&ce)?;
    for site in &sites {
        if let Some(id) = import_site(config, &tx, site, &mut report)? {
            ids.insert(site.id, id);
            import_databases(&ce, &tx, site.id, id, &mut report)?;
            import_ssh_users(&ce, &tx, site.id, id, &mut report)?;
        }
    }
    import_users(&ce, &tx, &ids, &mut report)?;
    collect_notes(&ce, &mut report);
    if dry_run {
        tx.rollback()?;
        return Ok(report);
    }
    tx.commit()?;
    // Lets the panel manage SSH keys for the imported accounts. Group membership doesn't affect
    // anything the sites do, and a failure here only matters for that later.
    for site in &sites {
        if report.sites_imported.contains(&site.domain) {
            let r = run_with(
                "usermod",
                &["-a", "-G", sysusers::USERS_GROUP, "--", &site.user],
                &CmdOpts::default().timeout(30),
            );
            if !r.missing && !r.success() {
                report
                    .notes
                    .push(format!("{}: couldn't add to {}", site.user, sysusers::USERS_GROUP));
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As CE generated it, from a real install.
    const PHP_VHOST: &str = r#"server {
  listen 80;
  listen 443 ssl;
  ssl_certificate_key /etc/nginx/ssl-certificates/php.test.local.key;
  ssl_certificate /etc/nginx/ssl-certificates/php.test.local.crt;
  server_name php.test.local;
  root /home/phpsite/htdocs/php.test.local/public;
  access_log /home/phpsite/logs/nginx/access.log main;
  location / {
    proxy_pass http://127.0.0.1:8080;
  }
}

server {
  listen 8080;
  server_name php.test.local;
  root /home/other/not-this-one;
  location ~ \.php$ {
    fastcgi_pass 127.0.0.1:19001;
  }
}
"#;

    #[test]
    fn reads_the_public_server_from_a_ce_vhost() {
        let f = parse_vhost(PHP_VHOST, "php.test.local");
        assert_eq!(f.root.as_deref(), Some("/home/phpsite/htdocs/php.test.local/public"));
        assert_eq!(
            f.cert.as_deref(),
            Some("/etc/nginx/ssl-certificates/php.test.local.crt")
        );
        assert_eq!(f.key.as_deref(), Some("/etc/nginx/ssl-certificates/php.test.local.key"));
        assert!(!f.serves_www);
    }

    #[test]
    fn directive_names_must_match_whole() {
        let f = parse_vhost("  ssl_certificate_key /k;\n  rootfoo /no;\n", "x.com");
        assert_eq!(f.cert, None, "ssl_certificate_key isn't ssl_certificate");
        assert_eq!(f.key.as_deref(), Some("/k"));
        assert_eq!(f.root, None);
    }

    #[test]
    fn ignores_comments_and_finds_www() {
        let f = parse_vhost(
            "  # root /old;\n  server_name x.com www.x.com;\n  root /new;\n",
            "x.com",
        );
        assert_eq!(f.root.as_deref(), Some("/new"));
        assert!(f.serves_www);
    }

    #[test]
    fn www_must_be_this_sites_www() {
        assert!(!parse_vhost("  server_name x.com www.other.com;\n", "x.com").serves_www);
    }

    #[test]
    fn site_types_map_and_unknown_ones_are_refused() {
        assert_eq!(map_site_type("reverse-proxy"), Some("reverse_proxy"));
        assert_eq!(map_site_type("php"), Some("php"));
        assert_eq!(map_site_type("wordpress"), None);
    }

    #[test]
    fn only_local_proxies_have_a_port() {
        assert_eq!(local_proxy_port("http://127.0.0.1:3300"), Some(3300));
        assert_eq!(local_proxy_port("https://localhost:8080/app"), Some(8080));
        assert_eq!(local_proxy_port("https://backend.example.com:8080"), None);
        assert_eq!(local_proxy_port("http://127.0.0.1"), None);
        assert_eq!(local_proxy_port("not a url"), None);
    }

    #[test]
    fn roles_never_grant_more_than_ce_did() {
        assert_eq!(map_role("ROLE_ADMIN"), "admin");
        assert_eq!(map_role("ROLE_SITE_MANAGER"), "site_manager");
        assert_eq!(map_role("ROLE_USER"), "site_manager");
        assert_eq!(map_role(""), "site_manager");
    }
}
