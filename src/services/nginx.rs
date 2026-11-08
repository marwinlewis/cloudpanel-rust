use super::cmd::{run, run_host_simple, CmdOutcome};
use super::ssl::SslService;
use crate::config::Config;
use crate::db::models::{BasicAuthUser, Site};
use crate::fsutil::write_atomic;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct NginxService;

/// File name of the panel's own nginx site. It can't collide with a site: domains have a dot.
const PANEL_VHOST: &str = "cloudpanel-panel";

/// What the panel's own nginx site needs. All values come from the panel itself.
pub struct PanelVhost {
    pub hostname: String,
    pub cert: String,
    pub key: String,
    pub upstream: String,
    pub secret: String,
    /// Cloudflare's address ranges, whose connections may name the client.
    pub real_ip_from: Vec<String>,
}

const SECURITY_HEADERS: &str = r#"    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;"#;

/// Shared `map` so `Connection: upgrade` is only sent for websocket requests.
const UPGRADE_MAP_FILE: &str = "cloudpanel-upgrade-map.conf";
const UPGRADE_MAP: &str =
    "# Managed by CloudPanel\nmap $http_upgrade $connection_upgrade {\n    default upgrade;\n    ''      close;\n}\n";

const MAINTENANCE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Maintenance</title>\
<body style=\"font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0\">\
<p>This site is temporarily unavailable.</p>";

/// nginx runs as a user that's in every site's group, so it can read what those users can't. A link
/// in one site pointing at another's file would be served unless it has to be the same owner's.
const SYMLINK_RULE: &str = "disable_symlinks if_not_owner;";

const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

impl NginxService {
    pub fn htpasswd_path(config: &Config, domain: &str) -> PathBuf {
        config.etc_dir.join("htpasswd").join(domain)
    }

    fn location_body(site: &Site) -> String {
        if site.site_type == "static" {
            return "        try_files $uri $uri/ /index.html;".to_string();
        }
        if site.site_type == "php" {
            return "        try_files $uri $uri/ /index.php?$args;".to_string();
        }
        let port = site.target_port.unwrap_or(3000);
        let ws = if site.websocket {
            "        proxy_set_header Upgrade $http_upgrade;\n        \
             proxy_set_header Connection $connection_upgrade;\n        \
             proxy_cache_bypass $http_upgrade;\n"
        } else {
            "        proxy_set_header Connection \"\";\n"
        };
        format!(
            "        proxy_pass http://127.0.0.1:{port};\n        \
             proxy_http_version 1.1;\n\
             {ws}        \
             proxy_set_header Host $host;\n        \
             proxy_set_header X-Real-IP $remote_addr;\n        \
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        \
             proxy_set_header X-Forwarded-Proto $scheme;\n        \
             proxy_read_timeout 300s;"
        )
    }

    /// Basic-auth directives for the `location /` block (empty when disabled).
    fn auth_block(config: &Config, site: &Site) -> String {
        if !site.basic_auth_enabled {
            return String::new();
        }
        let file = Self::htpasswd_path(config, &site.domain);
        let allows: Vec<&str> = site
            .basic_auth_allow
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let mut out = String::new();
        if !allows.is_empty() {
            out.push_str("        satisfy any;\n");
            for a in &allows {
                out.push_str(&format!("        allow {a};\n"));
            }
            out.push_str("        deny all;\n");
        }
        out.push_str(&format!(
            "        auth_basic \"Restricted\";\n        auth_basic_user_file {};\n",
            file.display()
        ));
        out
    }

    /// Everything inside the `server {}` block after listen/server_name/TLS.
    fn server_body(config: &Config, site: &Site) -> String {
        let domain = &site.domain;
        let mut out = String::new();
        out.push_str(SECURITY_HEADERS);
        out.push('\n');
        if site.ssl_enabled {
            out.push_str("    add_header Strict-Transport-Security \"max-age=31536000\" always;\n");
        }
        out.push_str(&format!(
            "\n    client_max_body_size {}M;\n    access_log {log}/{domain}.access.log;\n    \
             error_log {log}/{domain}.error.log;\n\n",
            site.max_body_mb.clamp(1, 10240),
            log = config.nginx_log_dir.display(),
        ));

        if !site.is_active {
            out.push_str("    location /.well-known/acme-challenge/ {\n        root /var/www/html;\n    }\n\n");
            out.push_str(&format!(
                "    location / {{\n        default_type text/html;\n        \
                 add_header Retry-After 3600 always;\n        return 503 '{MAINTENANCE_PAGE}';\n    }}\n"
            ));
            return out;
        }

        if site.site_type == "static" {
            let root = site.document_root.as_deref().unwrap_or("/var/www/html");
            out.push_str(&format!(
                "    root {root};\n    index index.html index.htm;\n    {SYMLINK_RULE}\n\n"
            ));
        }
        if site.site_type == "php" {
            let root = site.document_root.as_deref().unwrap_or("/var/www/html");
            out.push_str(&format!(
                "    root {root};\n    index index.php index.html index.htm;\n    {SYMLINK_RULE}\n\n"
            ));
        }
        out.push_str("    location / {\n");
        out.push_str(&Self::auth_block(config, site));
        out.push_str(&Self::location_body(site));
        out.push_str("\n    }\n\n    location ~ /\\.(?!well-known) {\n        deny all;\n    }\n");
        if site.site_type == "php" {
            // `try_files $uri =404` stops nginx handing a non-PHP upload to PHP as a script.
            out.push_str(&format!(
                "\n    location ~ \\.php$ {{\n{auth}        try_files $uri =404;\n        \
                 include fastcgi_params;\n        \
                 fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n        \
                 fastcgi_index index.php;\n        fastcgi_read_timeout 300s;\n        \
                 fastcgi_pass unix:{socket};\n    }}\n",
                auth = Self::auth_block(config, site),
                socket = super::php::socket_path(domain),
            ));
        }

        let custom = site.custom_directives.trim();
        if !custom.is_empty() {
            out.push_str("\n    # Custom directives\n");
            for line in custom.lines() {
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// Render the vhost. All interpolated values are validated before reaching here
    /// (domain via `validate::domain`, paths via `validate::path_within` or derived from config,
    /// allow-list entries via `validate::cidr`, directives via `validate::nginx_directives`).
    pub fn generate_config(config: &Config, site: &Site) -> String {
        Self::render_config(config, site, Self::cert_covers_www(site))
    }

    /// Whether the site's certificate is valid for its www name.
    pub fn cert_covers_www(site: &Site) -> bool {
        site.ssl_cert_path
            .as_deref()
            .and_then(SslService::cert_info)
            .is_some_and(|c| c.covers(&format!("www.{}", site.domain)))
    }

    /// Render the vhost. `www_tls` says whether the certificate covers www, without which
    /// nginx could only answer `https://www` with a certificate error.
    fn render_config(config: &Config, site: &Site, www_tls: bool) -> String {
        if site.redirects_www() {
            return Self::render_with_www_redirect(config, site, www_tls);
        }
        let names = site.server_names().join(" ");
        let body = Self::server_body(config, site);

        match (&site.ssl_enabled, &site.ssl_cert_path, &site.ssl_key_path) {
            (true, Some(cert), Some(key)) => format!(
                r#"# Managed by CloudPanel - changes will be overwritten
server {{
    listen 80;
    listen [::]:80;
    server_name {names};

    location /.well-known/acme-challenge/ {{
        root /var/www/html;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {names};

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:cloudpanel_ssl:10m;
    ssl_session_timeout 1d;

{body}}}
"#
            ),
            _ => format!(
                r#"# Managed by CloudPanel - changes will be overwritten
server {{
    listen 80;
    listen [::]:80;
    server_name {names};

{body}}}
"#
            ),
        }
    }

    /// The vhost when www redirects to the naked domain. Every www block keeps its port 80
    /// ACME location, or the www name on the certificate could no longer renew.
    fn render_with_www_redirect(config: &Config, site: &Site, www_tls: bool) -> String {
        let domain = &site.domain;
        let www = format!("www.{domain}");
        let body = Self::server_body(config, site);
        const ACME: &str = "    location /.well-known/acme-challenge/ {\n        root /var/www/html;\n    }\n";

        match (&site.ssl_enabled, &site.ssl_cert_path, &site.ssl_key_path) {
            (true, Some(cert), Some(key)) => {
                let tls = format!(
                    "    ssl_certificate {cert};\n    ssl_certificate_key {key};\n    \
                     ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_prefer_server_ciphers off;\n    \
                     ssl_session_cache shared:cloudpanel_ssl:10m;\n    ssl_session_timeout 1d;\n"
                );
                let www_block = if www_tls {
                    format!(
                        "\nserver {{\n    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    \
                         server_name {www};\n\n{tls}\n    \
                         add_header Strict-Transport-Security \"max-age=31536000\" always;\n    \
                         return 301 https://{domain}$request_uri;\n}}\n"
                    )
                } else {
                    String::new()
                };
                format!(
                    "# Managed by CloudPanel - changes will be overwritten\n\
                     server {{\n    listen 80;\n    listen [::]:80;\n    server_name {domain} {www};\n\n{ACME}\n    \
                     location / {{\n        return 301 https://{domain}$request_uri;\n    }}\n}}\n{www_block}\n\
                     server {{\n    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    \
                     server_name {domain};\n\n{tls}\n{body}}}\n"
                )
            }
            _ => format!(
                "# Managed by CloudPanel - changes will be overwritten\n\
                 server {{\n    listen 80;\n    listen [::]:80;\n    server_name {www};\n\n{ACME}\n    \
                 location / {{\n        return 301 http://{domain}$request_uri;\n    }}\n}}\n\n\
                 server {{\n    listen 80;\n    listen [::]:80;\n    server_name {domain};\n\n{body}}}\n"
            ),
        }
    }

    /// Write the htpasswd file for a site (hashes produced by `hash_htpasswd`).
    pub fn write_htpasswd(config: &Config, domain: &str, users: &[BasicAuthUser]) -> Result<(), String> {
        let path = Self::htpasswd_path(config, domain);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let mut body = String::new();
        for u in users {
            body.push_str(&format!("{}:{}\n", u.username, u.password_hash));
        }
        // nginx workers (www-data) must be able to read it; hashes are salted SHA-512 crypt.
        write_atomic(&path, body.as_bytes(), 0o644).map_err(|e| format!("write htpasswd: {e}"))
    }

    /// Hash a password for nginx basic auth with `openssl passwd -6` (password on stdin).
    pub fn hash_htpasswd(password: &str) -> Result<String, String> {
        use super::cmd::{run_with, CmdOpts};
        let r = run_with(
            "openssl",
            &["passwd", "-6", "-stdin"],
            &CmdOpts::default().stdin(format!("{password}\n")).timeout(10),
        );
        if r.missing {
            // Development fallback: nginx also accepts {PLAIN}, never used on a real server.
            if cfg!(windows) {
                return Ok(format!("{{PLAIN}}{password}"));
            }
            return Err("openssl is not installed".into());
        }
        let out = r.into_result("openssl", "")?;
        let hash = out.trim().to_string();
        if !hash.starts_with("$6$") {
            return Err("openssl returned an unexpected hash".into());
        }
        Ok(hash)
    }

    fn paths(config: &Config, domain: &str) -> (PathBuf, PathBuf) {
        let file_name = format!("{domain}.conf");
        (
            config.nginx_sites_available.join(&file_name),
            config.nginx_sites_enabled.join(&file_name),
        )
    }

    /// Where the shared map has to live for nginx to load it. Debian's `nginx.conf` includes
    /// `conf.d`, but CloudPanel CE's only includes `sites-enabled/*.conf`, so on a server migrated
    /// from CE a map in `conf.d` would never load and every vhost using it would fail `nginx -t`.
    fn upgrade_map_path(config: &Config, nginx_conf: Option<&str>) -> Option<PathBuf> {
        let root = config.nginx_sites_available.parent()?;
        let includes_conf_d = nginx_conf.map_or(true, |text| {
            text.lines()
                .map(str::trim_start)
                .any(|l| l.starts_with("include") && l.contains("conf.d/"))
        });
        Some(if includes_conf_d {
            root.join("conf.d").join(UPGRADE_MAP_FILE)
        } else {
            config.nginx_sites_enabled.join(UPGRADE_MAP_FILE)
        })
    }

    fn ensure_upgrade_map(config: &Config) -> Result<(), String> {
        let nginx_conf = config
            .nginx_sites_available
            .parent()
            .and_then(|root| fs::read_to_string(root.join("nginx.conf")).ok());
        let Some(path) = Self::upgrade_map_path(config, nginx_conf.as_deref()) else {
            return Ok(());
        };
        if path.exists() {
            return Ok(());
        }
        write_atomic(&path, UPGRADE_MAP.as_bytes(), 0o644)
            .map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }

    fn link(available: &Path, enabled: &Path) -> Result<(), String> {
        if enabled.exists() || enabled.symlink_metadata().is_ok() {
            fs::remove_file(enabled).map_err(|e| format!("Failed to replace {}: {e}", enabled.display()))?;
        }
        #[cfg(unix)]
        let res = std::os::unix::fs::symlink(available, enabled);
        #[cfg(not(unix))]
        let res = fs::copy(available, enabled).map(|_| ());
        res.map_err(|e| format!("Failed to enable site: {e}"))
    }

    /// Write the vhost, validate it with `nginx -t` and reload. On a failed test the
    /// previous config is restored so a bad change can never take nginx down.
    pub fn write_and_apply(config: &Config, site: &Site) -> Result<(), String> {
        Self::check_vhost_managed(site)?;
        Self::install_vhost(config, &site.domain, &Self::generate_config(config, site), 0o644)
    }

    /// An imported site's vhost is kept exactly as it is. [`Self::write_and_apply`] enforces this,
    /// and whatever has side effects on the way there (certbot reloads nginx, for one) should call
    /// this first, so that nothing has happened by the time the change is refused.
    pub fn check_vhost_managed(site: &Site) -> Result<(), String> {
        if site.vhost_managed {
            return Ok(());
        }
        Err(format!(
            "The nginx config of {domain} was imported from CloudPanel CE and is kept exactly as it is, so this \
             change can't be applied from the panel. Edit /etc/nginx/sites-enabled/{domain}.conf on the server.",
            domain = site.domain
        ))
    }

    fn install_vhost(config: &Config, name: &str, content: &str, mode: u32) -> Result<(), String> {
        fs::create_dir_all(&config.nginx_sites_available)
            .map_err(|e| format!("Failed to create sites-available: {e}"))?;
        fs::create_dir_all(&config.nginx_sites_enabled).map_err(|e| format!("Failed to create sites-enabled: {e}"))?;
        let _ = fs::create_dir_all(&config.nginx_log_dir);
        Self::ensure_upgrade_map(config)?;

        let (available, enabled) = Self::paths(config, name);
        // CE keeps vhosts as plain files in sites-enabled, with nothing in sites-available. Without
        // reading that copy too, a rejected config would delete the site's only vhost below.
        let previous = fs::read(&available).or_else(|_| fs::read(&enabled)).ok();
        let was_enabled = enabled.symlink_metadata().is_ok();

        write_atomic(&available, content.as_bytes(), mode).map_err(|e| format!("Failed to write nginx config: {e}"))?;
        Self::link(&available, &enabled)?;

        if let Err(e) = Self::test() {
            match previous {
                Some(prev) => {
                    let _ = write_atomic(&available, &prev, mode);
                    if was_enabled {
                        let _ = Self::link(&available, &enabled);
                    } else {
                        let _ = fs::remove_file(&enabled);
                    }
                }
                None => {
                    let _ = fs::remove_file(&enabled);
                    let _ = fs::remove_file(&available);
                }
            }
            warn!("nginx rejected config for {name}: {e}");
            return Err(e);
        }

        Self::reload()?;
        info!("Applied nginx configuration for {name}");
        Ok(())
    }

    /// The nginx site that serves the panel's own hostname on port 443, so it doesn't need
    /// `:8443` in the URL. `secret` proves to the panel that a request came through here (see
    /// `api::forwarded_client`), so the file must stay unreadable to site users.
    pub fn render_panel_vhost(config: &Config, tls: &PanelVhost) -> String {
        let PanelVhost {
            hostname,
            cert,
            key,
            upstream,
            secret,
            real_ip_from,
        } = tls;
        let real_ip_from: String = real_ip_from
            .iter()
            .map(|cidr| format!("    set_real_ip_from {cidr};\n"))
            .collect();
        format!(
            r#"# Managed by CloudPanel - changes will be overwritten
server {{
    listen 80;
    listen [::]:80;
    server_name {hostname};

    location /.well-known/acme-challenge/ {{
        root /var/www/html;
    }}

    location / {{
        return 301 https://{hostname}$request_uri;
    }}
}}

server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {hostname};

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:cloudpanel_ssl:10m;
    ssl_session_timeout 1d;

    access_log {log}/{hostname}.access.log;
    error_log {log}/{hostname}.error.log;

    # The panel enforces its own limits, and backups and uploads can be large.
    client_max_body_size 0;

    # Cloudflare's addresses, kept current by the panel. Only a connection from one of these can
    # name the client. Anyone else's CF-Connecting-IP is ignored and $remote_addr stays theirs.
{real_ip_from}    real_ip_header CF-Connecting-IP;

    location / {{
        proxy_pass {upstream};
        proxy_http_version 1.1;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 4;
        proxy_ssl_trusted_certificate {trust};
        proxy_ssl_name {hostname};
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-CloudPanel-Proxy "{secret}";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
}}
"#,
            log = config.nginx_log_dir.display(),
            trust = Self::panel_trust_path(config).display(),
        )
    }

    /// What nginx will accept as the panel, on the way to it from the panel's nginx site. Its port
    /// is one anyone on this machine can listen on while the panel is restarting, and nginx would
    /// send them every session cookie and the secret that vouches for the client's address. They
    /// don't have a certificate for this name, which the panel's real one is.
    fn panel_trust_path(config: &Config) -> PathBuf {
        config.etc_dir.join("panel-upstream-trust.pem")
    }

    /// The public CAs, for a certificate from Let's Encrypt, which then renews without this
    /// changing, plus the panel's own, for one that is self-signed.
    fn write_panel_trust(config: &Config, cert: &str) -> Result<(), String> {
        let mut trust = fs::read(cert).map_err(|e| format!("Failed to read {cert}: {e}"))?;
        trust.push(b'\n');
        if let Ok(public) = fs::read(SYSTEM_CA_BUNDLE) {
            trust.extend_from_slice(&public);
        }
        let path = Self::panel_trust_path(config);
        if fs::read(&path).is_ok_and(|current| current == trust) {
            return Ok(());
        }
        write_atomic(&path, &trust, 0o644).map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }

    /// Bring the panel's nginx site in line. It stays untouched when nothing changed, so a
    /// panel restart doesn't reload nginx for no reason.
    pub fn apply_panel_vhost(config: &Config, tls: &PanelVhost) -> Result<(), String> {
        Self::write_panel_trust(config, &tls.cert)?;
        let content = Self::render_panel_vhost(config, tls);
        let (available, enabled) = Self::paths(config, PANEL_VHOST);
        let current = fs::read_to_string(&available).ok();
        if current.as_deref() == Some(content.as_str()) && enabled.symlink_metadata().is_ok() {
            return Ok(());
        }
        Self::install_vhost(config, PANEL_VHOST, &content, 0o600)
    }

    pub fn remove_panel_vhost(config: &Config) -> Result<(), String> {
        if Self::paths(config, PANEL_VHOST).0.symlink_metadata().is_err() {
            return Ok(());
        }
        Self::remove_site(config, PANEL_VHOST)
    }

    pub fn remove_site(config: &Config, domain: &str) -> Result<(), String> {
        let (available, enabled) = Self::paths(config, domain);
        for p in [&enabled, &available] {
            if p.symlink_metadata().is_ok() {
                fs::remove_file(p).map_err(|e| format!("Failed to remove {}: {e}", p.display()))?;
            }
        }
        let _ = fs::remove_file(Self::htpasswd_path(config, domain));
        Self::test()?;
        Self::reload()?;
        info!("Removed nginx configuration for {domain}");
        Ok(())
    }

    /// Current vhost file content (for the read-only vhost viewer).
    pub fn read_vhost(config: &Config, domain: &str) -> Option<String> {
        let (available, enabled) = Self::paths(config, domain);
        fs::read_to_string(available)
            .or_else(|_| fs::read_to_string(enabled))
            .ok()
    }

    pub fn test() -> Result<(), String> {
        // Tests write vhosts to a temp dir the host's nginx never reads, so its verdict says nothing
        // about them. It also can't be asked without root where nginx and systemd are installed.
        if cfg!(test) {
            return Ok(());
        }
        // Outside the sandbox: CE's nginx build writes under /usr/share/nginx while it tests its
        // config, which is read-only in here, so the test would fail on a server migrated from CE.
        match run_host_simple("nginx", &["-t", "-q"]) {
            CmdOutcome::Ok(_) => Ok(()),
            CmdOutcome::Failed(e) => Err(format!("nginx configuration test failed: {e}")),
            CmdOutcome::Missing => {
                warn!("nginx not installed; skipping config test");
                Ok(())
            }
        }
    }

    pub fn reload() -> Result<(), String> {
        // A test must never reload the nginx of the machine it runs on. See `test`.
        if cfg!(test) {
            return Ok(());
        }
        match run("systemctl", &["reload", "nginx"]) {
            CmdOutcome::Ok(_) => return Ok(()),
            CmdOutcome::Failed(e) => warn!("systemctl reload nginx failed: {e}"),
            CmdOutcome::Missing => {}
        }
        match run_host_simple("nginx", &["-s", "reload"]) {
            CmdOutcome::Ok(_) => Ok(()),
            CmdOutcome::Failed(e) => Err(format!("nginx reload failed: {e}")),
            CmdOutcome::Missing => Ok(()),
        }
    }
}

#[cfg(test)]
pub(crate) fn test_site(site_type: &str) -> Site {
    use chrono::Utc;
    Site {
        id: 1,
        domain: "app.example.com".into(),
        site_type: site_type.into(),
        target_port: Some(3000),
        document_root: Some("/var/www/app.example.com/public".into()),
        system_user: "cloudpanel".into(),
        include_www: false,
        ssl_enabled: false,
        ssl_auto_renew: true,
        ssl_cert_path: None,
        ssl_key_path: None,
        is_active: true,
        app_command: None,
        app_workdir: None,
        app_env: "{}".into(),
        app_enabled: false,
        home_dir: None,
        websocket: true,
        max_body_mb: 128,
        custom_directives: String::new(),
        basic_auth_enabled: false,
        basic_auth_allow: String::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        app_manager: "systemd".into(),
        app_pm2: "{}".into(),
        www_redirect: false,
        php_version: None,
        vhost_managed: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::from_env();
        c.etc_dir = PathBuf::from("/etc/cloudpanel");
        c.nginx_log_dir = PathBuf::from("/var/log/nginx");
        c
    }

    #[test]
    fn proxy_config() {
        let c = NginxService::generate_config(&cfg(), &test_site("nodejs"));
        assert!(c.contains("server_name app.example.com;"));
        assert!(c.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(c.contains("proxy_set_header Upgrade $http_upgrade;"));
        assert!(c.contains("client_max_body_size 128M;"));
        assert!(c.contains("access_log /var/log/nginx/app.example.com.access.log;"));
        assert!(!c.contains("listen 443"));
    }

    #[test]
    fn static_ssl_config_with_www() {
        let mut s = test_site("static");
        s.include_www = true;
        s.ssl_enabled = true;
        s.ssl_cert_path = Some("/etc/letsencrypt/live/app.example.com/fullchain.pem".into());
        s.ssl_key_path = Some("/etc/letsencrypt/live/app.example.com/privkey.pem".into());
        let c = NginxService::generate_config(&cfg(), &s);
        assert!(c.contains("server_name app.example.com www.app.example.com;"));
        assert!(c.contains("root /var/www/app.example.com/public;"));
        assert!(c.contains("listen 443 ssl http2;"));
        assert!(c.contains("return 301 https://$host$request_uri;"));
        assert!(c.contains("Strict-Transport-Security"));
    }

    fn redirecting(ssl: bool) -> Site {
        let mut s = test_site("nodejs");
        s.domain = "example.com".into();
        s.include_www = true;
        s.www_redirect = true;
        if ssl {
            s.ssl_enabled = true;
            s.ssl_cert_path = Some("/etc/letsencrypt/live/example.com/fullchain.pem".into());
            s.ssl_key_path = Some("/etc/letsencrypt/live/example.com/privkey.pem".into());
        }
        s
    }

    #[test]
    fn www_redirect_over_https_when_certificate_covers_it() {
        let c = NginxService::render_config(&cfg(), &redirecting(true), true);
        // Port 80 goes straight to the naked domain, in one hop, and can still renew www.
        assert!(c.contains("server_name example.com www.example.com;"));
        assert!(c.contains("acme-challenge"));
        assert!(!c.contains("return 301 https://$host"));
        // The www block answers on 443 and only redirects.
        let www = c.split("server_name www.example.com;").nth(1).unwrap();
        let www = &www[..www.find("\n}").unwrap()];
        assert!(www.contains("ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;"));
        assert!(www.contains("return 301 https://example.com$request_uri;"));
        assert!(!www.contains("proxy_pass"));
        // The site itself is only on the naked domain.
        assert!(c.contains("server_name example.com;"));
        assert_eq!(c.matches("proxy_pass").count(), 1);
        assert_eq!(c.matches("listen 443 ssl http2;").count(), 2);
    }

    #[test]
    fn no_https_www_block_without_a_covering_certificate() {
        let c = NginxService::render_config(&cfg(), &redirecting(true), false);
        assert!(!c.contains("server_name www.example.com;"));
        assert_eq!(c.matches("listen 443 ssl http2;").count(), 1);
        assert!(c.contains("server_name example.com www.example.com;"));
        assert!(c.contains("return 301 https://example.com$request_uri;"));
    }

    #[test]
    fn www_redirect_without_https() {
        let c = NginxService::render_config(&cfg(), &redirecting(false), false);
        assert!(c.contains("server_name www.example.com;"));
        assert!(c.contains("return 301 http://example.com$request_uri;"));
        assert!(c.contains("server_name example.com;"));
        assert!(c.contains("acme-challenge"));
        assert!(!c.contains("listen 443"));
        assert_eq!(c.matches("proxy_pass").count(), 1);
    }

    #[test]
    fn panel_vhost_forwards_to_the_panel_and_vouches_for_the_client() {
        let c = NginxService::render_panel_vhost(
            &cfg(),
            &PanelVhost {
                hostname: "cpanel.example.com".into(),
                cert: "/etc/letsencrypt/live/cpanel.example.com/fullchain.pem".into(),
                key: "/etc/letsencrypt/live/cpanel.example.com/privkey.pem".into(),
                upstream: "https://127.0.0.1:8443".into(),
                secret: "s3cret".into(),
                real_ip_from: vec!["173.245.48.0/20".into(), "2606:4700::/32".into()],
            },
        );
        assert!(c.contains("listen 443 ssl http2;"));
        assert!(c.contains("server_name cpanel.example.com;"));
        assert!(c.contains("ssl_certificate /etc/letsencrypt/live/cpanel.example.com/fullchain.pem;"));
        assert!(c.contains("proxy_pass https://127.0.0.1:8443;"));
        assert!(c.contains("proxy_set_header Host $host;"));
        assert!(c.contains("proxy_set_header X-Real-IP $remote_addr;"));
        assert!(c.contains("proxy_set_header X-CloudPanel-Proxy \"s3cret\";"));
        // Cloudflare's connections can name the client, which reaches the panel through
        // $remote_addr. The header itself must never be copied across, or anyone could set it.
        let https = &c[c.find("listen 443").unwrap()..];
        assert!(https.contains("    set_real_ip_from 173.245.48.0/20;\n    set_real_ip_from 2606:4700::/32;\n"));
        assert!(https.contains("    real_ip_header CF-Connecting-IP;\n"));
        assert_eq!(c.matches("set_real_ip_from").count(), 2);
        assert!(!c.contains("$http_cf_connecting_ip"));
        // Port 80 can still validate certificate renewals.
        assert!(c.contains("acme-challenge"));
        assert!(c.contains("return 301 https://cpanel.example.com$request_uri;"));
    }

    #[test]
    fn php_config_passes_scripts_to_the_sites_own_pool() {
        let mut s = test_site("php");
        s.document_root = Some("/home/shop/htdocs/app.example.com".into());
        s.php_version = Some("8.4".into());
        let c = NginxService::generate_config(&cfg(), &s);
        assert!(c.contains("root /home/shop/htdocs/app.example.com;"));
        assert!(c.contains("index index.php"));
        assert!(c.contains("try_files $uri $uri/ /index.php?$args;"));
        assert!(c.contains("fastcgi_pass unix:/run/php/cloudpanel-app.example.com.sock;"));
        assert!(c.contains("try_files $uri =404;"));
        assert!(!c.contains("proxy_pass"));
    }

    #[test]
    fn php_scripts_stay_behind_basic_auth() {
        let mut s = test_site("php");
        s.basic_auth_enabled = true;
        let c = NginxService::generate_config(&cfg(), &s);
        let php = &c[c.find("location ~ \\.php$").unwrap()..];
        assert!(php.contains("auth_basic \"Restricted\";"));
    }

    #[test]
    fn imported_vhost_is_never_regenerated() {
        let mut s = test_site("nodejs");
        s.vhost_managed = false;
        let e = NginxService::write_and_apply(&cfg(), &s).unwrap_err();
        assert!(e.contains("imported from CloudPanel CE"));
    }

    #[test]
    fn upgrade_map_goes_where_nginx_will_load_it() {
        let c = cfg();
        let debian = "http {\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}\n";
        let ce = "http {\n    include /etc/nginx/mime.types;\n    include /etc/nginx/sites-enabled/*.conf;\n}\n";
        let commented =
            "http {\n    # include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*.conf;\n}\n";
        let in_conf_d = |text| {
            NginxService::upgrade_map_path(&c, text)
                .unwrap()
                .parent()
                .unwrap()
                .ends_with("conf.d")
        };
        assert!(in_conf_d(Some(debian)));
        assert!(!in_conf_d(Some(ce)));
        assert!(!in_conf_d(Some(commented)));
        // Can't read nginx.conf: keep the long-standing location.
        assert!(in_conf_d(None));
        let path = NginxService::upgrade_map_path(&c, Some(ce)).unwrap();
        assert!(path.to_string_lossy().ends_with(".conf"), "CE only includes *.conf");
    }

    #[test]
    fn disabled_site_still_redirects_www() {
        let mut s = redirecting(false);
        s.is_active = false;
        let c = NginxService::render_config(&cfg(), &s, false);
        assert!(c.contains("return 301 http://example.com$request_uri;"));
        assert!(c.contains("return 503 '"));
    }

    #[test]
    fn disabled_site_serves_maintenance() {
        let mut s = test_site("nodejs");
        s.is_active = false;
        let c = NginxService::generate_config(&cfg(), &s);
        assert!(c.contains("return 503 '"));
        assert!(!c.contains("proxy_pass"));
    }

    #[test]
    fn basic_auth_custom_and_no_websocket() {
        let mut s = test_site("reverse_proxy");
        s.basic_auth_enabled = true;
        s.basic_auth_allow = "10.0.0.0/8\n".into();
        s.websocket = false;
        s.custom_directives = "location /health {\n    return 200;\n}".into();
        let c = NginxService::generate_config(&cfg(), &s);
        assert!(c.contains("auth_basic \"Restricted\";"));
        #[cfg(unix)]
        assert!(c.contains("auth_basic_user_file /etc/cloudpanel/htpasswd/app.example.com;"));
        assert!(c.contains("satisfy any;\n        allow 10.0.0.0/8;\n        deny all;"));
        assert!(!c.contains("$connection_upgrade"));
        assert!(c.contains("    location /health {\n        return 200;\n    }\n"));
    }
}
