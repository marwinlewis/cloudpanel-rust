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
const S3_VHOST: &str = "cloudpanel-s3";

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

/// File name of the catch-all server for names no site claims. Like the panel's, it can't
/// collide with a site.
const DEFAULT_VHOST: &str = "cloudpanel-default";

/// What a site in maintenance mode says when the admin hasn't written anything.
pub const DEFAULT_MAINTENANCE_MESSAGE: &str =
    "We're making some improvements and will be back shortly. Thank you for your patience.";

/// Marks the maintenance block the panel adds to a vhost imported from CE, so it can be taken
/// out again without touching anything else in the file.
const MAINTENANCE_BEGIN: &str = "# BEGIN CloudPanel maintenance mode (removed when maintenance ends)";
const MAINTENANCE_END: &str = "# END CloudPanel maintenance mode";

/// The longest maintenance message the panel accepts.
pub const MAINTENANCE_MESSAGE_MAX: usize = 2000;

/// The answer for a name that no site on this server claims.
const UNKNOWN_HOST_PAGE: &str = "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
<title>Site not found</title><body style=\"font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0;\
color:#334155;background:#f8fafc\"><div style=\"text-align:center;padding:24px\"><h1 style=\"font-size:22px;margin:0 0 8px\">\
No site is configured at this address</h1><p style=\"margin:0;color:#64748b\">If you own this domain, add it as a site in \
the control panel.</p></div>";

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

    /// Text for the maintenance page. nginx serves the page from a single-quoted string, in which
    /// a quote or backslash would end or escape it and `$` would name a variable, so none of them
    /// survive: they become HTML entities like everything else markup could misread.
    fn page_text(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                '$' => out.push_str("&#36;"),
                '\\' => out.push_str("&#92;"),
                '{' => out.push_str("&#123;"),
                '}' => out.push_str("&#125;"),
                '\n' => out.push_str("<br>"),
                c if c.is_control() => {}
                c => out.push(c),
            }
        }
        out
    }

    /// The page visitors see while a site is in maintenance mode.
    pub fn maintenance_page(site: &Site) -> String {
        let message = site.maintenance_message.trim();
        let message = if message.is_empty() {
            DEFAULT_MAINTENANCE_MESSAGE
        } else {
            message
        };
        format!(
            "<!doctype html><html lang=en><meta charset=utf-8>\
             <meta name=viewport content=\"width=device-width,initial-scale=1\"><meta name=robots content=noindex>\
             <title>Under maintenance</title><style>\
             body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#f8fafc;color:#0f172a;\
             font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif}}\
             main{{max-width:560px;padding:40px 24px;text-align:center}}\
             .tag{{display:inline-block;padding:4px 12px;border-radius:999px;background:#fef3c7;color:#92400e;\
             font-size:13px;font-weight:600;letter-spacing:.02em}}\
             h1{{font-size:30px;margin:20px 0 12px}}p{{font-size:17px;line-height:1.6;color:#475569;margin:0}}\
             .domain{{margin-top:32px;font-size:13px;color:#94a3b8}}\
             @media (prefers-color-scheme:dark){{body{{background:#0f172a;color:#f1f5f9}}p{{color:#cbd5e1}}\
             .tag{{background:#422006;color:#fcd34d}}}}</style>\
             <main><span class=tag>Maintenance</span><h1>We&#39;ll be back soon</h1><p>{message}</p>\
             <p class=domain>{domain}</p></main>",
            message = Self::page_text(message),
            domain = Self::page_text(&site.domain),
        )
    }

    /// Addresses that see the site through maintenance mode, as one regex for `$remote_addr`.
    /// nginx's `if` can't match a CIDR range, so only whole addresses are accepted.
    fn maintenance_bypass(site: &Site) -> Option<String> {
        let ips: Vec<String> = site
            .maintenance_allow
            .lines()
            .filter_map(|l| l.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| ip.to_string().replace('.', "\\."))
            .collect();
        (!ips.is_empty()).then(|| format!("^({})$", ips.join("|")))
    }

    /// Server-level rules for maintenance mode. They run before nginx picks a location, so no
    /// location (custom directives, basic auth's allow-list) can let a visitor past them. Only
    /// certificate challenges and the listed addresses get through.
    fn maintenance_block(site: &Site) -> String {
        let mut out = String::from(
            "    # Maintenance mode: visitors see the page below; listed addresses see the site.\n    \
             set $cloudpanel_maintenance 1;\n    \
             if ($uri ~ \"^/\\.well-known/acme-challenge/\") {\n        set $cloudpanel_maintenance 0;\n    }\n",
        );
        if let Some(bypass) = Self::maintenance_bypass(site) {
            out.push_str(&format!(
                "    if ($remote_addr ~ \"{bypass}\") {{\n        set $cloudpanel_maintenance 0;\n    }}\n"
            ));
        }
        out.push_str(&format!(
            "    if ($cloudpanel_maintenance) {{\n        return 503;\n    }}\n    \
             error_page 503 @cloudpanel_maintenance;\n\n    \
             location @cloudpanel_maintenance {{\n{headers}\n        \
             add_header Retry-After 3600 always;\n        add_header Cache-Control \"no-store\" always;\n        \
             default_type text/html;\n        return 503 '{page}';\n    }}\n\n",
            headers = SECURITY_HEADERS
                .replace("\n    ", "\n        ")
                .replacen("    ", "        ", 1),
            page = Self::maintenance_page(site),
        ));
        out
    }

    /// Where the self-signed certificate lives that answers HTTPS for names without a certificate
    /// of their own.
    pub fn fallback_cert_paths(config: &Config) -> (PathBuf, PathBuf) {
        let dir = config.etc_dir.join("fallback-tls");
        (dir.join("cert.pem"), dir.join("key.pem"))
    }

    /// TLS listen lines for a server without a certificate of its own. Without them, nginx would
    /// hand an HTTPS request for the name to some other server on port 443. None until the
    /// fallback certificate exists.
    fn fallback_tls(config: &Config) -> Option<String> {
        let (cert, key) = Self::fallback_cert_paths(config);
        if !(cert.exists() && key.exists()) {
            return None;
        }
        Some(format!(
            "    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    \
             ssl_certificate {};\n    ssl_certificate_key {};\n",
            cert.display(),
            key.display()
        ))
    }

    /// Create the self-signed fallback certificate once. Visitors who reach a site by HTTPS before
    /// it has a real certificate see a certificate warning, then the site's own response; behind
    /// Cloudflare's "Full" mode, they see the site.
    pub fn ensure_fallback_cert(config: &Config) -> Result<(), String> {
        use super::cmd::{run_with, CmdOpts};
        let (cert, key) = Self::fallback_cert_paths(config);
        if cert.exists() && key.exists() {
            return Ok(());
        }
        let dir = cert.parent().ok_or("fallback certificate has no directory")?;
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let (cert_s, key_s) = (cert.to_string_lossy().to_string(), key.to_string_lossy().to_string());
        let r = run_with(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/CN=cloudpanel-default",
                "-keyout",
                &key_s,
                "-out",
                &cert_s,
            ],
            &CmdOpts::default().timeout(60),
        );
        if r.missing {
            return Err("openssl is not installed".into());
        }
        r.into_result("openssl", "").map(|_| ())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Whether a config other than the panel's own catch-all already is nginx's default server
    /// on `port`. Two would fail `nginx -t`. Debian's stock `default` site claims port 80.
    fn others_claim_default(config: &Config, port: &str) -> bool {
        let own = format!("{DEFAULT_VHOST}.conf");
        let mut dirs = vec![config.nginx_sites_enabled.clone()];
        if let Some(root) = config.nginx_sites_available.parent() {
            dirs.push(root.join("conf.d"));
        }
        dirs.iter()
            .filter_map(|d| fs::read_dir(d).ok())
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy() != own)
            .filter_map(|e| fs::read_to_string(e.path()).ok())
            .any(|text| {
                text.lines().map(str::trim_start).any(|l| {
                    let mut words = l.trim_end_matches(';').split_whitespace();
                    if words.next() != Some("listen") {
                        return false;
                    }
                    let Some(addr) = words.next() else { return false };
                    let addr_port = addr.rsplit_once(':').map_or(addr, |(_, p)| p);
                    addr_port == port && words.any(|w| w == "default_server" || w == "default")
                })
            })
    }

    /// The catch-all server: an HTTPS request for a name no site claims would otherwise go to the
    /// first server on port 443, the panel's own, and show its sign-in page.
    pub fn render_default_vhost(config: &Config, claim_80: bool, claim_443: bool) -> Option<String> {
        if !(claim_80 || claim_443) {
            return None;
        }
        let mut listen = String::new();
        if claim_80 {
            listen.push_str("    listen 80 default_server;\n    listen [::]:80 default_server;\n");
        }
        if claim_443 {
            let (cert, key) = Self::fallback_cert_paths(config);
            listen.push_str(&format!(
                "    listen 443 ssl http2 default_server;\n    listen [::]:443 ssl http2 default_server;\n    \
                 ssl_certificate {};\n    ssl_certificate_key {};\n",
                cert.display(),
                key.display()
            ));
        }
        Some(format!(
            "# Managed by CloudPanel - changes will be overwritten\n\
             # Answers for every name no site on this server claims.\n\
             server {{\n{listen}    server_name _;\n\n{SECURITY_HEADERS}\n\n    \
             location /.well-known/acme-challenge/ {{\n        root /var/www/html;\n    }}\n\n    \
             location / {{\n        default_type text/html;\n        return 404 '{UNKNOWN_HOST_PAGE}';\n    }}\n}}\n"
        ))
    }

    /// Put the catch-all server in place. Left untouched when nothing changed.
    pub fn apply_default_vhost(config: &Config) -> Result<(), String> {
        Self::ensure_fallback_cert(config)?;
        let claim_80 = !Self::others_claim_default(config, "80");
        let claim_443 = !Self::others_claim_default(config, "443");
        let Some(content) = Self::render_default_vhost(config, claim_80, claim_443) else {
            return Ok(());
        };
        let (available, enabled) = Self::paths(config, DEFAULT_VHOST);
        if fs::read_to_string(&available).ok().as_deref() == Some(content.as_str())
            && enabled.symlink_metadata().is_ok()
        {
            return Ok(());
        }
        Self::install_vhost(config, DEFAULT_VHOST, &content, 0o644)
    }

    /// Take every marked maintenance block out of an imported vhost, leaving it exactly as it was.
    fn strip_maintenance(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut inside = false;
        for line in text.split_inclusive('\n') {
            let t = line.trim();
            if t == MAINTENANCE_BEGIN {
                inside = true;
            } else if t == MAINTENANCE_END {
                inside = false;
            } else if !inside {
                out.push_str(line);
            }
        }
        out
    }

    /// Add the maintenance block to an imported vhost, right after `server_name` in each server
    /// that visitors reach on port 80 or 443. CE also has an internal server, reached from
    /// 127.0.0.1 through the public one; gating it too would refuse the allowed addresses.
    fn add_maintenance(text: &str, site: &Site) -> Result<String, String> {
        let clean = Self::strip_maintenance(text);
        let block = format!(
            "    {MAINTENANCE_BEGIN}\n{}    {MAINTENANCE_END}\n",
            Self::maintenance_block(site)
        );
        let lines: Vec<&str> = clean.split_inclusive('\n').collect();
        // Line ranges of the top-level server blocks.
        let mut blocks: Vec<(usize, usize)> = Vec::new();
        let mut depth = 0i32;
        let mut start = None;
        for (i, line) in lines.iter().enumerate() {
            let code = line.split('#').next().unwrap_or_default();
            if depth == 0 && start.is_none() && code.trim_start().starts_with("server") && code.contains('{') {
                start = Some(i);
            }
            depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
            if depth <= 0 {
                depth = 0;
                if let Some(s) = start.take() {
                    blocks.push((s, i));
                }
            }
        }
        let public = |l: &str| {
            let mut w = l
                .split('#')
                .next()
                .unwrap_or_default()
                .trim()
                .trim_end_matches(';')
                .split_whitespace();
            w.next() == Some("listen")
                && w.next()
                    .map(|a| a.rsplit_once(':').map_or(a, |(_, p)| p))
                    .is_some_and(|p| p == "80" || p == "443")
        };
        let mut insert_after = Vec::new();
        for (s, e) in blocks {
            let body = &lines[s..=e];
            if !body.iter().any(|l| public(l)) {
                continue;
            }
            if let Some(off) = body.iter().position(|l| l.trim_start().starts_with("server_name")) {
                insert_after.push(s + off);
            }
        }
        if insert_after.is_empty() {
            return Err(format!(
                "No server in the nginx config of {} listens on port 80 or 443, so maintenance mode can't be added",
                site.domain
            ));
        }
        let mut out = String::with_capacity(clean.len() + block.len() * insert_after.len());
        for (i, line) in lines.iter().enumerate() {
            out.push_str(line);
            if insert_after.contains(&i) {
                if !line.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&block);
            }
        }
        Ok(out)
    }

    /// Turn maintenance mode on or off for a site whose vhost was imported from CE. Its file is
    /// kept as it is apart from the marked block, which is taken out again when maintenance ends.
    /// The file is changed where it is (CE keeps plain files in sites-enabled), checked with
    /// `nginx -t` and put back on failure.
    pub fn apply_imported_maintenance(config: &Config, site: &Site) -> Result<(), String> {
        let (available, enabled) = Self::paths(config, &site.domain);
        // A link in sites-enabled points at sites-available: change the file it points at.
        let path = if available.exists() { available } else { enabled };
        let previous = fs::read(&path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        let text = String::from_utf8(previous.clone()).map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
        let next = if site.maintenance_mode {
            Self::add_maintenance(&text, site)?
        } else {
            Self::strip_maintenance(&text)
        };
        if next == text {
            return Ok(());
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&path)
                .map(|m| m.permissions().mode() & 0o7777)
                .unwrap_or(0o644)
        };
        #[cfg(not(unix))]
        let mode = 0o644;
        write_atomic(&path, next.as_bytes(), mode).map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
        if let Err(e) = Self::test() {
            let _ = write_atomic(&path, &previous, mode);
            warn!("nginx rejected maintenance mode for {}: {e}", site.domain);
            return Err(e);
        }
        Self::reload()?;
        info!(
            "Maintenance mode {} for imported site {}",
            if site.maintenance_mode { "on" } else { "off" },
            site.domain
        );
        Ok(())
    }

    /// Rewrite the vhosts of sites without a certificate that predate the fallback certificate,
    /// so HTTPS for them reaches the site rather than the catch-all.
    pub fn refresh_sites_without_tls(config: &Config, sites: &[Site]) {
        let Some(tls) = Self::fallback_tls(config) else { return };
        let marker = tls.lines().nth(2).unwrap_or_default().trim().to_string();
        for site in sites.iter().filter(|s| s.vhost_managed && !s.has_tls()) {
            if Self::read_vhost(config, &site.domain).is_some_and(|v| v.contains(&marker)) {
                continue;
            }
            if let Err(e) = Self::write_and_apply(config, site) {
                warn!("could not add HTTPS fallback for {}: {e}", site.domain);
            }
        }
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
        if site.maintenance_mode {
            out.push_str(&Self::maintenance_block(site));
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
{tls}    server_name {names};

{body}}}
"#,
                tls = Self::fallback_tls(config).unwrap_or_default(),
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
                 server {{\n    listen 80;\n    listen [::]:80;\n{tls}    server_name {www};\n\n{ACME}\n    \
                 location / {{\n        return 301 http://{domain}$request_uri;\n    }}\n}}\n\n\
                 server {{\n    listen 80;\n    listen [::]:80;\n{tls}    server_name {domain};\n\n{body}}}\n",
                tls = Self::fallback_tls(config).unwrap_or_default(),
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

    /// The public HTTPS endpoint for Garage's S3 API. Path-style only, so one name and one
    /// certificate cover every bucket. Signatures cover the Host header, so it is passed as is,
    /// and bodies stream straight through: S3 objects can be any size.
    pub fn render_s3_vhost(config: &Config, hostname: &str, cert: &str, key: &str, upstream: &str) -> String {
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

    client_max_body_size 0;

    location / {{
        proxy_pass http://{upstream};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
}}
"#,
            log = config.nginx_log_dir.display(),
        )
    }

    pub fn apply_s3_vhost(
        config: &Config,
        hostname: &str,
        cert: &str,
        key: &str,
        upstream: &str,
    ) -> Result<(), String> {
        let content = Self::render_s3_vhost(config, hostname, cert, key, upstream);
        Self::install_vhost(config, S3_VHOST, &content, 0o644)
    }

    pub fn remove_s3_vhost(config: &Config) -> Result<(), String> {
        if Self::paths(config, S3_VHOST).0.symlink_metadata().is_err() {
            return Ok(());
        }
        Self::remove_site(config, S3_VHOST)
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
        maintenance_mode: false,
        maintenance_message: String::new(),
        maintenance_allow: String::new(),
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

    /// As CE writes a vhost: a public server, and an internal one the public one proxies to.
    const CE_VHOST: &str = "server {\n  listen 80;\n  listen [::]:80;\n  listen 443 ssl http2;\n  \
        ssl_certificate /etc/nginx/ssl-certificates/shop.test.crt;\n  server_name shop.test www.shop.test; # names\n  \
        root /home/shop/htdocs/shop.test;\n  location / {\n    proxy_pass http://127.0.0.1:8080;\n  }\n}\n\n\
        server {\n  listen 8080;\n  listen [::]:8080;\n  server_name shop.test www.shop.test;\n  \
        location ~ \\.php$ {\n    fastcgi_pass 127.0.0.1:18001;\n  }\n}\n";

    fn imported() -> Site {
        let mut s = test_site("php");
        s.domain = "shop.test".into();
        s.vhost_managed = false;
        s.maintenance_mode = true;
        s.maintenance_allow = "203.0.113.7".into();
        s
    }

    #[test]
    fn imported_vhost_gets_maintenance_only_on_its_public_server() {
        let out = NginxService::add_maintenance(CE_VHOST, &imported()).unwrap();
        assert_eq!(out.matches(MAINTENANCE_BEGIN).count(), 1);
        let public_end = out.find("\n}\n").unwrap();
        let gate = out.find("if ($cloudpanel_maintenance)").unwrap();
        assert!(gate > out.find("server_name shop.test www.shop.test; # names").unwrap());
        assert!(gate < public_end, "the block goes into the public server");
        // Adding it again replaces it rather than stacking.
        let again = NginxService::add_maintenance(&out, &imported()).unwrap();
        assert_eq!(again, out);
        // Taking it out restores the file byte for byte.
        assert_eq!(NginxService::strip_maintenance(&out), CE_VHOST);
    }

    #[test]
    fn imported_vhost_without_a_public_server_is_refused() {
        let internal = "server {\n  listen 8080;\n  server_name shop.test;\n}\n";
        assert!(NginxService::add_maintenance(internal, &imported()).is_err());
    }

    #[test]
    fn imported_maintenance_edits_the_file_in_place() {
        let dir = std::env::temp_dir().join(format!("cp-maint-{}", std::process::id()));
        let mut c = cfg();
        c.nginx_sites_available = dir.join("sites-available");
        c.nginx_sites_enabled = dir.join("sites-enabled");
        fs::create_dir_all(&c.nginx_sites_enabled).unwrap();
        // CE keeps a plain file in sites-enabled and nothing in sites-available.
        let file = c.nginx_sites_enabled.join("shop.test.conf");
        fs::write(&file, CE_VHOST).unwrap();
        let mut s = imported();
        NginxService::apply_imported_maintenance(&c, &s).unwrap();
        assert!(fs::read_to_string(&file).unwrap().contains("return 503;"));
        assert!(!c.nginx_sites_available.join("shop.test.conf").exists());
        s.maintenance_mode = false;
        NginxService::apply_imported_maintenance(&c, &s).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), CE_VHOST);
        let _ = fs::remove_dir_all(&dir);
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
    fn maintenance_mode_answers_before_any_location() {
        let mut s = test_site("php");
        s.maintenance_mode = true;
        s.basic_auth_enabled = true;
        s.basic_auth_allow = "10.0.0.0/8".into();
        s.custom_directives = "location /api/ {\n    return 200;\n}".into();
        let c = NginxService::generate_config(&cfg(), &s);
        // Server-level rules come before every location, so none can let a visitor past.
        let gate = c.find("if ($cloudpanel_maintenance)").unwrap();
        assert!(gate < c.find("location /").unwrap());
        assert!(c.contains("set $cloudpanel_maintenance 1;"));
        assert!(c.contains("if ($uri ~ \"^/\\.well-known/acme-challenge/\")"));
        assert!(c.contains("error_page 503 @cloudpanel_maintenance;"));
        assert!(c.contains("location @cloudpanel_maintenance {"));
        assert!(c.contains(DEFAULT_MAINTENANCE_MESSAGE.replace('\'', "&#39;").as_str()));
        // The site is still there behind it.
        assert!(c.contains("fastcgi_pass"));
        assert!(!c.contains("$remote_addr ~"));
    }

    #[test]
    fn maintenance_bypass_lists_exact_addresses() {
        let mut s = test_site("nodejs");
        s.maintenance_mode = true;
        s.maintenance_allow = "203.0.113.7\n2001:db8::1\nnot-an-ip\n".into();
        let c = NginxService::generate_config(&cfg(), &s);
        assert!(c.contains("if ($remote_addr ~ \"^(203\\.0\\.113\\.7|2001:db8::1)$\")"));
    }

    #[test]
    fn maintenance_message_cannot_break_out_of_the_page() {
        let mut s = test_site("static");
        s.maintenance_mode = true;
        s.maintenance_message = "Back at 5' o\\clock; costs $5 <script>{x}</script>\nThanks".into();
        let page = NginxService::maintenance_page(&s);
        for bad in ['\'', '\\', '$', '<' /* only from our own markup */] {
            if bad == '<' {
                assert!(!page.contains("<script>"));
            } else {
                assert!(!page.contains(bad), "{bad} survived");
            }
        }
        assert!(page.contains("5&#39; o&#92;clock; costs &#36;5 &lt;script&gt;&#123;x&#125;&lt;/script&gt;<br>Thanks"));
    }

    #[test]
    fn disabled_site_ignores_maintenance_mode() {
        let mut s = test_site("nodejs");
        s.is_active = false;
        s.maintenance_mode = true;
        let c = NginxService::generate_config(&cfg(), &s);
        assert!(!c.contains("cloudpanel_maintenance"));
        assert!(c.contains("return 503 '"));
    }

    #[test]
    fn default_vhost_claims_only_free_ports() {
        let c = cfg();
        assert!(NginxService::render_default_vhost(&c, false, false).is_none());
        let only_tls = NginxService::render_default_vhost(&c, false, true).unwrap();
        assert!(only_tls.contains("listen 443 ssl http2 default_server;"));
        assert!(!only_tls.contains("listen 80 default_server;"));
        assert!(only_tls.contains("return 404 '"));
        assert!(!only_tls.contains("proxy_pass"));
        let both = NginxService::render_default_vhost(&c, true, true).unwrap();
        assert!(both.contains("listen [::]:80 default_server;"));
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
