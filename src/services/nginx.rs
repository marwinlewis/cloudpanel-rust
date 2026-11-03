use super::cmd::{run, CmdOutcome};
use crate::config::Config;
use crate::db::models::Site;
use crate::fsutil::write_atomic;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct NginxService;

const PROXY_LOCATION: &str = r#"    location / {
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_cache_bypass $http_upgrade;
    }"#;

const STATIC_LOCATION: &str = r#"    root {root};
    index index.html index.htm;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }"#;

const SECURITY_HEADERS: &str = r#"    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;"#;

/// Shared `map` so `Connection: upgrade` is only sent for websocket requests.
const UPGRADE_MAP_FILE: &str = "cloudpanel-upgrade-map.conf";
const UPGRADE_MAP: &str =
    "# Managed by CloudPanel\nmap $http_upgrade $connection_upgrade {\n    default upgrade;\n    ''      close;\n}\n";

impl NginxService {
    /// Render the vhost. All interpolated values are validated before reaching here
    /// (domain via `validate::domain`, paths via `validate::path_within` or derived from config).
    pub fn generate_config(site: &Site) -> String {
        let names = site.server_names().join(" ");
        let location = if site.site_type == "static" {
            let root = site.document_root.as_deref().unwrap_or("/var/www/html");
            STATIC_LOCATION.replace("{root}", root)
        } else {
            PROXY_LOCATION.replace("{port}", &site.target_port.unwrap_or(3000).to_string())
        };
        let domain = &site.domain;

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

{SECURITY_HEADERS}
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 128M;
    access_log /var/log/nginx/{domain}.access.log;
    error_log /var/log/nginx/{domain}.error.log;

{location}
}}
"#
            ),
            _ => format!(
                r#"# Managed by CloudPanel - changes will be overwritten
server {{
    listen 80;
    listen [::]:80;
    server_name {names};

{SECURITY_HEADERS}

    client_max_body_size 128M;
    access_log /var/log/nginx/{domain}.access.log;
    error_log /var/log/nginx/{domain}.error.log;

{location}
}}
"#
            ),
        }
    }

    fn paths(config: &Config, domain: &str) -> (PathBuf, PathBuf) {
        let file_name = format!("{domain}.conf");
        (
            config.nginx_sites_available.join(&file_name),
            config.nginx_sites_enabled.join(&file_name),
        )
    }

    fn ensure_upgrade_map(config: &Config) -> Result<(), String> {
        // conf.d sits next to sites-available on Debian/Ubuntu.
        let Some(root) = config.nginx_sites_available.parent() else {
            return Ok(());
        };
        let path = root.join("conf.d").join(UPGRADE_MAP_FILE);
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
        fs::create_dir_all(&config.nginx_sites_available)
            .map_err(|e| format!("Failed to create sites-available: {e}"))?;
        fs::create_dir_all(&config.nginx_sites_enabled).map_err(|e| format!("Failed to create sites-enabled: {e}"))?;
        Self::ensure_upgrade_map(config)?;

        let (available, enabled) = Self::paths(config, &site.domain);
        let previous = fs::read(&available).ok();
        let was_enabled = enabled.symlink_metadata().is_ok();

        write_atomic(&available, Self::generate_config(site).as_bytes(), 0o644)
            .map_err(|e| format!("Failed to write nginx config: {e}"))?;
        Self::link(&available, &enabled)?;

        if let Err(e) = Self::test() {
            match previous {
                Some(prev) => {
                    let _ = write_atomic(&available, &prev, 0o644);
                    if !was_enabled {
                        let _ = fs::remove_file(&enabled);
                    }
                }
                None => {
                    let _ = fs::remove_file(&enabled);
                    let _ = fs::remove_file(&available);
                }
            }
            warn!("nginx rejected config for {}: {e}", site.domain);
            return Err(e);
        }

        Self::reload()?;
        info!("Applied nginx configuration for {}", site.domain);
        Ok(())
    }

    pub fn remove_site(config: &Config, domain: &str) -> Result<(), String> {
        let (available, enabled) = Self::paths(config, domain);
        for p in [&enabled, &available] {
            if p.symlink_metadata().is_ok() {
                fs::remove_file(p).map_err(|e| format!("Failed to remove {}: {e}", p.display()))?;
            }
        }
        Self::test()?;
        Self::reload()?;
        info!("Removed nginx configuration for {domain}");
        Ok(())
    }

    pub fn test() -> Result<(), String> {
        match run("nginx", &["-t", "-q"]) {
            CmdOutcome::Ok(_) => Ok(()),
            CmdOutcome::Failed(e) => Err(format!("nginx configuration test failed: {e}")),
            CmdOutcome::Missing => {
                warn!("nginx not installed; skipping config test");
                Ok(())
            }
        }
    }

    pub fn reload() -> Result<(), String> {
        match run("systemctl", &["reload", "nginx"]) {
            CmdOutcome::Ok(_) => return Ok(()),
            CmdOutcome::Failed(e) => warn!("systemctl reload nginx failed: {e}"),
            CmdOutcome::Missing => {}
        }
        match run("nginx", &["-s", "reload"]) {
            CmdOutcome::Ok(_) => Ok(()),
            CmdOutcome::Failed(e) => Err(format!("nginx reload failed: {e}")),
            CmdOutcome::Missing => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn site(site_type: &str) -> Site {
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn proxy_config() {
        let c = NginxService::generate_config(&site("nodejs"));
        assert!(c.contains("server_name app.example.com;"));
        assert!(c.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(!c.contains("listen 443"));
    }

    #[test]
    fn static_ssl_config_with_www() {
        let mut s = site("static");
        s.include_www = true;
        s.ssl_enabled = true;
        s.ssl_cert_path = Some("/etc/letsencrypt/live/app.example.com/fullchain.pem".into());
        s.ssl_key_path = Some("/etc/letsencrypt/live/app.example.com/privkey.pem".into());
        let c = NginxService::generate_config(&s);
        assert!(c.contains("server_name app.example.com www.app.example.com;"));
        assert!(c.contains("root /var/www/app.example.com/public;"));
        assert!(c.contains("listen 443 ssl http2;"));
        assert!(c.contains("return 301 https://$host$request_uri;"));
    }
}
