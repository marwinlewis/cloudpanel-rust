use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub sites_dir: PathBuf,
    pub nginx_sites_available: PathBuf,
    pub nginx_sites_enabled: PathBuf,
    pub cron_file: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Parent of site users' home directories.
    pub home_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub systemd_dir: PathBuf,
    /// `/etc/cloudpanel`: env files, htpasswd files, encryption key.
    pub etc_dir: PathBuf,
    pub log_dir: PathBuf,
    pub stacks_dir: PathBuf,
    pub nginx_log_dir: PathBuf,
    pub fail2ban_dir: PathBuf,
    /// One file per address banned from the panel, kept by fail2ban's action. Under `/run`, as
    /// fail2ban restores its bans after a reboot.
    pub ban_dir: PathBuf,
    pub sshd_config_dir: PathBuf,
    /// Database engines selected at install time (`CLOUDPANEL_DB_ENGINES`).
    pub db_engines: Vec<String>,
    /// PHP sites can be created, chosen at install time (`CLOUDPANEL_PHP=1`).
    pub php_enabled: bool,
    /// Where Cloudflare's address ranges are fetched from (`CLOUDPANEL_CLOUDFLARE_IPS_URL`).
    pub cloudflare_ips_url: String,
    /// Where the latest CloudPanel release is looked up (`CLOUDPANEL_RELEASE_URL`).
    pub panel_release_url: String,
}

fn env_or(key: &str, linux_default: &str, dev_default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        if cfg!(windows) {
            dev_default.to_string()
        } else {
            linux_default.to_string()
        }
    })
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
}

impl Config {
    pub fn from_env() -> Self {
        let bind_addr = std::env::var("CLOUDPANEL_BIND").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
        let data_dir = PathBuf::from(env_or("CLOUDPANEL_DATA_DIR", "/var/lib/cloudpanel", "./data"));
        let db_path = env_path("CLOUDPANEL_DB_PATH").unwrap_or_else(|| data_dir.join("cloudpanel.db"));

        Self {
            bind_addr,
            db_path,
            sites_dir: PathBuf::from(env_or("CLOUDPANEL_SITES_DIR", "/var/www", "./data/sites")),
            nginx_sites_available: PathBuf::from(env_or(
                "CLOUDPANEL_NGINX_AVAILABLE",
                "/etc/nginx/sites-available",
                "./data/nginx/sites-available",
            )),
            nginx_sites_enabled: PathBuf::from(env_or(
                "CLOUDPANEL_NGINX_ENABLED",
                "/etc/nginx/sites-enabled",
                "./data/nginx/sites-enabled",
            )),
            cron_file: PathBuf::from(env_or(
                "CLOUDPANEL_CRON_FILE",
                "/etc/cron.d/cloudpanel",
                "./data/cron.d/cloudpanel",
            )),
            tls_cert: env_path("CLOUDPANEL_TLS_CERT"),
            tls_key: env_path("CLOUDPANEL_TLS_KEY"),
            home_dir: PathBuf::from(env_or("CLOUDPANEL_HOME_DIR", "/home", "./data/home")),
            backup_dir: PathBuf::from(env_or(
                "CLOUDPANEL_BACKUP_DIR",
                "/var/backups/cloudpanel",
                "./data/backups",
            )),
            systemd_dir: PathBuf::from(env_or(
                "CLOUDPANEL_SYSTEMD_DIR",
                "/etc/systemd/system",
                "./data/systemd",
            )),
            etc_dir: PathBuf::from(env_or("CLOUDPANEL_ETC_DIR", "/etc/cloudpanel", "./data/etc")),
            log_dir: PathBuf::from(env_or("CLOUDPANEL_LOG_DIR", "/var/log/cloudpanel", "./data/log")),
            stacks_dir: env_path("CLOUDPANEL_STACKS_DIR").unwrap_or_else(|| data_dir.join("stacks")),
            nginx_log_dir: PathBuf::from(env_or("CLOUDPANEL_NGINX_LOG_DIR", "/var/log/nginx", "./data/log/nginx")),
            fail2ban_dir: PathBuf::from(env_or("CLOUDPANEL_FAIL2BAN_DIR", "/etc/fail2ban", "./data/fail2ban")),
            ban_dir: PathBuf::from(env_or("CLOUDPANEL_BAN_DIR", "/run/cloudpanel-bans", "./data/bans")),
            sshd_config_dir: PathBuf::from(env_or(
                "CLOUDPANEL_SSHD_DIR",
                "/etc/ssh/sshd_config.d",
                "./data/ssh/sshd_config.d",
            )),
            db_engines: std::env::var("CLOUDPANEL_DB_ENGINES")
                .unwrap_or_else(|_| if cfg!(windows) { "sqlite".into() } else { String::new() })
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| matches!(s.as_str(), "mariadb" | "mongodb" | "sqlite"))
                .collect(),
            php_enabled: std::env::var("CLOUDPANEL_PHP").is_ok_and(|v| v.trim() == "1"),
            cloudflare_ips_url: std::env::var("CLOUDPANEL_CLOUDFLARE_IPS_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| crate::services::cloudflare::DEFAULT_URL.to_string()),
            panel_release_url: std::env::var("CLOUDPANEL_RELEASE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| crate::services::panel_update::DEFAULT_URL.to_string()),
            data_dir,
        }
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }

    /// Port the panel itself listens on (used to refuse firewall rules that would lock us out).
    pub fn panel_port(&self) -> Option<u16> {
        self.bind_addr.rsplit(':').next()?.parse().ok()
    }

    pub fn ssl_dir(&self) -> PathBuf {
        self.data_dir.join("ssl")
    }

    pub fn engine_configured(&self, engine: &str) -> bool {
        self.db_engines.iter().any(|e| e == engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_settings() {
        let mut c = Config::from_env();
        c.bind_addr = "0.0.0.0:8443".into();
        assert_eq!(c.panel_port(), Some(8443));
        c.bind_addr = "[::]:9000".into();
        assert_eq!(c.panel_port(), Some(9000));
        c.bind_addr = "garbage".into();
        assert_eq!(c.panel_port(), None);

        c.tls_cert = Some("cert.pem".into());
        c.tls_key = None;
        assert!(!c.tls_enabled());
        c.tls_key = Some("key.pem".into());
        assert!(c.tls_enabled());

        c.data_dir = PathBuf::from("base");
        assert_eq!(c.ssl_dir(), PathBuf::from("base").join("ssl"));

        c.db_engines = vec!["sqlite".into(), "mariadb".into()];
        assert!(c.engine_configured("mariadb"));
        assert!(!c.engine_configured("mongodb"));
    }
}
