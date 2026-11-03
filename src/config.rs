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
}
