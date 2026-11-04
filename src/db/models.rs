use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_SITE_MANAGER: &str = "site_manager";

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub email: String,
    pub role: String, // "admin" or "site_manager"
    #[serde(skip_serializing)]
    pub token_version: i64,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    #[serde(skip_serializing)]
    pub recovery_codes: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SiteType {
    Nodejs,
    Python,
    Static,
    DockerProxy,
    ReverseProxy,
}

impl SiteType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SiteType::Nodejs => "nodejs",
            SiteType::Python => "python",
            SiteType::Static => "static",
            SiteType::DockerProxy => "docker_proxy",
            SiteType::ReverseProxy => "reverse_proxy",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "nodejs" => Some(SiteType::Nodejs),
            "python" => Some(SiteType::Python),
            "static" => Some(SiteType::Static),
            "docker_proxy" => Some(SiteType::DockerProxy),
            "reverse_proxy" => Some(SiteType::ReverseProxy),
            _ => None,
        }
    }

    /// Site types whose process CloudPanel can supervise with a systemd unit.
    pub fn has_app(&self) -> bool {
        matches!(self, SiteType::Nodejs | SiteType::Python | SiteType::ReverseProxy)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Site {
    pub id: i64,
    pub domain: String,
    pub site_type: String,
    pub target_port: Option<u16>,
    pub document_root: Option<String>,
    pub system_user: String,
    pub include_www: bool,
    pub ssl_enabled: bool,
    pub ssl_auto_renew: bool,
    pub ssl_cert_path: Option<String>,
    pub ssl_key_path: Option<String>,
    pub is_active: bool,
    pub app_command: Option<String>,
    pub app_workdir: Option<String>,
    /// JSON object of environment variables for the app unit.
    #[serde(skip_serializing)]
    pub app_env: String,
    pub app_enabled: bool,
    /// Home directory of the site's Linux user (None for sites created before v0.3).
    pub home_dir: Option<String>,
    pub websocket: bool,
    pub max_body_mb: i64,
    pub custom_directives: String,
    pub basic_auth_enabled: bool,
    /// Newline-separated IPs/CIDRs that bypass basic auth.
    pub basic_auth_allow: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Site {
    pub fn server_names(&self) -> Vec<String> {
        let mut names = vec![self.domain.clone()];
        if self.include_www {
            names.push(format!("www.{}", self.domain));
        }
        names
    }

    pub fn kind(&self) -> Option<SiteType> {
        SiteType::parse(&self.site_type)
    }

    pub fn env_map(&self) -> std::collections::BTreeMap<String, String> {
        serde_json::from_str(&self.app_env).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirewallRule {
    pub id: i64,
    pub port: Option<u16>,
    pub port_end: Option<u16>,
    pub protocol: String, // "tcp", "udp", "any"
    pub action: String,   // "allow", "deny"
    pub source: Option<String>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CronJob {
    pub id: i64,
    pub site_id: Option<i64>,
    pub name: Option<String>,
    pub schedule: String,
    pub command: String,
    pub user: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CronRun {
    pub id: i64,
    pub job_id: i64,
    pub started_at: DateTime<Utc>,
    pub duration_ms: i64,
    pub exit_code: Option<i64>,
    pub output: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: i64,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub ip: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: i64,
    pub kind: String,
    pub target: Option<String>,
    pub status: String,
    pub output: String,
    pub user_id: Option<i64>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshUser {
    pub id: i64,
    pub site_id: i64,
    pub username: String,
    pub sftp_only: bool,
    pub is_owner: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshKey {
    pub id: i64,
    pub ssh_user_id: i64,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicAuthUser {
    pub id: i64,
    pub site_id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Database {
    pub id: i64,
    pub site_id: i64,
    pub engine: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupPolicy {
    pub site_id: i64,
    pub frequency: String,
    pub hour: i64,
    pub retention: i64,
    pub remote_enabled: bool,
    pub last_run: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Backup {
    pub id: i64,
    pub site_id: Option<i64>,
    pub domain: String,
    #[serde(skip_serializing)]
    pub path: String,
    pub file_name: String,
    pub size: i64,
    pub status: String,
    pub remote_key: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertChannel {
    pub id: i64,
    pub kind: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub config: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}
