use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    pub port: u16,
    pub protocol: String, // "tcp", "udp", "any"
    pub action: String,   // "allow", "deny"
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CronJob {
    pub id: i64,
    pub site_id: Option<i64>,
    pub schedule: String,
    pub command: String,
    pub user: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}
