//! Email sending service, in the style of Resend: verified domains, API keys, and two ways in.
//!
//! - **SMTP** on 587 (STARTTLS) and 465 (TLS): username `cloudpanel`, password = an API key. This is
//!   what Gmail's "Send mail as" and any app's SMTP settings use.
//! - **HTTP** `POST /emails` (Resend-compatible shape) behind nginx on the mail hostname.
//!
//! The service (`cloudpanel mail-serve`) runs as its own unprivileged user. It checks the key and the
//! sender's domain, signs with DKIM and hands the message to Postfix through `sendmail`. Postfix
//! queues, retries and delivers, and receives mail for forwarding addresses on port 25 (rewritten with
//! SRS by postsrsd so forwarding passes SPF). The service follows Postfix's log to record what
//! happened to every message and calls webhooks.
//!
//! The service's database lives in its own directory, owned by its user, so the root panel's
//! database and secret key never have to be readable by the internet-facing process. It is managed
//! from the panel's Email page or the CLI (`cloudpanel mail-*`, run as root), both through [`manage`].

pub mod cli;
pub mod dkim;
pub mod dns;
pub mod events;
pub mod http;
pub mod install;
pub mod keys;
pub mod manage;
pub mod message;
pub mod send;
pub mod serve;
pub mod smtp;
pub mod store;

use std::path::PathBuf;

/// System user the service runs as.
pub const USER: &str = "cloudpanel-mail";
/// Its systemd unit.
pub const UNIT: &str = "cloudpanel-mail.service";
/// The fixed SMTP username. The API key is the password, as with Resend.
pub const SMTP_USERNAME: &str = "cloudpanel";
/// DKIM selector published for every domain.
pub const DKIM_SELECTOR: &str = "cloudpanel";
/// nginx vhost name for the HTTP API.
pub const VHOST: &str = "cloudpanel-mail";
/// Where the HTTP API listens, behind nginx.
pub const HTTP_ADDR: &str = "127.0.0.1:2580";
/// Largest message accepted, in bytes (SMTP SIZE and the HTTP body limit).
pub const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;
/// Most recipients (to + cc + bcc) on one message.
pub const MAX_RECIPIENTS: usize = 50;
/// Default per-key sending limit, messages per hour.
pub const DEFAULT_HOURLY_LIMIT: u32 = 500;
/// Sent-message logs are kept this long.
pub const LOG_RETENTION_DAYS: i64 = 30;

/// Paths and settings for the mail service. Every value has a Linux default and an env override,
/// so tests and local runs can point it at a temporary directory.
#[derive(Clone, Debug)]
pub struct MailConfig {
    /// Data directory owned by [`USER`]: database, DKIM keys, journal cursor.
    pub state_dir: PathBuf,
    /// The public mail hostname (MX target, SMTP server name, API host).
    pub hostname: String,
    pub http_addr: String,
    pub smtp_addr: String,
    pub smtps_addr: String,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub sendmail: PathBuf,
    /// Where the certificate comes from (Let's Encrypt or self-signed). The service reads copies in
    /// its own directory, refreshed by `mail-cert-sync`.
    pub cert_source: Option<PathBuf>,
    pub key_source: Option<PathBuf>,
}

/// Settings written by `mail-install`, read by the service (EnvironmentFile) and by the CLI.
pub const ENV_FILE: &str = "/etc/cloudpanel/mail.env";

/// A setting from the environment, else from [`ENV_FILE`] (certbot's hook and root shells don't
/// load it).
pub(crate) fn env(key: &str) -> Option<String> {
    if let Some(v) = std::env::var(key).ok().filter(|v| !v.trim().is_empty()) {
        return Some(v);
    }
    let file = std::fs::read_to_string(ENV_FILE).ok()?;
    file.lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

impl MailConfig {
    pub fn from_env() -> Self {
        let state_dir = PathBuf::from(env("CLOUDPANEL_MAIL_DIR").unwrap_or_else(|| {
            if cfg!(target_os = "linux") {
                "/var/lib/cloudpanel-mail".into()
            } else {
                "./data/mail".into()
            }
        }));
        // Copies the service's user can read; see `install::sync_cert`.
        let tls_cert = env("CLOUDPANEL_MAIL_TLS_CERT")
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("tls/cert.pem"));
        let tls_key = env("CLOUDPANEL_MAIL_TLS_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("tls/key.pem"));
        Self {
            hostname: env("CLOUDPANEL_MAIL_HOST").unwrap_or_else(|| "localhost".into()),
            http_addr: env("CLOUDPANEL_MAIL_HTTP").unwrap_or_else(|| HTTP_ADDR.into()),
            smtp_addr: env("CLOUDPANEL_MAIL_SMTP").unwrap_or_else(|| "0.0.0.0:587".into()),
            smtps_addr: env("CLOUDPANEL_MAIL_SMTPS").unwrap_or_else(|| "0.0.0.0:465".into()),
            sendmail: PathBuf::from(env("CLOUDPANEL_MAIL_SENDMAIL").unwrap_or_else(|| "/usr/sbin/sendmail".into())),
            cert_source: env("CLOUDPANEL_MAIL_CERT_SOURCE").map(PathBuf::from),
            key_source: env("CLOUDPANEL_MAIL_KEY_SOURCE").map(PathBuf::from),
            tls_cert,
            tls_key,
            state_dir,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("mail.db")
    }

    pub fn dkim_dir(&self) -> PathBuf {
        self.state_dir.join("dkim")
    }

    pub fn dkim_key_path(&self, domain: &str) -> PathBuf {
        self.dkim_dir().join(format!("{domain}.pem"))
    }

    pub fn cursor_path(&self) -> PathBuf {
        self.state_dir.join("journal.cursor")
    }
}

/// Current time as an RFC 3339 string (what every table stores).
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A random id like Resend's: a UUID v4 in its usual text form.
pub fn new_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// The domain part of an address, lowercased. None when it isn't `local@domain`.
pub fn domain_of(address: &str) -> Option<String> {
    let (local, domain) = address.trim().rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(domain.trim_end_matches('.').to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_uuid_v4() {
        let id = new_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert_ne!(new_id(), id);
    }

    #[test]
    fn domain_of_addresses() {
        assert_eq!(domain_of("Me@Example.COM").as_deref(), Some("example.com"));
        assert_eq!(domain_of("a@b@c.io").as_deref(), Some("c.io"));
        assert_eq!(domain_of("nobody"), None);
        assert_eq!(domain_of("@x.com"), None);
    }
}
