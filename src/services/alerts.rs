//! Alerts: threshold checks run by the scheduler every minute and one-off event
//! notifications, delivered by email (SMTP) or webhooks (generic JSON, Slack, Discord).

use crate::config::Config;
use crate::db::{self, models::AlertChannel, DbPool};
use crate::state::SharedState;
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

pub const RULES_SETTING: &str = "alert_rules";
/// How a new CloudPanel release's notification starts; `notify_event` routes on it.
pub const PANEL_UPDATE_TITLE: &str = "Update available: CloudPanel";
const REMIND_AFTER_HOURS: i64 = 6;

fn on() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AlertRules {
    pub disk_pct: f32,
    pub memory_pct: f32,
    pub cpu_pct: f32,
    /// Minutes CPU/memory must stay above the threshold.
    pub sustain_minutes: u32,
    pub cert_days: i64,
    pub services: bool,
    pub backups: bool,
    pub security: bool,
    /// Defaulted because rules saved before this existed would otherwise fail to load, and be
    /// silently replaced by the defaults.
    #[serde(default = "on")]
    pub panel_updates: bool,
}

impl Default for AlertRules {
    fn default() -> Self {
        AlertRules {
            disk_pct: 90.0,
            memory_pct: 90.0,
            cpu_pct: 90.0,
            sustain_minutes: 5,
            cert_days: 14,
            services: true,
            backups: true,
            security: true,
            panel_updates: true,
        }
    }
}

impl AlertRules {
    pub fn validate(&self) -> Result<(), String> {
        for (n, v) in [
            ("Disk", self.disk_pct),
            ("Memory", self.memory_pct),
            ("CPU", self.cpu_pct),
        ] {
            if !(1.0..=100.0).contains(&v) {
                return Err(format!("{n} threshold must be between 1 and 100%"));
            }
        }
        if !(1..=60).contains(&self.sustain_minutes) || !(1..=90).contains(&self.cert_days) {
            return Err("Duration must be 1-60 minutes and certificate warning 1-90 days".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChannelConfig {
    Email {
        host: String,
        port: u16,
        /// "starttls", "tls" or "none"
        security: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        from: String,
        to: String,
    },
    Webhook {
        url: String,
    },
    Slack {
        url: String,
    },
    Discord {
        url: String,
    },
}

impl ChannelConfig {
    pub fn kind(&self) -> &'static str {
        match self {
            ChannelConfig::Email { .. } => "email",
            ChannelConfig::Webhook { .. } => "webhook",
            ChannelConfig::Slack { .. } => "slack",
            ChannelConfig::Discord { .. } => "discord",
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            ChannelConfig::Email {
                host,
                port,
                security,
                from,
                to,
                ..
            } => {
                crate::validate::domain(host).or_else(|_| {
                    host.parse::<std::net::IpAddr>()
                        .map(|_| String::new())
                        .map_err(|_| "Invalid SMTP host".to_string())
                })?;
                if *port == 0 || !matches!(security.as_str(), "starttls" | "tls" | "none") {
                    return Err("Invalid SMTP port or security".into());
                }
                crate::validate::email(from)?;
                for t in to.split(',') {
                    crate::validate::email(t.trim())?;
                }
                Ok(())
            }
            ChannelConfig::Webhook { url } | ChannelConfig::Slack { url } | ChannelConfig::Discord { url } => {
                let u = reqwest::Url::parse(url).map_err(|_| "Invalid webhook URL".to_string())?;
                if u.scheme() != "https" && u.scheme() != "http" {
                    return Err("Webhook URLs must use https".into());
                }
                Ok(())
            }
        }
    }

    /// A safe summary for the UI (no secrets).
    pub fn summary(&self) -> String {
        match self {
            ChannelConfig::Email { to, host, .. } => format!("{to} via {host}"),
            ChannelConfig::Webhook { url } | ChannelConfig::Slack { url } | ChannelConfig::Discord { url } => {
                reqwest::Url::parse(url)
                    .map(|u| u.host_str().unwrap_or("").to_string())
                    .unwrap_or_default()
            }
        }
    }
}

fn hostname() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "server".into())
}

fn send_email(cfg: &ChannelConfig, subject: &str, body: &str) -> Result<(), String> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};
    let ChannelConfig::Email {
        host,
        port,
        security,
        username,
        password,
        from,
        to,
    } = cfg
    else {
        return Err("not an email channel".into());
    };
    let mut msg = Message::builder()
        .from(from.parse().map_err(|e| format!("from: {e}"))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);
    for t in to.split(',') {
        msg = msg.to(t.trim().parse().map_err(|e| format!("to: {e}"))?);
    }
    let msg = msg.body(body.to_string()).map_err(|e| e.to_string())?;
    let builder = match security.as_str() {
        "tls" => SmtpTransport::relay(host).map_err(|e| e.to_string())?,
        "starttls" => SmtpTransport::starttls_relay(host).map_err(|e| e.to_string())?,
        _ => SmtpTransport::builder_dangerous(host),
    };
    let mut builder = builder.port(*port).timeout(Some(Duration::from_secs(20)));
    if !username.is_empty() {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }
    builder.build().send(&msg).map_err(|e| format!("SMTP: {e}"))?;
    Ok(())
}

fn send_webhook(cfg: &ChannelConfig, subject: &str, body: &str, level: &str) -> Result<(), String> {
    let (url, payload) = match cfg {
        ChannelConfig::Slack { url } => (url, serde_json::json!({ "text": format!("*{subject}*\n{body}") })),
        ChannelConfig::Discord { url } => (url, serde_json::json!({ "content": format!("**{subject}**\n{body}") })),
        ChannelConfig::Webhook { url } => (
            url,
            serde_json::json!({
                "source": "cloudpanel", "server": hostname(), "level": level,
                "title": subject, "message": body, "time": Utc::now(),
            }),
        ),
        ChannelConfig::Email { .. } => return Err("not a webhook channel".into()),
    };
    let url = url.clone();
    let send = async move {
        let res = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("webhook: {e}"))?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("webhook returned {}", res.status()))
        }
    };
    tokio::runtime::Handle::current().block_on(send)
}

pub fn deliver(cfg: &ChannelConfig, subject: &str, body: &str, level: &str) -> Result<(), String> {
    match cfg {
        ChannelConfig::Email { .. } => send_email(cfg, subject, body),
        _ => send_webhook(cfg, subject, body, level),
    }
}

fn channels(config: &Config, pool: &DbPool) -> Vec<(AlertChannel, ChannelConfig)> {
    let Ok(conn) = pool.get() else { return vec![] };
    db::list_alert_channels(&conn)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.enabled)
        .filter_map(|c| {
            let cfg = crate::secrets::open(&config.etc_dir, &c.config).ok()?;
            Some((c, cfg))
        })
        .collect()
}

fn broadcast(config: &Config, pool: &DbPool, subject: &str, body: &str, level: &str) {
    let subject = format!("[{}] {subject}", hostname());
    for (c, cfg) in channels(config, pool) {
        if let Err(e) = deliver(&cfg, &subject, body, level) {
            tracing::warn!("alert channel '{}' failed: {e}", c.name);
        }
    }
}

/// Send a one-off notification (failed backup, security event) to every channel.
pub fn notify_event(config: &Config, pool: &DbPool, title: &str, body: &str) {
    let rules: AlertRules = pool
        .get()
        .ok()
        .and_then(|c| db::get_json(&c, RULES_SETTING).ok())
        .unwrap_or_default();
    let enabled = if title.starts_with("Backup") {
        rules.backups
    } else if title.starts_with(PANEL_UPDATE_TITLE) {
        rules.panel_updates
    } else {
        rules.security
    };
    if !enabled {
        return;
    }
    let (config, pool, title, body) = (config.clone(), pool.clone(), title.to_string(), body.to_string());
    // Never block the caller on slow SMTP servers.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(move || broadcast(&config, &pool, &title, &body, "warning"));
    } else {
        broadcast(&config, &pool, &title, &body, "warning");
    }
}

// ---------- Threshold evaluation ----------

static CPU_HISTORY: Mutex<VecDeque<f32>> = Mutex::new(VecDeque::new());
static MEM_HISTORY: Mutex<VecDeque<f32>> = Mutex::new(VecDeque::new());
static TICKS: Mutex<u64> = Mutex::new(0);

fn push(hist: &Mutex<VecDeque<f32>>, v: f32, keep: usize) -> bool {
    let mut h = hist.lock().unwrap_or_else(|e| e.into_inner());
    h.push_back(v);
    while h.len() > keep {
        h.pop_front();
    }
    h.len() >= keep
}

fn sustained_above(hist: &Mutex<VecDeque<f32>>, threshold: f32) -> bool {
    let h = hist.lock().unwrap_or_else(|e| e.into_inner());
    !h.is_empty() && h.iter().all(|v| *v >= threshold)
}

/// One condition's current value.
pub struct Check {
    pub key: String,
    pub firing: bool,
    pub title: String,
    pub detail: String,
}

fn collect_checks(state: &SharedState, rules: &AlertRules) -> Vec<Check> {
    let mut checks = Vec::new();
    let m = {
        let mut c = state.metrics.lock().unwrap_or_else(|e| e.into_inner());
        c.collect()
    };
    let keep = rules.sustain_minutes as usize;
    let cpu_full = push(&CPU_HISTORY, m.total_cpu_usage, keep);
    let mem_full = push(&MEM_HISTORY, m.memory_usage_percentage, keep);
    checks.push(Check {
        key: "cpu".into(),
        firing: cpu_full && sustained_above(&CPU_HISTORY, rules.cpu_pct),
        title: format!("CPU usage above {:.0}%", rules.cpu_pct),
        detail: format!(
            "CPU has been at {:.0}% or more for {} minutes (now {:.0}%).",
            rules.cpu_pct, keep, m.total_cpu_usage
        ),
    });
    checks.push(Check {
        key: "memory".into(),
        firing: mem_full && sustained_above(&MEM_HISTORY, rules.memory_pct),
        title: format!("Memory usage above {:.0}%", rules.memory_pct),
        detail: format!("Memory is at {:.0}%.", m.memory_usage_percentage),
    });
    for d in &m.disks {
        checks.push(Check {
            key: format!("disk:{}", d.mount_point),
            firing: d.usage_percentage >= rules.disk_pct,
            title: format!("Disk {} is {:.0}% full", d.mount_point, d.usage_percentage),
            detail: format!(
                "{} has {:.1} GB free.",
                d.mount_point,
                d.available_space_bytes as f64 / 1e9
            ),
        });
    }

    let tick = {
        let mut t = TICKS.lock().unwrap_or_else(|e| e.into_inner());
        *t += 1;
        *t
    };
    let Ok(conn) = state.pool.get() else { return checks };
    let sites = db::list_sites(&conn).unwrap_or_default();

    if rules.services {
        for s in &sites {
            if s.app_enabled && s.is_active && super::apps::has_start(s) {
                let st = super::apps::status(&state.config, s);
                if st.installed && st.active_state != "unknown" {
                    checks.push(Check {
                        key: format!("app:{}", s.domain),
                        firing: st.active_state != "active" && st.active_state != "activating",
                        title: format!("App for {} is {}", s.domain, st.active_state),
                        detail: format!("The service {} is {} ({}).", st.unit, st.active_state, st.sub_state),
                    });
                }
            }
        }
        for (name, desc) in super::system::MANAGED {
            if let Some(st) = super::system::status(name, desc) {
                if st.enabled == "enabled" {
                    checks.push(Check {
                        key: format!("service:{name}"),
                        firing: st.active_state == "failed" || st.active_state == "inactive",
                        title: format!("{desc} ({name}) is {}", st.active_state),
                        detail: format!("systemd reports {name} as {} ({}).", st.active_state, st.sub_state),
                    });
                }
            }
        }
    }

    // Certificates change slowly; check once an hour.
    if tick % 60 == 1 {
        for s in &sites {
            if let Some(info) = s.ssl_cert_path.as_deref().and_then(super::ssl::SslService::cert_info) {
                checks.push(Check {
                    key: format!("cert:{}", s.domain),
                    firing: info.days_left < rules.cert_days,
                    title: format!("Certificate for {} expires in {} days", s.domain, info.days_left),
                    detail: format!("Expiry: {}. Issuer: {}.", info.not_after, info.issuer),
                });
            }
        }
    }
    checks
}

/// Called every minute by the scheduler.
pub fn evaluate(state: &SharedState) {
    let rules: AlertRules = state
        .pool
        .get()
        .ok()
        .and_then(|c| db::get_json(&c, RULES_SETTING).ok())
        .unwrap_or_default();
    let checks = collect_checks(state, &rules);
    let Ok(conn) = state.pool.get() else { return };
    let have_channels = db::list_alert_channels(&conn)
        .map(|c| c.iter().any(|x| x.enabled))
        .unwrap_or(false);
    let now = Utc::now();
    for c in checks {
        let Ok((was, since, last_sent)) = db::get_alert_state(&conn, &c.key) else {
            continue;
        };
        match (was, c.firing) {
            (false, true) => {
                if have_channels {
                    broadcast(&state.config, &state.pool, &c.title, &c.detail, "critical");
                }
                let _ = db::set_alert_state(&conn, &c.key, true, Some(now), Some(now));
            }
            (true, true) => {
                if have_channels && last_sent.map_or(true, |t| now - t > ChronoDuration::hours(REMIND_AFTER_HOURS)) {
                    broadcast(
                        &state.config,
                        &state.pool,
                        &format!("Still: {}", c.title),
                        &c.detail,
                        "critical",
                    );
                    let _ = db::set_alert_state(&conn, &c.key, true, since, Some(now));
                }
            }
            (true, false) => {
                if have_channels {
                    broadcast(
                        &state.config,
                        &state.pool,
                        &format!("Resolved: {}", c.key),
                        "The condition has cleared.",
                        "info",
                    );
                }
                let _ = db::set_alert_state(&conn, &c.key, false, None, None);
            }
            (false, false) => {}
        }
    }
}

/// Currently firing alerts (for the UI).
pub fn firing(conn: &rusqlite::Connection) -> Vec<serde_json::Value> {
    let mut stmt = match conn.prepare("SELECT key, since FROM alert_state WHERE firing = 1 ORDER BY since") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([], |r| {
        Ok(serde_json::json!({ "key": r.get::<_, String>(0)?, "since": r.get::<_, Option<chrono::DateTime<Utc>>>(1)? }))
    })
    .map(|rows| rows.flatten().collect())
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_channels_and_rules() {
        assert!(ChannelConfig::Webhook {
            url: "https://hooks.example.com/x".into()
        }
        .validate()
        .is_ok());
        assert!(ChannelConfig::Slack {
            url: "file:///etc/passwd".into()
        }
        .validate()
        .is_err());
        let email = ChannelConfig::Email {
            host: "smtp.example.com".into(),
            port: 587,
            security: "starttls".into(),
            username: String::new(),
            password: String::new(),
            from: "panel@example.com".into(),
            to: "ops@example.com, me@example.com".into(),
        };
        assert!(email.validate().is_ok());
        assert_eq!(email.kind(), "email");
        let mut r = AlertRules::default();
        assert!(r.validate().is_ok());
        r.disk_pct = 150.0;
        assert!(r.validate().is_err());
    }

    #[test]
    fn rules_saved_before_a_new_rule_existed_keep_their_values() {
        let r: AlertRules = serde_json::from_str(
            r#"{"disk_pct":70,"memory_pct":80,"cpu_pct":85,"sustain_minutes":3,"cert_days":7,"services":false,"backups":false,"security":false}"#,
        )
        .unwrap();
        assert_eq!(r.disk_pct, 70.0);
        assert!(!r.security);
        assert!(r.panel_updates);
    }

    #[test]
    fn sustained_detection() {
        let h: Mutex<VecDeque<f32>> = Mutex::new(VecDeque::new());
        for v in [95.0, 96.0, 97.0] {
            push(&h, v, 3);
        }
        assert!(sustained_above(&h, 90.0));
        push(&h, 50.0, 3);
        assert!(!sustained_above(&h, 90.0));
    }
}
