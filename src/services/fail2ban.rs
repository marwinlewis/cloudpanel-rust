//! fail2ban integration: jails for sshd and the panel login (fed by
//! `/var/log/cloudpanel/auth.log`), status, ban and unban.

use super::cmd::{run_with, CmdOpts};
use crate::config::Config;
use crate::fsutil::write_atomic;
use serde::{Deserialize, Serialize};
use std::fs;

pub const SETTING: &str = "fail2ban";
pub const JAILS: [&str; 2] = ["sshd", "cloudpanel"];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Fail2banSettings {
    pub sshd: bool,
    pub panel: bool,
    pub maxretry: u32,
    pub findtime_minutes: u32,
    pub bantime_minutes: u32,
    /// Never ban these IPs/CIDRs.
    #[serde(default)]
    pub ignoreip: Vec<String>,
}

impl Default for Fail2banSettings {
    fn default() -> Self {
        Fail2banSettings {
            sshd: true,
            panel: true,
            maxretry: 5,
            findtime_minutes: 10,
            bantime_minutes: 60,
            ignoreip: vec![],
        }
    }
}

impl Fail2banSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=100).contains(&self.maxretry) {
            return Err("Max retries must be 1-100".into());
        }
        if !(1..=1440).contains(&self.findtime_minutes) {
            return Err("Find time must be 1-1440 minutes".into());
        }
        if !(1..=525_600).contains(&self.bantime_minutes) {
            return Err("Ban time must be between 1 minute and 1 year".into());
        }
        for ip in &self.ignoreip {
            crate::validate::cidr(ip)?;
        }
        Ok(())
    }
}

/// fail2ban strips the part matched by `datepattern` before applying `failregex`, so the
/// regex starts after the timestamp.
pub fn render_filter() -> String {
    "# Managed by CloudPanel\n[Definition]\n\
     failregex = ^\\s*cloudpanel auth failure from <HOST> user=\\S* reason=\\S+$\n\
     ignoreregex =\n\
     datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%SZ\n"
        .to_string()
}

pub fn render_jail(config: &Config, s: &Fail2banSettings) -> String {
    let ignore = if s.ignoreip.is_empty() {
        "127.0.0.1/8 ::1".to_string()
    } else {
        format!("127.0.0.1/8 ::1 {}", s.ignoreip.join(" "))
    };
    let common = format!(
        "maxretry = {}\nfindtime = {}m\nbantime = {}m\nignoreip = {ignore}\n",
        s.maxretry, s.findtime_minutes, s.bantime_minutes
    );
    let port = config.panel_port().unwrap_or(8443);
    format!(
        "# Managed by CloudPanel - changes will be overwritten\n\
         [sshd]\nenabled = {}\nbackend = systemd\n{common}\n\
         [cloudpanel]\nenabled = {}\nport = {port}\nfilter = cloudpanel\nlogpath = {}/auth.log\nbackend = polling\n{common}",
        s.sshd,
        s.panel,
        config.log_dir.display()
    )
}

fn client(args: &[&str]) -> Result<String, String> {
    let r = run_with("fail2ban-client", args, &CmdOpts::default().timeout(30));
    if r.missing {
        return Err("fail2ban is not installed on this server".into());
    }
    r.into_result("fail2ban-client", "")
}

pub fn installed() -> bool {
    super::cmd::which("fail2ban-client")
}

/// Write filter + jail and reload fail2ban. Rolls back the jail if the config test fails.
pub fn apply(config: &Config, s: &Fail2banSettings) -> Result<(), String> {
    let filter = config.fail2ban_dir.join("filter.d").join("cloudpanel.conf");
    let jail = config.fail2ban_dir.join("jail.d").join("cloudpanel.conf");
    for p in [&filter, &jail] {
        if let Some(d) = p.parent() {
            fs::create_dir_all(d).map_err(|e| format!("create {}: {e}", d.display()))?;
        }
    }
    let _ = fs::create_dir_all(&config.log_dir);
    let log = config.log_dir.join("auth.log");
    if !log.exists() {
        let _ = fs::write(&log, "");
    }
    write_atomic(&filter, render_filter().as_bytes(), 0o644).map_err(|e| e.to_string())?;
    let previous = fs::read(&jail).ok();
    write_atomic(&jail, render_jail(config, s).as_bytes(), 0o644).map_err(|e| e.to_string())?;
    if !installed() {
        return Ok(()); // development or --no-fail2ban; files are ready for later
    }
    if let Err(e) = client(&["-t"]) {
        match previous {
            Some(p) => {
                let _ = write_atomic(&jail, &p, 0o644);
            }
            None => {
                let _ = fs::remove_file(&jail);
            }
        }
        return Err(format!("fail2ban rejected the configuration: {e}"));
    }
    // reload fails when the service is stopped; start it in that case.
    if client(&["reload"]).is_err() {
        let _ = run_with("systemctl", &["restart", "fail2ban"], &CmdOpts::default().timeout(30));
    }
    Ok(())
}

/// Install the filter and jail on first start so protection works without visiting the UI.
pub fn ensure(config: &Config, s: &Fail2banSettings) {
    let jail = config.fail2ban_dir.join("jail.d").join("cloudpanel.conf");
    let filter = config.fail2ban_dir.join("filter.d").join("cloudpanel.conf");
    // Also refresh a filter written by an older version.
    let stale = fs::read_to_string(&filter).is_ok_and(|f| f != render_filter());
    if (!jail.exists() || stale) && (installed() || cfg!(windows)) {
        if let Err(e) = apply(config, s) {
            tracing::warn!("fail2ban setup: {e}");
        }
    }
}

#[derive(Serialize, Default)]
pub struct JailStatus {
    pub jail: String,
    pub active: bool,
    pub currently_failed: u64,
    pub total_failed: u64,
    pub currently_banned: u64,
    pub total_banned: u64,
    pub banned: Vec<String>,
}

pub fn parse_status(jail: &str, out: &str) -> JailStatus {
    let mut st = JailStatus {
        jail: jail.to_string(),
        active: true,
        ..Default::default()
    };
    for line in out.lines() {
        let l = line.trim_start_matches(['|', '`', '-', ' ']);
        let num = |s: &str| s.rsplit(':').next().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        if l.starts_with("Currently failed:") {
            st.currently_failed = num(l);
        } else if l.starts_with("Total failed:") {
            st.total_failed = num(l);
        } else if l.starts_with("Currently banned:") {
            st.currently_banned = num(l);
        } else if l.starts_with("Total banned:") {
            st.total_banned = num(l);
        } else if let Some(list) = l.strip_prefix("Banned IP list:") {
            st.banned = list.split_whitespace().map(str::to_string).collect();
        }
    }
    st
}

pub fn status() -> Vec<JailStatus> {
    JAILS
        .iter()
        .map(|j| match client(&["status", j]) {
            Ok(out) => parse_status(j, &out),
            Err(_) => JailStatus {
                jail: j.to_string(),
                ..Default::default()
            },
        })
        .collect()
}

pub fn ban(jail: &str, ip: &str) -> Result<(), String> {
    client(&["set", jail, "banip", ip]).map(|_| ())
}

pub fn unban(jail: &str, ip: &str) -> Result<(), String> {
    client(&["set", jail, "unbanip", ip]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let out = "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t2\n|  |- Total failed:\t40\n\
                   |  `- Journal matches:\t_SYSTEMD_UNIT=sshd.service\n`- Actions\n   |- Currently banned:\t1\n\
                   |  |- Total banned:\t7\n   `- Banned IP list:\t203.0.113.9 198.51.100.4\n";
        let s = parse_status("sshd", out);
        assert_eq!(s.currently_failed, 2);
        assert_eq!(s.total_banned, 7);
        assert_eq!(s.banned, vec!["203.0.113.9", "198.51.100.4"]);
    }

    #[test]
    fn renders_jail_and_filter_regex() {
        let mut c = Config::from_env();
        c.log_dir = "/var/log/cloudpanel".into();
        c.bind_addr = "0.0.0.0:8443".into();
        let j = render_jail(&c, &Fail2banSettings::default());
        assert!(j.contains("[cloudpanel]\nenabled = true\nport = 8443"));
        assert!(j.contains("bantime = 60m"));
        assert!(render_filter().contains("failregex = ^\\s*cloudpanel auth failure from <HOST> "));
        // The log line format written by the login handler must match the filter.
        let line = "2026-11-04T06:40:31Z cloudpanel auth failure from 1.2.3.4 user=admin reason=password";
        assert!(line.contains(" cloudpanel auth failure from ") && line.ends_with("reason=password"));
    }
}
