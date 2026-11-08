//! fail2ban integration: jails for sshd and the panel login (fed by
//! `/var/log/cloudpanel/auth.log`), status, ban and unban.
//!
//! The panel enforces bans from its login jail itself, not the firewall. Behind Cloudflare the
//! firewall only sees Cloudflare's addresses, so a rule for the visitor would do nothing and a
//! rule for an edge would cut off everyone using it. Without Cloudflare, closing 443 as well as
//! the panel's port would take every hosted site away from that client. So fail2ban keeps
//! deciding who is banned and for how long, and its action only keeps one file per banned address
//! in [`Config::ban_dir`], which the panel checks once it knows who the client really is. That
//! covers both ports. See `api::real_client_address`.

use super::cmd::{run_with, CmdOpts};
use crate::config::Config;
use crate::fsutil::write_atomic;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;

pub const SETTING: &str = "fail2ban";
pub const PANEL_JAIL: &str = "cloudpanel";
pub const JAILS: [&str; 2] = ["sshd", PANEL_JAIL];

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

/// fail2ban runs `actionstart` before it restores saved bans, so emptying the directory there
/// clears only bans that ended while it wasn't running.
pub fn render_action(config: &Config) -> String {
    let dir = config.ban_dir.display();
    format!(
        "# Managed by CloudPanel\n[Definition]\n\
         actionstart = mkdir -p -m 700 \"{dir}\" && find \"{dir}\" -mindepth 1 -delete\n\
         actionstop = find \"{dir}\" -mindepth 1 -delete\n\
         actioncheck =\n\
         actionban = touch \"{dir}/<ip>\"\n\
         actionunban = rm -f \"{dir}/<ip>\"\n"
    )
}

/// Has fail2ban banned this address from the panel? One `stat`, on every request, so that a ban
/// or an unban counts straight away.
pub fn is_banned(config: &Config, ip: IpAddr) -> bool {
    config.ban_dir.join(ip.to_canonical().to_string()).exists()
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
    format!(
        "# Managed by CloudPanel - changes will be overwritten\n\
         [sshd]\nenabled = {}\nbackend = systemd\n{common}\n\
         [{PANEL_JAIL}]\nenabled = {}\naction = cloudpanel\nfilter = cloudpanel\nlogpath = {}/auth.log\nlogtimezone = UTC\nbackend = polling\n{common}",
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

fn filter_path(config: &Config) -> std::path::PathBuf {
    config.fail2ban_dir.join("filter.d").join("cloudpanel.conf")
}

fn action_path(config: &Config) -> std::path::PathBuf {
    config.fail2ban_dir.join("action.d").join("cloudpanel.conf")
}

fn jail_path(config: &Config) -> std::path::PathBuf {
    config.fail2ban_dir.join("jail.d").join("cloudpanel.conf")
}

/// Write filter, action and jail, and reload fail2ban. Rolls back the jail if the config test
/// fails.
pub fn apply(config: &Config, s: &Fail2banSettings) -> Result<(), String> {
    let filter = filter_path(config);
    let action = action_path(config);
    let jail = jail_path(config);
    for p in [&filter, &action, &jail] {
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
    write_atomic(&action, render_action(config).as_bytes(), 0o644).map_err(|e| e.to_string())?;
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

/// Is anything missing, or written by an older version? An old jail would keep using the firewall.
fn out_of_date(config: &Config, s: &Fail2banSettings) -> bool {
    [
        (filter_path(config), render_filter()),
        (action_path(config), render_action(config)),
        (jail_path(config), render_jail(config, s)),
    ]
    .iter()
    .any(|(path, wanted)| fs::read_to_string(path).map_or(true, |found| found != *wanted))
}

/// Install the filter, action and jail on start so protection works without visiting the UI.
pub fn ensure(config: &Config, s: &Fail2banSettings) {
    if out_of_date(config, s) && (installed() || cfg!(windows)) {
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
        assert!(j.contains("[cloudpanel]\nenabled = true\naction = cloudpanel\n"));
        // No firewall action and nothing for one to act on, for either port.
        assert!(!j.contains("port ="));
        assert!(!j.contains("banaction"));
        // The log's times are UTC. Read as local time, they look too old east of Greenwich, and
        // nobody would ever be banned.
        assert!(j.contains("logtimezone = UTC\n"));
        assert!(j.contains("bantime = 60m"));
        assert!(render_filter().contains("failregex = ^\\s*cloudpanel auth failure from <HOST> "));
        // The log line format written by the login handler must match the filter.
        let line = "2026-11-04T06:40:31Z cloudpanel auth failure from 1.2.3.4 user=admin reason=password";
        assert!(line.contains(" cloudpanel auth failure from ") && line.ends_with("reason=password"));
    }

    fn config_in(dir: &std::path::Path) -> Config {
        let mut c = Config::from_env();
        c.fail2ban_dir = dir.join("fail2ban");
        c.log_dir = dir.join("log");
        c.ban_dir = dir.join("bans");
        c
    }

    #[test]
    fn the_action_keeps_a_file_per_banned_address() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config_in(dir.path());
        c.ban_dir = "/run/cloudpanel-bans".into();
        let a = render_action(&c);
        assert!(a.contains("actionban = touch \"/run/cloudpanel-bans/<ip>\"\n"));
        assert!(a.contains("actionunban = rm -f \"/run/cloudpanel-bans/<ip>\"\n"));
        assert!(a.contains("actionstart = mkdir -p -m 700 \"/run/cloudpanel-bans\" && find "));
        assert!(!a.contains("iptables") && !a.contains("nft"));
    }

    #[test]
    fn a_ban_file_bans_that_address_however_it_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let c = config_in(dir.path());
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // With no directory at all, as on a server without fail2ban.
        assert!(!is_banned(&c, ip("203.0.113.9")));
        fs::create_dir_all(&c.ban_dir).unwrap();
        fs::write(c.ban_dir.join("203.0.113.9"), "").unwrap();
        assert!(is_banned(&c, ip("203.0.113.9")));
        assert!(is_banned(&c, ip("::ffff:203.0.113.9")));
        assert!(!is_banned(&c, ip("203.0.113.90")));
        #[cfg(unix)]
        {
            fs::write(c.ban_dir.join("2001:db8::9"), "").unwrap();
            assert!(is_banned(&c, ip("2001:db8:0:0:0:0:0:9")));
            assert!(!is_banned(&c, ip("2001:db8::a")));
        }
    }

    #[test]
    fn a_jail_from_an_older_version_is_out_of_date() {
        let dir = tempfile::tempdir().unwrap();
        let c = config_in(dir.path());
        let s = Fail2banSettings::default();
        assert!(out_of_date(&c, &s));
        for (path, text) in [
            (filter_path(&c), render_filter()),
            (action_path(&c), render_action(&c)),
            (jail_path(&c), render_jail(&c, &s)),
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        assert!(!out_of_date(&c, &s));

        // The firewall jail older versions wrote, which is what upgrades start from.
        let new = render_jail(&c, &s);
        fs::write(jail_path(&c), new.replace("action = cloudpanel", "port = 8443")).unwrap();
        assert!(out_of_date(&c, &s));
        fs::write(jail_path(&c), new).unwrap();
        assert!(!out_of_date(&c, &s));

        fs::remove_file(action_path(&c)).unwrap();
        assert!(out_of_date(&c, &s));
    }
}
