//! Host services (systemd units) and package updates.

use super::apps::parse_show;
use super::cmd::{run_host, run_streaming, run_with, CmdOpts};
use crate::jobs::JobLog;
use serde::{Deserialize, Serialize};

/// Units shown on the Services page (only those that exist are listed).
pub const MANAGED: &[(&str, &str)] = &[
    ("nginx", "Web server"),
    ("ssh", "SSH server"),
    ("cron", "Task scheduler"),
    ("fail2ban", "Intrusion prevention"),
    ("docker", "Container engine"),
    ("mariadb", "MariaDB database"),
    ("mysql", "MySQL database"),
    ("mongod", "MongoDB database"),
    ("ufw", "Firewall"),
];

#[derive(Serialize, Clone)]
pub struct ServiceStatus {
    pub name: String,
    pub description: String,
    pub active_state: String,
    pub sub_state: String,
    pub enabled: String,
    pub main_pid: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub since: Option<String>,
}

pub fn status(name: &str, description: &str) -> Option<ServiceStatus> {
    let r = run_with(
        "systemctl",
        &[
            "show",
            name,
            "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,MemoryCurrent,ActiveEnterTimestamp",
        ],
        &CmdOpts::default().timeout(10),
    );
    if !r.success() {
        return None;
    }
    let m = parse_show(&r.stdout);
    if m.get("LoadState").map(String::as_str) != Some("loaded") {
        return None;
    }
    Some(ServiceStatus {
        name: name.to_string(),
        description: description.to_string(),
        active_state: m.get("ActiveState").cloned().unwrap_or_default(),
        sub_state: m.get("SubState").cloned().unwrap_or_default(),
        enabled: m.get("UnitFileState").cloned().unwrap_or_default(),
        main_pid: m.get("MainPID").and_then(|v| v.parse().ok()).filter(|p| *p > 0),
        memory_bytes: m.get("MemoryCurrent").and_then(|v| v.parse().ok()),
        since: m.get("ActiveEnterTimestamp").cloned().filter(|s| !s.is_empty()),
    })
}

pub fn list(app_units: &[(String, String)]) -> Vec<ServiceStatus> {
    let mut out: Vec<ServiceStatus> = MANAGED.iter().filter_map(|(n, d)| status(n, d)).collect();
    // On Debian `ssh` is the unit; some systems only have `sshd`.
    if !out.iter().any(|s| s.name == "ssh") {
        if let Some(s) = status("sshd", "SSH server") {
            out.push(s);
        }
    }
    for (unit, domain) in app_units {
        if let Some(s) = status(unit, &format!("App · {domain}")) {
            out.push(s);
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
    Reload,
}

impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "start" => Some(Action::Start),
            "stop" => Some(Action::Stop),
            "restart" => Some(Action::Restart),
            "reload" => Some(Action::Reload),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Restart => "restart",
            Action::Reload => "reload",
        }
    }
}

/// `name` must be validated with `validate::service_name`.
pub fn act(name: &str, action: Action) -> Result<(), String> {
    if action == Action::Stop && matches!(name, "ssh" | "sshd") {
        return Err("Stopping SSH from the panel is refused; you could lose access to the server".into());
    }
    let r = run_with("systemctl", &[action.as_str(), name], &CmdOpts::default().timeout(90));
    if r.missing {
        return Err("systemctl is not available on this system".into());
    }
    r.into_result("systemctl", "").map(|_| ())
}

// ---------- Updates ----------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Upgradable {
    pub name: String,
    pub version: String,
    pub current: String,
    pub security: bool,
}

/// Parse `apt list --upgradable` output.
pub fn parse_upgradable(out: &str) -> Vec<Upgradable> {
    out.lines()
        .filter(|l| l.contains("[upgradable from:"))
        .filter_map(|l| {
            let (name_suite, rest) = l.split_once(' ')?;
            let (name, suite) = name_suite.split_once('/')?;
            let version = rest.split_whitespace().next()?.to_string();
            let current = l
                .split("[upgradable from:")
                .nth(1)?
                .trim()
                .trim_end_matches(']')
                .trim()
                .to_string();
            Some(Upgradable {
                name: name.to_string(),
                version,
                current,
                security: suite.contains("-security"),
            })
        })
        .collect()
}

pub fn list_upgradable() -> Result<Vec<Upgradable>, String> {
    let r = run_with("apt", &["list", "--upgradable"], &CmdOpts::default().timeout(120));
    if r.missing {
        return Ok(vec![]);
    }
    let out = r.into_result("apt", "")?;
    Ok(parse_upgradable(&out))
}

fn apt_job(args: &[&str], log: &JobLog) -> Result<(), String> {
    log.line(&format!("$ apt-get {}", args.join(" ")));
    let opts = CmdOpts::default()
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("NEEDRESTART_MODE", "a")
        .timeout(2 * 3600);
    // apt must run outside the panel's sandbox (it writes /usr and /etc).
    let mut full: Vec<&str> = vec![];
    full.extend_from_slice(args);
    let mut downgrade_refused = false;
    let mut on_line = |l: &str, _: bool| {
        downgrade_refused |= l.contains("Packages were downgraded");
        log.line(l);
    };
    let r = if cfg!(unix) && super::cmd::which("systemd-run") {
        let mut sr: Vec<String> = vec![
            "--wait".into(),
            "--pipe".into(),
            "--collect".into(),
            "--quiet".into(),
            "--setenv=DEBIAN_FRONTEND=noninteractive".into(),
            "--setenv=NEEDRESTART_MODE=a".into(),
            "--".into(),
            "apt-get".into(),
        ];
        sr.extend(full.iter().map(|s| s.to_string()));
        let argv: Vec<&str> = sr.iter().map(String::as_str).collect();
        run_streaming(
            "systemd-run",
            &argv,
            &CmdOpts::default().timeout(2 * 3600),
            &mut on_line,
        )
    } else {
        run_streaming("apt-get", &full, &opts, &mut on_line)
    };
    if r.missing {
        return Err("apt-get is not available on this system".into());
    }
    if !r.success() {
        return Err(apt_failure(r.code.unwrap_or(-1), downgrade_refused));
    }
    Ok(())
}

/// Why apt failed. A refused downgrade needs explaining: nothing was upgraded, and the panel won't
/// allow it, because a downgrade could undo a security update.
fn apt_failure(code: i32, downgrade_refused: bool) -> String {
    if downgrade_refused {
        return "Nothing was upgraded: apt wants to replace the packages listed under DOWNGRADED with copies from \
                another repository, and the panel doesn't allow downgrades. On a server migrated from CloudPanel \
                CE, fix this by running: sudo bash migrate-from-ce.sh fix-apt"
            .to_string();
    }
    format!("apt-get exited with code {code}")
}

pub fn refresh_updates(log: &JobLog) -> Result<Vec<Upgradable>, String> {
    apt_job(&["update", "-q"], log)?;
    let list = list_upgradable()?;
    log.line(&format!(
        "{} package(s) can be upgraded ({} security)",
        list.len(),
        list.iter().filter(|u| u.security).count()
    ));
    Ok(list)
}

pub fn upgrade_all(log: &JobLog) -> Result<(), String> {
    apt_job(&["update", "-q"], log)?;
    apt_job(
        &[
            "-y",
            "-q",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
            "upgrade",
        ],
        log,
    )
}

pub fn reboot_required() -> bool {
    std::path::Path::new("/var/run/reboot-required").exists()
}

pub fn reboot() -> Result<(), String> {
    let r = run_host("systemctl", &["reboot"], &CmdOpts::default().timeout(30));
    if r.missing {
        return Err("systemctl is not available on this system".into());
    }
    r.into_result("systemctl", "").map(|_| ())
}

/// Global unicast addresses of this host (no external lookups).
pub fn public_ips() -> (Option<String>, Option<String>) {
    let r = run_with("ip", &["-j", "addr"], &CmdOpts::default().timeout(5));
    if !r.success() {
        return (None, None);
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&r.stdout) else {
        return (None, None);
    };
    let (mut v4, mut v6) = (None, None);
    for iface in v.as_array().into_iter().flatten() {
        for a in iface["addr_info"].as_array().into_iter().flatten() {
            if a["scope"] != "global" {
                continue;
            }
            let Some(ip) = a["local"].as_str().and_then(|s| s.parse::<std::net::IpAddr>().ok()) else {
                continue;
            };
            match ip {
                std::net::IpAddr::V4(x) if v4.is_none() && !x.is_private() && !x.is_loopback() => {
                    v4 = Some(x.to_string())
                }
                std::net::IpAddr::V6(x) if v6.is_none() && (x.segments()[0] & 0xe000) == 0x2000 => {
                    v6 = Some(x.to_string())
                }
                _ => {}
            }
        }
    }
    // Fall back to the first private IPv4 (VPS behind NAT).
    if v4.is_none() {
        for iface in v.as_array().into_iter().flatten() {
            for a in iface["addr_info"].as_array().into_iter().flatten() {
                if a["scope"] == "global" && a["family"] == "inet" {
                    if let Some(s) = a["local"].as_str() {
                        return (Some(s.to_string()), v6);
                    }
                }
            }
        }
    }
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_downgrade_is_explained() {
        assert_eq!(apt_failure(100, false), "apt-get exited with code 100");
        let e = apt_failure(100, true);
        assert!(e.contains("Nothing was upgraded"));
        assert!(e.contains("fix-apt"));
    }

    #[test]
    fn parses_apt_list() {
        let out = "Listing... Done\n\
            openssl/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]\n\
            nginx/jammy-updates 1.18.0-6ubuntu14.5 all [upgradable from: 1.18.0-6ubuntu14.4]\n";
        let l = parse_upgradable(out);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].name, "openssl");
        assert!(l[0].security);
        assert_eq!(l[1].current, "1.18.0-6ubuntu14.4");
        assert!(!l[1].security);
    }
}
