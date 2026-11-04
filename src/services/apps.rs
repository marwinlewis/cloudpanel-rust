//! Process manager for Node.js / Python / generic apps: one systemd unit per site,
//! running as the site user with automatic restarts.

use super::cmd::{run_with, CmdOpts};
use crate::config::Config;
use crate::db::models::{Site, SiteType};
use crate::fsutil::write_atomic;
use crate::jobs::JobLog;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use tracing::info;

/// `cloudpanel-app-<slug>` where slug is the domain with dots replaced.
pub fn unit_name(domain: &str) -> String {
    format!("cloudpanel-app-{}", domain.replace('.', "-"))
}

fn unit_path(config: &Config, domain: &str) -> PathBuf {
    config.systemd_dir.join(format!("{}.service", unit_name(domain)))
}

fn env_path(config: &Config, domain: &str) -> PathBuf {
    config.etc_dir.join("apps").join(format!("{}.env", unit_name(domain)))
}

/// Working directory for the app: explicit setting, else the site's htdocs.
pub fn workdir(site: &Site) -> String {
    if let Some(w) = site.app_workdir.as_deref().filter(|s| !s.is_empty()) {
        return w.to_string();
    }
    match &site.home_dir {
        Some(h) => format!("{h}/htdocs/{}", site.domain),
        None => site.document_root.clone().unwrap_or_else(|| "/var/www".into()),
    }
}

/// Quote a value for a systemd EnvironmentFile (double quotes, escaped).
fn env_quote(v: &str) -> String {
    format!(
        "\"{}\"",
        v.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$")
    )
}

pub fn render_env(site: &Site) -> String {
    let mut out = String::from("# Managed by CloudPanel\n");
    if let Some(p) = site.target_port {
        out.push_str(&format!("PORT={p}\n"));
    }
    out.push_str("HOST=127.0.0.1\n");
    for (k, v) in site.env_map() {
        out.push_str(&format!("{k}={}\n", env_quote(&v)));
    }
    out
}

/// Render the unit. Values were validated: domain (`validate::domain`), user
/// (`validate::system_user`), command (single line) and workdir (`path_within`).
pub fn render_unit(site: &Site, env_file: &str) -> String {
    let cmd = site.app_command.as_deref().unwrap_or("");
    let wd = workdir(site);
    let home = site.home_dir.clone().unwrap_or_else(|| wd.clone());
    let lang_env = match site.kind() {
        Some(SiteType::Nodejs) => "Environment=NODE_ENV=production\n",
        Some(SiteType::Python) => "Environment=PYTHONUNBUFFERED=1\n",
        _ => "",
    };
    // systemd expands '%' specifiers and '$VAR' itself; escape both so the shell sees
    // the command verbatim (and expands $PORT etc. from the environment file).
    let exec = cmd
        .replace('%', "%%")
        .replace('$', "$$")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!(
        "# Managed by CloudPanel - changes will be overwritten\n\
         [Unit]\n\
         Description=CloudPanel app for {domain}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=10\n\n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         WorkingDirectory={wd}\n\
         Environment=HOME={home}\n\
         Environment=PATH={home}/.local/bin:{wd}/node_modules/.bin:{wd}/.venv/bin:/usr/local/bin:/usr/bin:/bin\n\
         {lang_env}\
         EnvironmentFile=-{env_file}\n\
         ExecStart=/bin/sh -c \"{exec}\"\n\
         Restart=always\n\
         RestartSec=3\n\
         KillMode=mixed\n\
         TimeoutStopSec=20\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=tmpfs\n\
         BindPaths={home}\n\
         ReadWritePaths={home}\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         LockPersonality=yes\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        domain = site.domain,
        user = site.system_user,
    )
}

fn systemctl(args: &[&str]) -> Result<String, String> {
    let r = run_with("systemctl", args, &CmdOpts::default().timeout(60));
    if r.missing {
        return Ok(String::new()); // development
    }
    r.into_result("systemctl", "")
}

/// Write the unit + env file and (re)start or stop it according to `app_enabled`.
pub fn apply(config: &Config, site: &Site) -> Result<(), String> {
    let unit = unit_name(&site.domain);
    let env_file = env_path(config, &site.domain);
    if let Some(dir) = env_file.parent() {
        crate::fsutil::create_private_dir(dir, 0o700).map_err(|e| e.to_string())?;
    }
    write_atomic(&env_file, render_env(site).as_bytes(), 0o600).map_err(|e| format!("write env file: {e}"))?;

    let has_command = site.app_command.as_deref().is_some_and(|c| !c.trim().is_empty());
    if !has_command {
        stop_and_disable(&unit);
        return Ok(());
    }
    let path = unit_path(config, &site.domain);
    write_atomic(&path, render_unit(site, &env_file.to_string_lossy()).as_bytes(), 0o644)
        .map_err(|e| format!("write unit: {e}"))?;
    systemctl(&["daemon-reload"])?;
    if site.app_enabled && site.is_active {
        systemctl(&["enable", &unit])?;
        systemctl(&["restart", &unit])?;
        info!("started {unit}");
    } else {
        stop_and_disable(&unit);
    }
    Ok(())
}

fn stop_and_disable(unit: &str) {
    let _ = systemctl(&["disable", "--now", unit]);
}

/// Stop the app and delete its unit and env file.
pub fn remove(config: &Config, domain: &str) {
    let unit = unit_name(domain);
    stop_and_disable(&unit);
    let _ = fs::remove_file(unit_path(config, domain));
    let _ = fs::remove_file(env_path(config, domain));
    let _ = systemctl(&["daemon-reload"]);
}

#[derive(Clone, Copy)]
pub enum AppAction {
    Start,
    Stop,
    Restart,
}

pub fn act(domain: &str, action: AppAction) -> Result<(), String> {
    let unit = unit_name(domain);
    let verb = match action {
        AppAction::Start => "start",
        AppAction::Stop => "stop",
        AppAction::Restart => "restart",
    };
    systemctl(&[verb, &unit]).map(|_| ())
}

#[derive(Serialize, Default)]
pub struct AppStatus {
    pub unit: String,
    pub installed: bool,
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub since: Option<String>,
    pub restarts: Option<u32>,
}

/// Parse `systemctl show` key=value output.
pub fn parse_show(out: &str) -> std::collections::HashMap<String, String> {
    out.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn status(config: &Config, domain: &str) -> AppStatus {
    let unit = unit_name(domain);
    let installed = unit_path(config, domain).exists();
    let mut st = AppStatus {
        unit: unit.clone(),
        installed,
        active_state: if installed {
            "unknown".into()
        } else {
            "not-installed".into()
        },
        ..Default::default()
    };
    if !installed {
        return st;
    }
    let r = run_with(
        "systemctl",
        &[
            "show",
            &unit,
            "--property=ActiveState,SubState,MainPID,MemoryCurrent,ActiveEnterTimestamp,NRestarts",
        ],
        &CmdOpts::default().timeout(10),
    );
    if r.success() {
        let m = parse_show(&r.stdout);
        st.active_state = m.get("ActiveState").cloned().unwrap_or_default();
        st.sub_state = m.get("SubState").cloned().unwrap_or_default();
        st.main_pid = m.get("MainPID").and_then(|v| v.parse().ok()).filter(|p| *p > 0);
        st.memory_bytes = m.get("MemoryCurrent").and_then(|v| v.parse().ok());
        st.since = m.get("ActiveEnterTimestamp").cloned().filter(|s| !s.is_empty());
        st.restarts = m.get("NRestarts").and_then(|v| v.parse().ok());
    }
    st
}

/// Recent journal lines for a unit (unit name must be validated by the caller).
pub fn journal(unit: &str, lines: usize) -> Result<String, String> {
    let n = lines.to_string();
    let r = run_with(
        "journalctl",
        &["-u", unit, "-n", &n, "--no-pager", "-o", "short-iso"],
        &CmdOpts::default().timeout(20),
    );
    if r.missing {
        return Ok("journalctl is not available on this system.".into());
    }
    r.into_result("journalctl", "")
}

/// Install dependencies as the site user (`npm ci`/`npm install` or a Python venv + pip).
pub fn install_dependencies(site: &Site, log: &JobLog) -> Result<(), String> {
    let wd = PathBuf::from(workdir(site));
    let user = site.system_user.clone();
    let mut steps: Vec<(String, Vec<String>)> = Vec::new();
    match site.kind() {
        Some(SiteType::Nodejs) => {
            if !wd.join("package.json").exists() {
                return Err(format!("No package.json in {}", wd.display()));
            }
            let sub = if wd.join("package-lock.json").exists() {
                "ci"
            } else {
                "install"
            };
            steps.push(("npm".into(), vec![sub.into(), "--no-audit".into(), "--no-fund".into()]));
            if fs::read_to_string(wd.join("package.json")).is_ok_and(|p| p.contains("\"build\"")) {
                steps.push(("npm".into(), vec!["run".into(), "build".into()]));
            }
        }
        Some(SiteType::Python) => {
            if !wd.join("requirements.txt").exists() {
                return Err(format!("No requirements.txt in {}", wd.display()));
            }
            if !wd.join(".venv").exists() {
                steps.push(("python3".into(), vec!["-m".into(), "venv".into(), ".venv".into()]));
            }
            steps.push((
                ".venv/bin/pip".into(),
                vec!["install".into(), "-r".into(), "requirements.txt".into()],
            ));
        }
        _ => return Err("Dependencies can only be installed for Node.js and Python sites".into()),
    }
    let home = site
        .home_dir
        .clone()
        .unwrap_or_else(|| wd.to_string_lossy().into_owned());
    for (prog, args) in steps {
        let prog = if prog.starts_with('.') {
            wd.join(&prog).to_string_lossy().into_owned()
        } else {
            prog
        };
        log.line(&format!("$ {prog} {}", args.join(" ")));
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let opts = CmdOpts::default()
            .user(&user)
            .cwd(&wd)
            .env("HOME", &home)
            .timeout(20 * 60);
        let opts = if cfg!(windows) {
            CmdOpts { as_user: None, ..opts }
        } else {
            opts
        };
        let r = super::cmd::run_streaming(&prog, &argv, &opts, &mut |l, _| log.line(l));
        if r.missing {
            return Err(format!("{prog} is not installed"));
        }
        if !r.success() {
            return Err(format!("{prog} exited with code {}", r.code.unwrap_or(-1)));
        }
    }
    log.line("Dependencies installed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn site() -> Site {
        Site {
            id: 1,
            domain: "shop.example.com".into(),
            site_type: "nodejs".into(),
            target_port: Some(3000),
            document_root: None,
            system_user: "shop-example".into(),
            include_www: false,
            ssl_enabled: false,
            ssl_auto_renew: true,
            ssl_cert_path: None,
            ssl_key_path: None,
            is_active: true,
            app_command: Some("npm start -- --port=$PORT --x=%d".into()),
            app_workdir: None,
            app_env: r#"{"API_KEY":"a\"b$c"}"#.into(),
            app_enabled: true,
            home_dir: Some("/home/shop-example".into()),
            websocket: true,
            max_body_mb: 128,
            custom_directives: String::new(),
            basic_auth_enabled: false,
            basic_auth_allow: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn unit_and_env() {
        let s = site();
        assert_eq!(unit_name(&s.domain), "cloudpanel-app-shop-example-com");
        let u = render_unit(&s, "/etc/cloudpanel/apps/x.env");
        assert!(u.contains("User=shop-example\n"));
        assert!(u.contains("WorkingDirectory=/home/shop-example/htdocs/shop.example.com\n"));
        assert!(u.contains("ExecStart=/bin/sh -c \"npm start -- --port=$$PORT --x=%%d\"\n"));
        assert!(u.contains("Restart=always"));
        let e = render_env(&s);
        assert!(e.contains("PORT=3000\n"));
        assert!(e.contains("API_KEY=\"a\\\"b\\$c\"\n"));
    }

    #[test]
    fn parses_systemctl_show() {
        let m = parse_show("ActiveState=active\nSubState=running\nMainPID=42\n");
        assert_eq!(m["MainPID"], "42");
    }
}
