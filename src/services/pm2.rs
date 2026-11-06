//! Run a Node.js site's app under PM2.
//!
//! Each site user has their own daemon in `~/.pm2`, so `pm2 ls` over SSH shows what the panel
//! shows. The daemon belongs to the site's `cloudpanel-app-<slug>` unit, which brings it back
//! at boot. Panel commands run in transient `systemd-run` units, and anything they spawn dies
//! when that unit exits, so the unit must be started first: every `pm2` call here only talks
//! to the running daemon over its socket. `pm2` starts a daemon itself when it finds none,
//! which is why nothing calls it without checking that the daemon is up.

use super::apps::{self, AppAction, AppStatus};
use super::cmd::{run_host, run_host_streaming, run_with, CmdOpts, CmdResult};
use super::runtimes;
use crate::config::Config;
use crate::db::models::{Pm2Options, Site};
use crate::fsutil::write_atomic;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tracing::warn;

/// PM2 major version installed by the panel. An existing install is never changed.
pub const PM2_MAJOR: u32 = 7;
const PM2_PATHS: &[&str] = &["/usr/bin/pm2", "/usr/local/bin/pm2"];
const CONFIG_REL: &str = ".cloudpanel/pm2.config.js";
const ECOSYSTEM_FILES: &[&str] = &["ecosystem.config.js", "ecosystem.config.cjs"];

static INSTALL_LOCK: Mutex<()> = Mutex::new(());

pub fn binary() -> Option<&'static str> {
    PM2_PATHS.iter().copied().find(|p| Path::new(p).is_file())
}

pub fn installed() -> bool {
    binary().is_some()
}

/// Install PM2 globally if missing. Runs outside the panel sandbox: `/usr` is read-only there.
pub fn ensure(config: &Config, log: &dyn Fn(&str)) -> Result<(), String> {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if installed() {
        return Ok(());
    }
    if !runtimes::can_install(config) {
        return Err("PM2 is not installed and this system has no apt-get; install PM2 manually".into());
    }
    log(&format!("PM2 is not installed; installing PM2 {PM2_MAJOR}..."));
    let script = format!(
        "set -eu\n\
         export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a\n\
         [ -x /usr/sbin/logrotate ] || apt-get install -y -q --no-install-recommends logrotate || true\n\
         npm install -g pm2@{PM2_MAJOR} --no-audit --no-fund\n"
    );
    let opts = CmdOpts::default()
        .env("HOME", "/root")
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .timeout(15 * 60);
    let r = run_host_streaming("/bin/sh", &["-c", &script], &opts, &mut |l, _| log(l));
    if !r.success() || !installed() {
        return Err(format!("PM2 installation failed (exit code {})", r.code.unwrap_or(-1)));
    }
    log("PM2 installed.");
    Ok(())
}

/// The ecosystem file in the workdir that this site should run, if any.
pub fn ecosystem_file(site: &Site) -> Option<String> {
    if !site.uses_pm2() || !site.pm2_options().use_ecosystem {
        return None;
    }
    detect_ecosystem(site)
}

/// The workdir's ecosystem file, whether or not this site is set to use it.
pub fn detect_ecosystem(site: &Site) -> Option<String> {
    let wd = apps::workdir(site);
    ECOSYSTEM_FILES
        .iter()
        .map(|f| Path::new(&wd).join(f))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

/// A single `.js`/`.cjs`/`.mjs` path: PM2 can run it directly, and in cluster mode.
pub fn is_script(command: &str) -> bool {
    let c = command.trim();
    !c.is_empty() && !c.chars().any(char::is_whitespace) && [".js", ".cjs", ".mjs"].iter().any(|ext| c.ends_with(ext))
}

fn cluster_requested(o: &Pm2Options) -> bool {
    let i = o.instances.trim();
    !(i.is_empty() || i == "1")
}

/// Check options before they are stored. `command` is the site's start command.
pub fn validate_options(o: &Pm2Options, command: Option<&str>, has_ecosystem: bool) -> Result<Pm2Options, String> {
    let instances = o.instances.trim();
    if !instances.is_empty() && instances != "max" && !instances.parse::<u32>().is_ok_and(|n| (1..=64).contains(&n)) {
        return Err("Instances must be a number from 1 to 64, or max".into());
    }
    let mem = o.max_memory.trim();
    if !mem.is_empty() {
        let digits = mem.strip_suffix(['K', 'M', 'G']).unwrap_or("");
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err("Max memory must look like 512M or 1G".into());
        }
    }
    let args = o.node_args.trim();
    if args.len() > 500 || args.chars().any(char::is_control) {
        return Err("Node arguments must be a single line of at most 500 characters".into());
    }
    let cron = o.cron_restart.trim();
    let fields = cron.split_whitespace().count();
    if !cron.is_empty()
        && (!(5..=6).contains(&fields)
            || !cron
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_whitespace() || matches!(c, '*' | '/' | ',' | '-')))
    {
        return Err("Cron restart must be a 5 or 6 field cron schedule".into());
    }
    let out = Pm2Options {
        use_ecosystem: o.use_ecosystem,
        instances: if instances.is_empty() {
            "1".into()
        } else {
            instances.into()
        },
        max_memory: mem.into(),
        node_args: args.into(),
        cron_restart: cron.split_whitespace().collect::<Vec<_>>().join(" "),
    };
    let via_ecosystem = has_ecosystem && out.use_ecosystem;
    if !via_ecosystem && cluster_requested(&out) && !command.is_some_and(is_script) {
        return Err("Cluster mode needs a JavaScript entry point such as server.js as the start command".into());
    }
    Ok(out)
}

fn home_of(site: &Site) -> Result<&str, String> {
    site.home_dir
        .as_deref()
        .ok_or_else(|| "This site has no Linux user".to_string())
}

/// Render the unit that owns the site's PM2 daemon, in the same shape `pm2 startup` generates.
pub fn render_unit(site: &Site, pm2: &str) -> String {
    let wd = apps::workdir(site);
    let home = site.home_dir.clone().unwrap_or_else(|| wd.clone());
    format!(
        "# Managed by CloudPanel - changes will be overwritten\n\
         [Unit]\n\
         Description=CloudPanel PM2 daemon for {domain}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=10\n\n\
         [Service]\n\
         Type=forking\n\
         User={user}\n\
         Group={user}\n\
         WorkingDirectory={home}\n\
         LimitNOFILE=65535\n\
         Environment=HOME={home}\n\
         Environment=PM2_HOME={home}/.pm2\n\
         Environment=PATH={path}\n\
         PIDFile={home}/.pm2/pm2.pid\n\
         ExecStart={pm2} resurrect\n\
         ExecReload={pm2} reload all\n\
         ExecStop={pm2} kill\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         TimeoutStartSec=90\n\
         TimeoutStopSec=30\n\
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
        path = apps::app_path(&home, &wd),
    )
}

/// Render the config handed to PM2. Values go in this 0600 file, never on a command line.
/// The site's app port always wins; an ecosystem file's other settings are left alone.
pub fn render_config(site: &Site, env: &BTreeMap<String, String>, ecosystem: Option<&str>) -> String {
    let wd = apps::workdir(site);
    let mut vars = serde_json::Map::new();
    for (k, v) in env {
        vars.insert(k.clone(), json!(v));
    }
    if let Some(p) = site.target_port {
        vars.insert("PORT".into(), json!(p.to_string()));
    }
    vars.entry("HOST").or_insert_with(|| json!("127.0.0.1"));
    let vars = Value::Object(vars);
    let date_format = "YYYY-MM-DD HH:mm:ss Z";
    match ecosystem {
        Some(file) => format!(
            "// Managed by CloudPanel - changes will be overwritten\n\
             const env = {vars};\n\
             const cwd = {cwd};\n\
             const loaded = require({file});\n\
             const apps = Array.isArray(loaded) ? loaded : (loaded.apps || []);\n\
             module.exports = {{\n  apps: apps.map((app) => ({{\n    log_date_format: {fmt},\n    ...app,\n    \
             cwd: app.cwd || cwd,\n    env: {{ NODE_ENV: 'production', ...(app.env || {{}}), ...env }},\n  }})),\n}};\n",
            cwd = json!(wd),
            file = json!(file),
            fmt = json!(date_format),
        ),
        None => {
            let o = site.pm2_options();
            let cmd = site.app_command.as_deref().unwrap_or("").trim();
            let mut app = json!({
                "name": site.domain,
                "cwd": wd,
                "autorestart": true,
                "exp_backoff_restart_delay": 100,
                "merge_logs": true,
                "log_date_format": date_format,
                "env": { "NODE_ENV": "production" },
            });
            if is_script(cmd) {
                app["script"] = json!(cmd);
                if cluster_requested(&o) {
                    app["exec_mode"] = json!("cluster");
                    app["instances"] = match o.instances.parse::<u32>() {
                        Ok(n) => json!(n),
                        Err(_) => json!(o.instances),
                    };
                }
                if !o.node_args.is_empty() {
                    app["node_args"] = json!(o.node_args);
                }
            } else {
                app["script"] = json!("/bin/sh");
                app["args"] = json!(["-c", cmd]);
                app["interpreter"] = json!("none");
            }
            if !o.max_memory.is_empty() {
                app["max_memory_restart"] = json!(o.max_memory);
            }
            if !o.cron_restart.is_empty() {
                app["cron_restart"] = json!(o.cron_restart);
            }
            if let (Some(obj), Value::Object(user)) = (app["env"].as_object_mut(), &vars) {
                for (k, v) in user {
                    obj.insert(k.clone(), v.clone());
                }
            }
            format!(
                "// Managed by CloudPanel - changes will be overwritten\nmodule.exports = {};\n",
                json!({ "apps": [app] })
            )
        }
    }
}

fn opts(site: &Site, timeout: u64) -> Result<CmdOpts, String> {
    let home = home_of(site)?;
    let wd = apps::workdir(site);
    let cwd = if Path::new(&wd).is_dir() {
        wd.clone()
    } else {
        home.to_string()
    };
    Ok(CmdOpts::default()
        .user(&site.system_user)
        .cwd(cwd)
        .env("HOME", home)
        .env("PM2_HOME", &format!("{home}/.pm2"))
        .env("PATH", &apps::app_path(home, &wd))
        .timeout(timeout))
}

/// Run `pm2` as the site user. Only call this while the daemon is up (see the module docs).
fn pm2(site: &Site, args: &[&str], timeout: u64) -> Result<CmdResult, String> {
    let bin = binary().ok_or("PM2 is not installed")?;
    Ok(run_with(bin, args, &opts(site, timeout)?))
}

fn pm2_ok(site: &Site, args: &[&str], timeout: u64) -> Result<String, String> {
    pm2(site, args, timeout)?.into_result("pm2", "PM2 is not installed")
}

/// Write the generated config as the site user, so root never writes into their directory.
fn write_config(site: &Site) -> Result<String, String> {
    let home = home_of(site)?;
    let ecosystem = ecosystem_file(site);
    let config = render_config(site, &apps::effective_env(site), ecosystem.as_deref());
    apps::write_user_file(site, "pm2.config.js", config.as_bytes())?;
    Ok(format!("{home}/{CONFIG_REL}"))
}

/// Rotate logs with the system's logrotate: `pm2-logrotate` costs a Node process per site.
fn install_logrotate(config: &Config, site: &Site) {
    if !runtimes::can_install(config) {
        return;
    }
    let Some(home) = site.home_dir.as_deref() else { return };
    let conf = format!(
        "# Managed by CloudPanel - changes will be overwritten\n\
         {home}/.pm2/logs/*.log {{\n    su {user} {user}\n    daily\n    size 10M\n    rotate 5\n    \
         compress\n    delaycompress\n    missingok\n    notifempty\n    copytruncate\n}}\n",
        user = site.system_user,
    );
    let script = format!("cat > {}", logrotate_path(&site.domain));
    let r = run_host("/bin/sh", &["-c", &script], &CmdOpts::default().stdin(conf).timeout(30));
    if !r.success() {
        warn!("logrotate config for {}: {}", site.domain, r.stderr.trim());
    }
}

fn logrotate_path(domain: &str) -> String {
    format!("/etc/logrotate.d/cloudpanel-pm2-{}", domain.replace('.', "-"))
}

/// Remove what only PM2 sites have: the rotation config, and a hand-started daemon, which
/// would otherwise stop the site user from being deleted.
pub fn remove(config: &Config, site: &Site) {
    if runtimes::can_install(config) {
        let script = format!("rm -f {}", logrotate_path(&site.domain));
        let _ = run_host("/bin/sh", &["-c", &script], &CmdOpts::default().timeout(30));
    }
    if foreign_daemon(config, site) {
        let _ = pm2(site, &["kill"], 60);
    }
}

fn daemon_alive(site: &Site) -> bool {
    let Some(home) = site.home_dir.as_deref() else {
        return false;
    };
    let Some(pid) = fs::read_to_string(format!("{home}/.pm2/pm2.pid"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    else {
        return false;
    };
    // The site user controls the pid file, so ask /proc what that process really is.
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|c| String::from_utf8_lossy(&c).contains("God Daemon"))
        .unwrap_or(false)
}

/// A PM2 daemon for this user that the panel's unit doesn't own (started by hand over SSH).
pub fn foreign_daemon(config: &Config, site: &Site) -> bool {
    daemon_alive(site) && apps::unit_state(config, &site.domain).0 != "active"
}

/// Take over a hand-started daemon. systemd won't accept a PID from outside its cgroup, so it
/// has to stop and start again under the unit. Its saved process list is set aside so that the
/// panel's config decides what runs; it stays on disk in case it is needed.
pub fn adopt(site: &Site) -> Result<(), String> {
    let home = home_of(site)?;
    pm2_ok(site, &["kill"], 60)?;
    let r = run_with(
        "/bin/sh",
        &[
            "-c",
            "[ ! -f \"$PM2_HOME/dump.pm2\" ] || mv -f \"$PM2_HOME/dump.pm2\" \"$PM2_HOME/dump.pm2.pre-cloudpanel\"",
        ],
        &opts(site, 30)?,
    );
    if !r.success() {
        warn!("could not set aside {home}/.pm2/dump.pm2: {}", r.stderr.trim());
    }
    Ok(())
}

/// Install and start the unit, and write the current config. Returns the config path.
fn ensure_daemon(config: &Config, site: &Site) -> Result<String, String> {
    let bin = binary().ok_or("PM2 is not installed")?;
    let unit = apps::unit_name(&site.domain);
    if foreign_daemon(config, site) {
        return Err(
            "A PM2 daemon started by hand is running for this site. Save the Application settings to take it over."
                .into(),
        );
    }
    write_atomic(
        &apps::unit_path(config, &site.domain),
        render_unit(site, bin).as_bytes(),
        0o644,
    )
    .map_err(|e| format!("write unit: {e}"))?;
    apps::systemctl(&["daemon-reload"])?;
    apps::systemctl(&["enable", &unit])?;
    let _ = apps::systemctl(&["reset-failed", &unit]);
    apps::systemctl(&["start", &unit])?;
    install_logrotate(config, site);
    write_config(site)
}

/// Bring PM2 in line with the site's settings. `fresh` removes the running apps first, which
/// is needed when the command or mode changed, because a reload would keep the old definition.
pub fn apply(config: &Config, site: &Site, fresh: bool) -> Result<(), String> {
    let unit = apps::unit_name(&site.domain);
    if !(apps::has_start(site) && site.app_enabled && site.is_active) {
        let _ = apps::systemctl(&["disable", "--now", &unit]);
        return Ok(());
    }
    let cfg = ensure_daemon(config, site)?;
    if fresh {
        let _ = pm2(site, &["delete", "all"], 60);
    }
    pm2_ok(site, &["startOrReload", &cfg, "--update-env"], 180)?;
    pm2_ok(site, &["save", "--force"], 60)?;
    Ok(())
}

pub fn act(config: &Config, site: &Site, action: AppAction) -> Result<(), String> {
    let unit = apps::unit_name(&site.domain);
    if matches!(action, AppAction::Stop) {
        if apps::unit_state(config, &site.domain).0 == "active" {
            let cfg = write_config(site)?;
            pm2_ok(site, &["stop", &cfg], 60)?;
            pm2_ok(site, &["save", "--force"], 60)?;
        } else {
            let _ = apps::systemctl(&["stop", &unit]);
        }
        return Ok(());
    }
    let cfg = ensure_daemon(config, site)?;
    let verb = if matches!(action, AppAction::Reload) {
        "startOrReload"
    } else {
        "startOrRestart"
    };
    pm2_ok(site, &[verb, &cfg, "--update-env"], 180)?;
    pm2_ok(site, &["save", "--force"], 60)?;
    Ok(())
}

#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct Process {
    pub name: String,
    pub id: i64,
    pub status: String,
    pub pid: Option<u64>,
    pub cpu: f64,
    pub memory_bytes: u64,
    pub restarts: u64,
    pub started_at_ms: Option<i64>,
    pub exec_mode: String,
}

/// Pick out the fields shown in the panel. `pm2 jlist` includes each app's whole environment,
/// which must go no further than this function.
pub fn parse_jlist(out: &str) -> Vec<Process> {
    let start = out.find('[').unwrap_or(0);
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&out[start..]) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|p| {
            let env = &p["pm2_env"];
            Process {
                name: p["name"].as_str().unwrap_or("").to_string(),
                id: p["pm_id"].as_i64().unwrap_or(-1),
                status: env["status"].as_str().unwrap_or("unknown").to_string(),
                pid: p["pid"].as_u64().filter(|x| *x > 0),
                cpu: p["monit"]["cpu"].as_f64().unwrap_or(0.0),
                memory_bytes: p["monit"]["memory"].as_u64().unwrap_or(0),
                restarts: env["restart_time"].as_u64().unwrap_or(0),
                started_at_ms: env["pm_uptime"].as_i64(),
                exec_mode: env["exec_mode"].as_str().unwrap_or("").replace("_mode", ""),
            }
        })
        .collect()
}

/// Add PM2's view to a unit's status. A running daemon with a crashed app is not healthy, so
/// the state is taken from the apps, and alerts follow it.
pub fn enrich_status(site: &Site, st: &mut AppStatus) {
    if st.active_state != "active" {
        return;
    }
    let Ok(r) = pm2(site, &["jlist"], 30) else {
        return;
    };
    if !r.success() {
        return;
    }
    summarize(parse_jlist(&r.stdout), st);
}

fn summarize(processes: Vec<Process>, st: &mut AppStatus) {
    let online = processes.iter().filter(|p| p.status == "online").count();
    let errored = processes.iter().any(|p| p.status == "errored");
    if online > 0 && online == processes.len() {
        st.sub_state = "online".into();
    } else if errored {
        st.active_state = "failed".into();
        st.sub_state = "errored".into();
    } else if online > 0 {
        st.sub_state = "partly online".into();
    } else {
        st.active_state = "inactive".into();
        st.sub_state = if processes.is_empty() { "no apps" } else { "stopped" }.into();
    }
    st.main_pid = processes.iter().find_map(|p| p.pid).and_then(|p| u32::try_from(p).ok());
    st.memory_bytes = Some(processes.iter().map(|p| p.memory_bytes).sum());
    st.restarts = u32::try_from(processes.iter().map(|p| p.restarts).sum::<u64>()).ok();
    st.processes = processes;
}

/// Recent app output. Read as the site user: they own these paths and could link them anywhere.
pub fn logs(site: &Site, lines: usize) -> Result<String, String> {
    let n = lines.to_string();
    let r = run_with(
        "/bin/sh",
        &[
            "-c",
            "cd \"$PM2_HOME/logs\" 2>/dev/null || exit 0; set -- *.log; [ -e \"$1\" ] || exit 0; \
             exec tail -n \"$0\" -- \"$@\"",
            &n,
        ],
        &opts(site, 20)?,
    );
    if r.missing {
        return Ok(String::new()); // development
    }
    r.into_result("tail", "")
}

/// Empty the app's log files. This doesn't need the daemon, so unlike `pm2 flush` it can't start one.
pub fn flush_logs(site: &Site) -> Result<(), String> {
    let r = run_with(
        "/bin/sh",
        &[
            "-c",
            "cd \"$PM2_HOME/logs\" 2>/dev/null || exit 0; for f in *.log; do [ ! -f \"$f\" ] || : > \"$f\"; done",
        ],
        &opts(site, 20)?,
    );
    r.into_result("sh", "").map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::nginx::test_site;

    fn site() -> Site {
        let mut s = test_site("nodejs");
        s.domain = "shop.example.com".into();
        s.system_user = "shop-example".into();
        s.home_dir = Some("/home/shop-example".into());
        s.app_manager = "pm2".into();
        s.app_command = Some("npm start -- --x=\"y\"".into());
        s
    }

    fn env() -> BTreeMap<String, String> {
        [
            ("SECRET".to_string(), "a\"b".to_string()),
            ("PORT".to_string(), "9999".to_string()),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn unit_runs_the_daemon_as_the_site_user() {
        let u = render_unit(&site(), "/usr/bin/pm2");
        assert!(u.contains("Type=forking\n"));
        assert!(u.contains("User=shop-example\n"));
        assert!(u.contains("Environment=PM2_HOME=/home/shop-example/.pm2\n"));
        assert!(u.contains("PIDFile=/home/shop-example/.pm2/pm2.pid\n"));
        assert!(u.contains("ExecStart=/usr/bin/pm2 resurrect\n"));
        assert!(u.contains("ExecStop=/usr/bin/pm2 kill\n"));
    }

    #[test]
    fn shell_command_runs_forked_and_app_port_wins() {
        let c = render_config(&site(), &env(), None);
        assert!(c.contains("\"script\":\"/bin/sh\""));
        assert!(c.contains("\"interpreter\":\"none\""));
        assert!(c.contains("\"PORT\":\"3000\""), "{c}");
        assert!(!c.contains("9999"));
        assert!(c.contains("\"SECRET\":\"a\\\"b\""));
        assert!(!c.contains("exec_mode"));
    }

    #[test]
    fn script_can_cluster_with_options() {
        let mut s = site();
        s.app_command = Some("server.js".into());
        s.app_pm2 = serde_json::to_string(&Pm2Options {
            instances: "2".into(),
            max_memory: "512M".into(),
            node_args: "--max-old-space-size=512".into(),
            ..Default::default()
        })
        .unwrap();
        let c = render_config(&s, &env(), None);
        assert!(c.contains("\"script\":\"server.js\""));
        assert!(c.contains("\"exec_mode\":\"cluster\""));
        assert!(c.contains("\"instances\":2"));
        assert!(c.contains("\"max_memory_restart\":\"512M\""));
        assert!(c.contains("\"node_args\":\"--max-old-space-size=512\""));
    }

    #[test]
    fn ecosystem_file_is_wrapped_and_panel_env_wins() {
        let c = render_config(&site(), &env(), Some("/home/x/ecosystem.config.js"));
        assert!(c.contains("require(\"/home/x/ecosystem.config.js\")"));
        assert!(c.contains("...(app.env || {}), ...env"));
        assert!(c.contains("\"PORT\":\"3000\""));
    }

    #[test]
    fn validates_options() {
        let base = Pm2Options::default();
        let cluster = Pm2Options {
            instances: "max".into(),
            ..base.clone()
        };
        assert!(validate_options(&base, Some("npm start"), false).is_ok());
        assert!(validate_options(&cluster, Some("npm start"), false).is_err());
        assert!(validate_options(&cluster, Some("server.js"), false).is_ok());
        assert!(validate_options(&cluster, None, true).is_ok());
        for bad in [
            Pm2Options {
                instances: "0".into(),
                ..base.clone()
            },
            Pm2Options {
                max_memory: "lots".into(),
                ..base.clone()
            },
            Pm2Options {
                cron_restart: "not a cron".into(),
                ..base.clone()
            },
            Pm2Options {
                node_args: "a\nb".into(),
                ..base.clone()
            },
        ] {
            assert!(validate_options(&bad, Some("server.js"), false).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn jlist_keeps_no_environment() {
        let out = r#"[{"name":"a","pm_id":0,"pid":12,"monit":{"cpu":3,"memory":100},
            "pm2_env":{"status":"online","restart_time":2,"pm_uptime":5,"exec_mode":"cluster_mode","SECRET":"hunter2"}}]"#;
        let p = parse_jlist(out);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].exec_mode, "cluster");
        assert_eq!(p[0].restarts, 2);
        assert!(!serde_json::to_string(&p).unwrap().contains("hunter2"));
        assert!(parse_jlist("not json").is_empty());
    }

    #[test]
    fn status_follows_the_apps() {
        let proc = |status: &str| Process {
            status: status.into(),
            ..Default::default()
        };
        let run = |procs: Vec<Process>| {
            let mut st = AppStatus {
                active_state: "active".into(),
                ..Default::default()
            };
            summarize(procs, &mut st);
            st.active_state
        };
        assert_eq!(run(vec![proc("online"), proc("online")]), "active");
        assert_eq!(run(vec![proc("online"), proc("errored")]), "failed");
        assert_eq!(run(vec![proc("stopped")]), "inactive");
        assert_eq!(run(vec![]), "inactive");
    }

    #[test]
    fn recognises_scripts() {
        assert!(is_script("server.js"));
        assert!(is_script("dist/index.mjs"));
        assert!(!is_script("npm start"));
        assert!(!is_script("node server.js"));
        assert!(!is_script(""));
    }
}
