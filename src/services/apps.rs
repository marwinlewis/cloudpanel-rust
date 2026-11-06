//! Process manager for Node.js / Python / generic apps: one systemd unit per site, running
//! as the site user with automatic restarts. Node.js sites can run under PM2 instead (see
//! `pm2`), in which case the same unit owns the site's PM2 daemon.

use super::cmd::{run_with, CmdOpts, CmdResult};
use super::{dotenv, pm2};
use crate::config::Config;
use crate::db::models::{Site, SiteType};
use crate::fsutil::write_atomic;
use crate::jobs::JobLog;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// `cloudpanel-app-<slug>` where slug is the domain with dots replaced.
pub fn unit_name(domain: &str) -> String {
    format!("cloudpanel-app-{}", domain.replace('.', "-"))
}

pub(crate) fn unit_path(config: &Config, domain: &str) -> PathBuf {
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

/// The app's variables: the `.env` file, plus anything still only in the panel's database
/// from before `.env` became the source of truth. The file wins.
pub fn effective_env(site: &Site) -> BTreeMap<String, String> {
    let mut env = site.env_map();
    match dotenv::read_site(site) {
        Ok(Some(text)) => env.extend(dotenv::parse(&text).vars),
        Ok(None) => {}
        Err(e) => warn!("{}: {e}", site.domain),
    }
    env
}

pub fn render_env(site: &Site) -> String {
    let env = effective_env(site);
    let mut out = String::from("# Managed by CloudPanel\n");
    if let Some(p) = site.target_port {
        out.push_str(&format!("PORT={p}\n"));
    }
    if !env.contains_key("HOST") {
        out.push_str("HOST=127.0.0.1\n");
    }
    for (k, v) in &env {
        // nginx proxies to the site's app port, so a PORT in .env can't move the app.
        if k == "PORT" && site.target_port.is_some() {
            continue;
        }
        out.push_str(&format!("{k}={}\n", env_quote(v)));
    }
    out
}

/// Write the root-only copy of the environment that units read.
fn write_env_file(config: &Config, site: &Site) -> Result<PathBuf, String> {
    let env_file = env_path(config, &site.domain);
    if let Some(dir) = env_file.parent() {
        crate::fsutil::create_private_dir(dir, 0o700).map_err(|e| e.to_string())?;
    }
    write_atomic(&env_file, render_env(site).as_bytes(), 0o600).map_err(|e| format!("write env file: {e}"))?;
    Ok(env_file)
}

/// True when `.env` has changed since the app last picked it up.
pub fn env_pending(config: &Config, site: &Site) -> bool {
    if !has_start(site) || !site.app_enabled {
        return false;
    }
    fs::read_to_string(env_path(config, &site.domain)).map_or(true, |applied| applied != render_env(site))
}

/// PATH for the app and for commands run on its behalf.
pub fn app_path(home: &str, wd: &str) -> String {
    format!("{home}/.local/bin:{wd}/node_modules/.bin:{wd}/.venv/bin:/usr/local/bin:/usr/bin:/bin")
}

/// Whether the site has something to run: a start command, or an ecosystem file under PM2.
pub fn has_start(site: &Site) -> bool {
    site.app_command.as_deref().is_some_and(|c| !c.trim().is_empty()) || pm2::ecosystem_file(site).is_some()
}

/// Write a private file into `~/.cloudpanel` as the site user. They own that directory, so
/// doing this as root could be redirected with a symlink. Contents travel over stdin.
pub(crate) fn write_user_file(site: &Site, name: &str, contents: &[u8]) -> Result<(), String> {
    let home = site.home_dir.as_deref().ok_or("This site has no Linux user")?;
    let opts = local_user(
        CmdOpts::default()
            .user(&site.system_user)
            .env("HOME", home)
            .stdin(contents.to_vec())
            .timeout(30),
    );
    let r = run_with(
        "/bin/sh",
        &[
            "-c",
            "umask 077 && mkdir -p \"$HOME/.cloudpanel\" && cat > \"$HOME/.cloudpanel/$0.tmp\" \
             && mv -f \"$HOME/.cloudpanel/$0.tmp\" \"$HOME/.cloudpanel/$0\"",
            name,
        ],
        &opts,
    );
    r.into_result("sh", "/bin/sh is not available").map(|_| ())
}

/// There are no site users to switch to in Windows development builds.
fn local_user(opts: CmdOpts) -> CmdOpts {
    if cfg!(windows) {
        CmdOpts { as_user: None, ..opts }
    } else {
        opts
    }
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
         Environment=PATH={path}\n\
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
        path = app_path(&home, &wd),
    )
}

pub(crate) fn systemctl(args: &[&str]) -> Result<String, String> {
    let r = run_with("systemctl", args, &CmdOpts::default().timeout(60));
    if r.missing {
        return Ok(String::new()); // development
    }
    r.into_result("systemctl", "")
}

/// Write the unit + env file and (re)start or stop it according to `app_enabled`.
pub fn apply(config: &Config, site: &Site) -> Result<(), String> {
    apply_with(config, site, false)
}

/// [`apply`] for a changed command or mode. PM2 removes the running apps first, because a
/// reload would keep their old definition.
pub fn apply_fresh(config: &Config, site: &Site) -> Result<(), String> {
    apply_with(config, site, true)
}

fn apply_with(config: &Config, site: &Site, fresh: bool) -> Result<(), String> {
    let unit = unit_name(&site.domain);
    let env_file = write_env_file(config, site)?;
    if site.uses_pm2() {
        return pm2::apply(config, site, fresh);
    }

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
        let _ = systemctl(&["reset-failed", &unit]);
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

/// Stop the site's unit whichever manager it runs. Under PM2 this stops the whole daemon.
/// Use it when switching managers, or while the site's files are being replaced.
pub fn stop_unit(domain: &str) {
    let _ = systemctl(&["stop", &unit_name(domain)]);
}

/// Stop the app and delete its unit and env file.
pub fn remove(config: &Config, site: &Site) {
    let domain = &site.domain;
    let unit = unit_name(domain);
    stop_and_disable(&unit);
    pm2::remove(config, site);
    let _ = fs::remove_file(unit_path(config, domain));
    let _ = fs::remove_file(env_path(config, domain));
    let _ = systemctl(&["daemon-reload"]);
}

#[derive(Clone, Copy)]
pub enum AppAction {
    Start,
    Stop,
    Restart,
    /// Zero-downtime restart. PM2 only.
    Reload,
}

pub fn act(config: &Config, site: &Site, action: AppAction) -> Result<(), String> {
    let stopping = matches!(action, AppAction::Stop);
    if !stopping {
        // Any start picks up the current `.env`.
        write_env_file(config, site)?;
    }
    if site.uses_pm2() {
        return pm2::act(config, site, action);
    }
    let unit = unit_name(&site.domain);
    let verb = match action {
        AppAction::Start => "start",
        AppAction::Stop => "stop",
        AppAction::Restart => "restart",
        AppAction::Reload => return Err("Reload is only available for apps running under PM2".into()),
    };
    if !stopping {
        let _ = systemctl(&["reset-failed", &unit]);
    }
    systemctl(&[verb, &unit]).map(|_| ())
}

#[derive(Serialize, Default)]
pub struct AppStatus {
    pub unit: String,
    pub manager: String,
    pub installed: bool,
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub since: Option<String>,
    pub restarts: Option<u32>,
    /// PM2 apps, one entry per instance.
    pub processes: Vec<pm2::Process>,
    /// A PM2 daemon for this site that was started by hand, outside the panel's unit.
    pub foreign_daemon: bool,
}

/// Parse `systemctl show` key=value output.
pub fn parse_show(out: &str) -> std::collections::HashMap<String, String> {
    out.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The unit's (ActiveState, SubState). Empty when systemd isn't available.
pub(crate) fn unit_state(config: &Config, domain: &str) -> (String, String) {
    if !unit_path(config, domain).exists() {
        return ("not-installed".into(), String::new());
    }
    let r = run_with(
        "systemctl",
        &["show", &unit_name(domain), "--property=ActiveState,SubState"],
        &CmdOpts::default().timeout(10),
    );
    let m = parse_show(&r.stdout);
    (
        m.get("ActiveState").cloned().unwrap_or_default(),
        m.get("SubState").cloned().unwrap_or_default(),
    )
}

pub fn status(config: &Config, site: &Site) -> AppStatus {
    let domain = &site.domain;
    let unit = unit_name(domain);
    let installed = unit_path(config, domain).exists();
    let mut st = AppStatus {
        unit: unit.clone(),
        manager: site.app_manager.clone(),
        installed,
        active_state: if installed {
            "unknown".into()
        } else {
            "not-installed".into()
        },
        ..Default::default()
    };
    if site.kind() == Some(SiteType::Nodejs) {
        st.foreign_daemon = pm2::foreign_daemon(config, site);
    }
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
    if site.uses_pm2() {
        pm2::enrich_status(site, &mut st);
    }
    st
}

/// Recent app output. PM2 apps log to files; the unit's journal only has the daemon's own
/// lines, which are what explain a daemon that won't start.
pub fn logs(site: &Site, lines: usize) -> Result<String, String> {
    if site.uses_pm2() {
        let out = pm2::logs(site, lines)?;
        if !out.trim().is_empty() {
            return Ok(out);
        }
    }
    journal(&unit_name(&site.domain), lines)
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

/// What a Node.js project in the workdir needs, shown in the Application tab.
#[derive(Serialize, Default, Clone, Debug, PartialEq, Eq)]
pub struct ProjectInfo {
    pub has_package_json: bool,
    pub package_manager: String,
    pub has_lockfile: bool,
    pub has_build_script: bool,
    /// Built elsewhere and uploaded complete: nothing here can be installed or rebuilt.
    pub prebuilt: bool,
    pub note: Option<String>,
}

const LOCKFILES: &[(&str, &str)] = &[
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
    ("npm-shrinkwrap.json", "npm"),
];
const BUILD_OUTPUT: &[&str] = &[".next", "dist", "build", ".output", "out"];
const SOURCE_MARKERS: &[&str] = &[
    "src",
    "app",
    "pages",
    "tsconfig.json",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "vite.config.js",
    "vite.config.ts",
    "nuxt.config.js",
    "nuxt.config.ts",
];

const PREBUILT_NOTE: &str = "This looks like a prebuilt deploy: it has build output and node_modules, but no source \
                             files or lockfile. Its node_modules is already complete and there is nothing here to \
                             build, so restart the app after uploading a new build.";

pub fn inspect_project(wd: &Path) -> ProjectInfo {
    let mut info = ProjectInfo {
        package_manager: "npm".into(),
        ..Default::default()
    };
    let Ok(text) = fs::read_to_string(wd.join("package.json")) else {
        info.note = Some(format!("No package.json in {}", wd.display()));
        return info;
    };
    info.has_package_json = true;
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(pkg) => {
            info.has_build_script = pkg["scripts"]["build"].as_str().is_some_and(|b| !b.trim().is_empty());
        }
        Err(e) => info.note = Some(format!("package.json is not valid JSON: {e}")),
    }
    if let Some((_, pm)) = LOCKFILES.iter().find(|(f, _)| wd.join(f).exists()) {
        info.has_lockfile = true;
        info.package_manager = (*pm).into();
    }
    let has = |names: &[&str]| names.iter().any(|n| wd.join(n).exists());
    info.prebuilt = !info.has_lockfile && wd.join("node_modules").is_dir() && has(BUILD_OUTPUT) && !has(SOURCE_MARKERS);
    if info.prebuilt {
        info.note = Some(PREBUILT_NOTE.into());
    }
    info
}

const STEP_TIMEOUT_SECS: u64 = 20 * 60;

/// Run one step as the site user, streaming its output. `out_of_sync` is set if npm reports
/// that the lockfile doesn't match. Only `HOME` and `PATH` are passed in: the app's variables
/// would make `npm install` skip the devDependencies a build needs (`NODE_ENV=production`).
fn run_step(site: &Site, wd: &Path, prog: &str, args: &[&str], log: &JobLog, out_of_sync: &mut bool) -> CmdResult {
    let home = site
        .home_dir
        .clone()
        .unwrap_or_else(|| wd.to_string_lossy().into_owned());
    log.line(&format!("$ {prog} {}", args.join(" ")));
    let opts = local_user(
        CmdOpts::default()
            .user(&site.system_user)
            .cwd(wd)
            .env("HOME", &home)
            .env("PATH", &app_path(&home, &wd.to_string_lossy()))
            .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
            .timeout(STEP_TIMEOUT_SECS),
    );
    super::cmd::run_streaming(prog, args, &opts, &mut |l, _| {
        if l.contains("EUSAGE") || l.contains("can only install packages when your package.json") {
            *out_of_sync = true;
        }
        log.line(l);
    })
}

/// Turn a failed step into something a person can act on.
fn step_error(prog: &str, r: &CmdResult) -> String {
    if r.timed_out {
        return format!("{prog} did not finish within {} minutes", STEP_TIMEOUT_SECS / 60);
    }
    if r.missing {
        return format!("{prog} is not installed");
    }
    match r.code {
        // 203 is systemd's "could not execute"; 127 is the shell's "not found".
        Some(203) | Some(127) => format!("{prog} could not be started; check that it is installed for the site user"),
        Some(137) => format!(
            "{prog} was killed (exit code 137), most likely because the server ran out of memory. \
             Build on another machine and upload the result, or add swap."
        ),
        code => format!("{prog} exited with code {}", code.unwrap_or(-1)),
    }
}

fn step(site: &Site, wd: &Path, prog: &str, args: &[&str], log: &JobLog) -> Result<(), String> {
    let mut ignored = false;
    let r = run_step(site, wd, prog, args, log, &mut ignored);
    if r.success() {
        Ok(())
    } else {
        Err(step_error(prog, &r))
    }
}

/// How to invoke the project's package manager: (program, leading arguments).
fn manager_command(pm: &str) -> (&'static str, &'static [&'static str]) {
    match pm {
        "pnpm" => ("corepack", &["pnpm"]),
        "yarn" => ("corepack", &["yarn"]),
        _ => ("npm", &[]),
    }
}

fn install_node(site: &Site, wd: &Path, info: &ProjectInfo, force: bool, log: &JobLog) -> Result<(), String> {
    if !info.has_package_json {
        return Err(format!("No package.json in {}", wd.display()));
    }
    if info.prebuilt && !force {
        log.line(PREBUILT_NOTE);
        log.line("Skipped installing. Nothing was changed.");
        return Ok(());
    }
    if info.package_manager != "npm" {
        let (prog, lead) = manager_command(&info.package_manager);
        let mut args: Vec<&str> = lead.to_vec();
        args.push("install");
        return step(site, wd, prog, &args, log);
    }
    if info.has_lockfile {
        let mut out_of_sync = false;
        let r = run_step(
            site,
            wd,
            "npm",
            &["ci", "--no-audit", "--no-fund"],
            log,
            &mut out_of_sync,
        );
        if r.success() {
            return Ok(());
        }
        if !out_of_sync {
            return Err(step_error("npm", &r));
        }
        log.line("package-lock.json is out of sync with package.json; falling back to npm install.");
    }
    step(site, wd, "npm", &["install", "--no-audit", "--no-fund"], log)
}

fn install_python(site: &Site, wd: &Path, log: &JobLog) -> Result<(), String> {
    if !wd.join("requirements.txt").exists() {
        return Err(format!("No requirements.txt in {}", wd.display()));
    }
    if !wd.join(".venv").exists() {
        step(site, wd, "python3", &["-m", "venv", ".venv"], log)?;
    }
    let pip = wd.join(".venv/bin/pip").to_string_lossy().into_owned();
    step(site, wd, &pip, &["install", "-r", "requirements.txt"], log)
}

/// Install dependencies as the site user. `force` also installs over a prebuilt deploy.
pub fn install_dependencies(site: &Site, log: &JobLog, force: bool) -> Result<(), String> {
    let wd = PathBuf::from(workdir(site));
    match site.kind() {
        Some(SiteType::Nodejs) => {
            let info = inspect_project(&wd);
            install_node(site, &wd, &info, force, log)?;
            if info.prebuilt && !force {
                return Ok(());
            }
        }
        Some(SiteType::Python) => install_python(site, &wd, log)?,
        _ => return Err("Dependencies can only be installed for Node.js and Python sites".into()),
    }
    log.line("Dependencies installed.");
    Ok(())
}

fn shell_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// Run the project's build script with the app's variables. They reach it through a private
/// file that is removed before the build starts, because `--setenv` would show them in `ps`.
pub fn build(site: &Site, log: &JobLog) -> Result<(), String> {
    let wd = PathBuf::from(workdir(site));
    if site.kind() != Some(SiteType::Nodejs) {
        return Err("Only Node.js sites have a build step".into());
    }
    let info = inspect_project(&wd);
    if !info.has_package_json {
        return Err(format!("No package.json in {}", wd.display()));
    }
    if info.prebuilt {
        return Err(PREBUILT_NOTE.into());
    }
    if !info.has_build_script {
        return Err("package.json has no build script".into());
    }
    let mut file = String::new();
    for (k, v) in effective_env(site) {
        if k != "PORT" {
            file.push_str(&format!("{k}={}\n", shell_quote(&v)));
        }
    }
    write_user_file(site, "build.env", file.as_bytes())?;
    let (prog, lead) = manager_command(&info.package_manager);
    let mut argv: Vec<&str> = vec![
        "-c",
        "set -a; . \"$HOME/.cloudpanel/build.env\"; set +a; rm -f \"$HOME/.cloudpanel/build.env\"; exec \"$0\" \"$@\"",
        prog,
    ];
    argv.extend_from_slice(lead);
    argv.extend_from_slice(&["run", "build"]);
    log.line("Building with the variables from .env");
    let mut ignored = false;
    let r = run_step(site, &wd, "/bin/sh", &argv, log, &mut ignored);
    if !r.success() {
        return Err(step_error(prog, &r));
    }
    log.line("Build finished.");
    Ok(())
}

/// After an install, bring back an app that couldn't start without its dependencies.
pub fn restart_if_down(config: &Config, site: &Site, log: &JobLog) -> Result<(), String> {
    if !site.app_enabled || !site.is_active || !has_start(site) {
        return Ok(());
    }
    if status(config, site).active_state != "active" {
        log.line("The app was not running; starting it.");
        act(config, site, AppAction::Restart)?;
    }
    Ok(())
}

/// Install, build, then reload the app with the new code.
pub fn deploy(config: &Config, site: &Site, log: &JobLog) -> Result<(), String> {
    let wd = PathBuf::from(workdir(site));
    install_dependencies(site, log, false)?;
    if site.kind() == Some(SiteType::Nodejs) {
        let info = inspect_project(&wd);
        if info.has_build_script && !info.prebuilt {
            build(site, log)?;
        }
    }
    if !has_start(site) {
        log.line("No start command is set, so there is nothing to restart.");
        return Ok(());
    }
    if !site.app_enabled || !site.is_active {
        log.line("The app is not enabled, so it was not restarted.");
        return Ok(());
    }
    log.line("Restarting the app with the new code.");
    let action = if site.uses_pm2() {
        AppAction::Reload
    } else {
        AppAction::Restart
    };
    act(config, site, action)?;
    log.line("Deploy finished.");
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
            app_manager: "systemd".into(),
            app_pm2: "{}".into(),
            www_redirect: false,
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
    fn env_port_cannot_move_the_app_and_host_can_be_overridden() {
        let mut s = site();
        s.app_env = r#"{"PORT":"9999","HOST":"0.0.0.0"}"#.into();
        let e = render_env(&s);
        assert!(e.contains("PORT=3000\n"));
        assert!(!e.contains("9999"));
        assert!(e.contains("HOST=\"0.0.0.0\"\n"));
        assert!(!e.contains("HOST=127.0.0.1"));
    }

    fn project(files: &[&str]) -> (tempfile::TempDir, ProjectInfo) {
        let dir = tempfile::tempdir().unwrap();
        for f in files {
            if let Some(name) = f.strip_suffix('/') {
                fs::create_dir_all(dir.path().join(name)).unwrap();
            } else if *f == "package.json" {
                fs::write(
                    dir.path().join(f),
                    r#"{"scripts":{"build":"next build"},"files":["build"]}"#,
                )
                .unwrap();
            } else {
                fs::write(dir.path().join(f), "").unwrap();
            }
        }
        let info = inspect_project(dir.path());
        (dir, info)
    }

    #[test]
    fn detects_prebuilt_deploys() {
        // The layout that failed in production: built elsewhere and uploaded complete.
        let (_d, info) = project(&["package.json", "server.js", ".next/", "node_modules/"]);
        assert!(info.prebuilt);
        assert!(info.has_build_script);
        assert!(info.note.is_some());

        for files in [
            // Without node_modules an install is what it needs.
            &["package.json", ".next/"][..],
            &["package.json", ".next/", "node_modules/", "src/"][..],
            &["package.json", ".next/", "node_modules/", "package-lock.json"][..],
            &["package.json", "node_modules/"][..],
        ] {
            assert!(!project(files).1.prebuilt, "{files:?}");
        }
    }

    #[test]
    fn build_script_comes_from_scripts_not_text() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"files":["build"],"name":"build"}"#).unwrap();
        assert!(!inspect_project(dir.path()).has_build_script);
        fs::write(dir.path().join("package.json"), r#"{"scripts":{"build":"tsc"}}"#).unwrap();
        assert!(inspect_project(dir.path()).has_build_script);
    }

    #[test]
    fn detects_the_package_manager() {
        assert_eq!(project(&["package.json"]).1.package_manager, "npm");
        assert_eq!(project(&["package.json", "yarn.lock"]).1.package_manager, "yarn");
        assert_eq!(project(&["package.json", "pnpm-lock.yaml"]).1.package_manager, "pnpm");
        assert!(project(&["package.json", "package-lock.json"]).1.has_lockfile);
    }

    #[test]
    fn explains_failed_steps() {
        let failed = |code| CmdResult {
            code: Some(code),
            missing: false,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(step_error("npm", &failed(137)).contains("out of memory"));
        assert!(step_error("npm", &failed(203)).contains("could not be started"));
        assert!(step_error("npm", &failed(1)).contains("code 1"));
        let timed_out = CmdResult {
            timed_out: true,
            ..failed(-1)
        };
        assert!(step_error("npm", &timed_out).contains("did not finish"));
    }

    #[test]
    fn parses_systemctl_show() {
        let m = parse_show("ActiveState=active\nSubState=running\nMainPID=42\n");
        assert_eq!(m["MainPID"], "42");
    }
}
