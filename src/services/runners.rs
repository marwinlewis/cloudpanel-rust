//! GitHub Actions self-hosted runners.
//!
//! Each runner belongs to a site and runs as that site's Linux user, from
//! `~/actions-runner/<name>/`, under a hardened systemd unit the panel writes
//! (`cloudpanel-runner-<id>.service`). It can reach the site's files but no other site's, and it
//! deploys through the panel: the unit hands it a token that only lets it deploy or restart its
//! own site's app (`POST /api/runner-hook/deploy`).
//!
//! The runner release is pinned and checked against its SHA-256, then kept in
//! [`Config::runner_cache_dir`], where site users can read it. Runners update themselves after
//! that, inside their own directory, as GitHub stops sending jobs to outdated runners.
//!
//! Runners installed by hand (with `config.sh` and `svc.sh`) are found by [`scan`] and can be
//! adopted: the panel replaces their `actions.runner.*` unit with its own, for the same directory
//! and registration.

use super::apps::{parse_show, systemctl};
use super::cmd::{run_streaming, run_with, CmdOpts};
use crate::config::Config;
use crate::db::models::Runner;
use crate::fsutil::write_atomic;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The runner release the panel installs. Hashes are the ones GitHub publishes for the assets.
pub const VERSION: &str = "2.338.2";
const SHA256_X64: &str = "baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40";
const SHA256_ARM64: &str = "670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945";
const RELEASES: &str = "https://github.com/actions/runner/releases/download";

/// Where a site user's runners live, under their home.
pub const RUNNERS_DIR: &str = "actions-runner";

// ---------- Installation ----------

/// The release's architecture name for this machine and its expected SHA-256.
fn target() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "x86_64" => Some(("x64", SHA256_X64)),
        "aarch64" => Some(("arm64", SHA256_ARM64)),
        _ => None,
    }
}

/// The cached release for this machine.
pub fn tarball(config: &Config) -> Option<PathBuf> {
    let (arch, _) = target()?;
    Some(
        config
            .runner_cache_dir
            .join(format!("actions-runner-linux-{arch}-{VERSION}.tar.gz")),
    )
}

/// Is the runner release in place, so runners can be created?
pub fn installed(config: &Config) -> bool {
    tarball(config).is_some_and(|p| p.is_file())
}

/// Can the panel install the runner release itself? It needs a real systemd host and a known CPU.
pub fn can_install(config: &Config) -> bool {
    super::runtimes::can_install(config) && target().is_some()
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn http() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(20 * 60))
        .user_agent(concat!("cloudpanel/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

/// Download the release into the cache, streaming it to disk while hashing it. Nothing replaces
/// the cached file unless the hash matches.
async fn download(path: &Path, sha: &str, log: &dyn Fn(&str)) -> Result<(), String> {
    use std::io::Write;
    if path.is_file() && sha256_file(path).is_ok_and(|h| h == sha) {
        log(&format!("The runner {VERSION} release is already downloaded"));
        return Ok(());
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let url = format!("{RELEASES}/v{VERSION}/{name}");
    log(&format!("Downloading {url}"));
    let mut res = http()?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", super::panel_update::with_causes(&e)))?;
    if !res.status().is_success() {
        return Err(format!("Download failed: HTTP {}", res.status()));
    }
    let part = path.with_extension("part");
    let mut file = std::fs::File::create(&part).map_err(|e| format!("Could not write {}: {e}", part.display()))?;
    let mut hasher = Sha256::new();
    let mut size = 0usize;
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| format!("Download failed: {}", super::panel_update::with_causes(&e)))?
    {
        hasher.update(&chunk);
        size += chunk.len();
        file.write_all(&chunk)
            .map_err(|e| format!("Could not write {}: {e}", part.display()))?;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    let got: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != sha {
        let _ = std::fs::remove_file(&part);
        return Err(format!(
            "Checksum verification failed for the runner release (expected {sha}, got {got}). Nothing was installed."
        ));
    }
    crate::fsutil::set_mode(&part, 0o644).map_err(|e| e.to_string())?;
    std::fs::rename(&part, path).map_err(|e| format!("Could not save {}: {e}", path.display()))?;
    log(&format!("Checksum verified ({} MB)", size / 1_000_000));
    Ok(())
}

fn stream(log: &dyn Fn(&str), program: &str, args: &[&str], opts: &CmdOpts) -> Result<(), String> {
    let r = run_streaming(program, args, opts, &mut |l, _| log(l));
    if r.success() {
        Ok(())
    } else {
        Err(format!("{program} failed (exit code {})", r.code.unwrap_or(-1)))
    }
}

/// Install the libraries the runner needs (ICU, Kerberos, OpenSSL...), with the script the
/// release ships, falling back to the packages every supported release has under some name.
fn install_dependencies(config: &Config, tarball: &Path, log: &dyn Fn(&str)) -> Result<(), String> {
    let tmp = config.runner_cache_dir.join("deps");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let t = tarball.to_string_lossy();
    let d = tmp.to_string_lossy();
    let opts = CmdOpts::default()
        .timeout(15 * 60)
        .env("DEBIAN_FRONTEND", "noninteractive");
    let result = stream(log, "tar", &["-xzf", &t, "-C", &d, "./bin/installdependencies.sh"], &opts)
        .and_then(|_| {
            log("Installing the runner's system libraries");
            stream(log, "bash", &[&format!("{d}/bin/installdependencies.sh")], &opts)
        })
        .or_else(|e| {
            log(&format!("{e}; installing the libraries with apt instead"));
            stream(
                log,
                "apt-get",
                &["install", "-y", "-q", "--no-install-recommends", "libkrb5-3", "zlib1g", "libicu-dev", "libssl3t64"],
                &opts,
            )
            .or_else(|_| {
                stream(
                    log,
                    "apt-get",
                    &["install", "-y", "-q", "--no-install-recommends", "libkrb5-3", "zlib1g", "libicu-dev", "libssl3"],
                    &opts,
                )
            })
        });
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// Download the pinned runner release and install what it needs. Runs as root outside the
/// panel's sandbox, from `cloudpanel runners-install` (the installer and the panel's Install
/// button both call that). Running it again is safe.
pub async fn install(config: &Config, log: &dyn Fn(&str)) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("GitHub runners can only be installed on Linux".into());
    }
    if !crate::fsutil::running_as_root() {
        return Err("Installing GitHub runners needs root".into());
    }
    let (_, sha) = target().ok_or_else(|| {
        format!(
            "GitHub has no runner release for this CPU ({})",
            std::env::consts::ARCH
        )
    })?;
    let path = tarball(config).ok_or("Unsupported CPU")?;
    std::fs::create_dir_all(&config.runner_cache_dir).map_err(|e| e.to_string())?;
    crate::fsutil::set_mode(&config.runner_cache_dir, 0o755).map_err(|e| e.to_string())?;
    download(&path, sha, log).await?;
    install_dependencies(config, &path, log)?;
    // Older releases are no longer needed: runners update themselves.
    if let Ok(entries) = std::fs::read_dir(&config.runner_cache_dir) {
        for e in entries.flatten() {
            let p = e.path();
            let n = e.file_name().to_string_lossy().into_owned();
            if p != path && n.starts_with("actions-runner-linux-") && n.ends_with(".tar.gz") {
                let _ = std::fs::remove_file(p);
            }
        }
    }
    log(&format!("GitHub Actions runner {VERSION} is ready. Create runners on the Runners page."));
    Ok(())
}

// ---------- GitHub API ----------

/// The API path for a runner URL: `repos/<o>/<r>` or `orgs/<o>`.
pub fn api_scope(github_url: &str) -> Result<String, String> {
    let (_, owner, repo) = crate::validate::github_url(github_url)?;
    Ok(match repo {
        Some(r) => format!("repos/{owner}/{r}"),
        None => format!("orgs/{owner}"),
    })
}

async fn github_post_token(api: &str, pat: &str, github_url: &str, kind: &str) -> Result<String, String> {
    #[derive(Deserialize)]
    struct TokenResponse {
        token: String,
    }
    let url = format!("{api}/{}/actions/runners/{kind}", api_scope(github_url)?);
    let res = http()?
        .post(&url)
        .bearer_auth(pat)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("GitHub could not be reached: {}", super::panel_update::with_causes(&e)))?;
    let status = res.status();
    if !status.is_success() {
        let hint = match status.as_u16() {
            401 => "the token is invalid or expired",
            403 | 404 => "the token can't manage runners there (repository runners need Administration: write, organization runners Self-hosted runners: write)",
            _ => "unexpected answer",
        };
        return Err(format!("GitHub refused the request: HTTP {status}, {hint}"));
    }
    let body: TokenResponse = res
        .json()
        .await
        .map_err(|e| format!("Unexpected answer from GitHub: {e}"))?;
    Ok(body.token)
}

/// A one-hour token to register a runner with, from the stored token.
pub async fn registration_token(api: &str, pat: &str, github_url: &str) -> Result<String, String> {
    github_post_token(api, pat, github_url, "registration-token").await
}

/// A one-hour token to unregister a runner with, from the stored token.
pub async fn removal_token(api: &str, pat: &str, github_url: &str) -> Result<String, String> {
    github_post_token(api, pat, github_url, "remove-token").await
}

/// What GitHub says about a runner.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RemoteRunner {
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub busy: bool,
}

/// The runners GitHub has registered for a repository or organization.
pub async fn list_remote(api: &str, pat: &str, github_url: &str) -> Result<Vec<RemoteRunner>, String> {
    #[derive(Deserialize)]
    struct List {
        runners: Vec<RemoteRunner>,
    }
    let url = format!("{api}/{}/actions/runners?per_page=100", api_scope(github_url)?);
    let res = http()?
        .get(&url)
        .bearer_auth(pat)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("GitHub could not be reached: {}", super::panel_update::with_causes(&e)))?;
    if !res.status().is_success() {
        return Err(format!("GitHub refused the request: HTTP {}", res.status()));
    }
    Ok(res
        .json::<List>()
        .await
        .map_err(|e| format!("Unexpected answer from GitHub: {e}"))?
        .runners)
}

// ---------- Units ----------

pub fn unit_name(id: i64) -> String {
    format!("cloudpanel-runner-{id}")
}

pub fn unit_path(config: &Config, id: i64) -> PathBuf {
    config.systemd_dir.join(format!("{}.service", unit_name(id)))
}

pub fn env_path(config: &Config, id: i64) -> PathBuf {
    config.etc_dir.join("runners").join(format!("{id}.env"))
}

/// Paths go into the unit unquoted, so only plain ones are accepted.
pub fn plain_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= 255
        && !p.split('/').any(|seg| seg == "..")
        && p.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
}

/// A user's home directory, from `/etc/passwd`.
pub fn home_of(user: &str) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7 && f[0] == user).then(|| f[5].to_string())
    })
}

fn user_of_uid(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[0].to_string())
    })
}

/// The unit, modelled on the one GitHub's `svc.sh` writes, sandboxed like the panel's app units.
/// `runsvc.sh` turns systemd's SIGTERM into the SIGINT the runner stops cleanly on, and restarts
/// it after a self-update. Values were validated: user (`validate::system_user`), paths
/// ([`plain_path`]).
pub fn render_unit(r: &Runner, home: &str, env_file: &str) -> String {
    let dir = &r.dir;
    let mut rw = home.to_string();
    if !Path::new(dir).starts_with(home) {
        rw.push(' ');
        rw.push_str(dir);
    }
    format!(
        "# Managed by CloudPanel - changes will be overwritten\n\
         [Unit]\n\
         Description=GitHub Actions runner {name} ({url})\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         WorkingDirectory={dir}\n\
         Environment=HOME={home}\n\
         EnvironmentFile=-{env_file}\n\
         ExecStart={dir}/runsvc.sh\n\
         Restart=always\n\
         RestartSec=5\n\
         KillMode=process\n\
         KillSignal=SIGTERM\n\
         TimeoutStopSec=5min\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=tmpfs\n\
         BindPaths={rw}\n\
         ReadWritePaths={rw}\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         LockPersonality=yes\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        name = r.name,
        url = r.github_url,
        user = r.system_user,
    )
}

/// The panel URL runners call on this machine to deploy.
pub fn hook_url(config: &Config) -> String {
    let scheme = if config.tls_enabled() { "https" } else { "http" };
    let port = config.panel_port().unwrap_or(8443);
    format!("{scheme}://127.0.0.1:{port}/api/runner-hook/deploy")
}

pub fn render_env(config: &Config, deploy_token: Option<&str>) -> String {
    let mut s = String::from("# Managed by CloudPanel\n");
    if let Some(t) = deploy_token {
        s.push_str(&format!(
            "CLOUDPANEL_DEPLOY_URL={}\nCLOUDPANEL_DEPLOY_TOKEN={t}\n",
            hook_url(config)
        ));
    }
    s
}

/// A fresh deploy token and the hash the database keeps of it.
pub fn new_deploy_token() -> (String, String) {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let token: String = format!("cpr_{}", buf.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let hash = crate::auth::jwt::token_hash(&token);
    (token, hash)
}

/// Write the env file and unit, then start the runner.
pub fn apply(config: &Config, r: &Runner, deploy_token: Option<&str>) -> Result<(), String> {
    if !plain_path(&r.dir) {
        return Err(format!("The runner directory {} can't be used in a unit", r.dir));
    }
    let home = home_of(&r.system_user)
        .filter(|h| plain_path(h))
        .unwrap_or_else(|| r.dir.clone());
    let env = env_path(config, r.id);
    if let Some(parent) = env.parent() {
        crate::fsutil::create_private_dir(parent, 0o700).map_err(|e| e.to_string())?;
    }
    // Keep the current token when there's no new one.
    if deploy_token.is_some() || !env.exists() {
        write_atomic(&env, render_env(config, deploy_token).as_bytes(), 0o600)
            .map_err(|e| format!("write {}: {e}", env.display()))?;
    }
    let unit = unit_name(r.id);
    write_atomic(
        &unit_path(config, r.id),
        render_unit(r, &home, &env.to_string_lossy()).as_bytes(),
        0o644,
    )
    .map_err(|e| format!("write unit: {e}"))?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", &unit])?;
    let _ = systemctl(&["reset-failed", &unit]);
    systemctl(&["restart", &unit])?;
    Ok(())
}

/// Stop the runner and delete its unit and env file. Its directory and registration stay.
pub fn remove_unit(config: &Config, id: i64) {
    let _ = systemctl(&["disable", "--now", &unit_name(id)]);
    let _ = std::fs::remove_file(unit_path(config, id));
    let _ = std::fs::remove_file(env_path(config, id));
    let _ = systemctl(&["daemon-reload"]);
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }
}

pub fn act(id: i64, action: Action) -> Result<(), String> {
    let unit = unit_name(id);
    let verb = match action {
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
    };
    if !matches!(action, Action::Stop) {
        let _ = systemctl(&["reset-failed", &unit]);
    }
    systemctl(&[verb, &unit]).map(|_| ())
}

/// The unit's state, and whether the runner's directory still holds a registration.
#[derive(Serialize, Default, Debug, Clone)]
pub struct Status {
    pub unit: String,
    pub active_state: String,
    pub sub_state: String,
    pub since: Option<String>,
    /// The directory or its `.runner` file is gone.
    pub missing: bool,
}

pub fn status(config: &Config, r: &Runner) -> Status {
    let unit = unit_name(r.id);
    let missing = !Path::new(&r.dir).join(".runner").is_file();
    if !unit_path(config, r.id).exists() {
        return Status {
            unit,
            active_state: "not-installed".into(),
            missing,
            ..Default::default()
        };
    }
    let out = run_with(
        "systemctl",
        &["show", &unit, "--property=ActiveState,SubState,ActiveEnterTimestamp"],
        &CmdOpts::default().timeout(10),
    );
    let m = parse_show(&out.stdout);
    Status {
        unit,
        active_state: m.get("ActiveState").cloned().unwrap_or_default(),
        sub_state: m.get("SubState").cloned().unwrap_or_default(),
        since: m.get("ActiveEnterTimestamp").filter(|v| !v.is_empty()).cloned(),
        missing,
    }
}

pub fn logs(id: i64, lines: usize) -> Result<String, String> {
    super::apps::journal(&unit_name(id), lines)
}

// ---------- Creating and removing ----------

fn as_user(user: &str, home: &str) -> CmdOpts {
    CmdOpts::default().user(user).env("HOME", home).timeout(10 * 60)
}

/// What to register a runner with.
pub struct Registration<'a> {
    pub url: &'a str,
    pub token: &'a str,
    pub name: &'a str,
    pub labels: &'a str,
    pub group: &'a str,
}

/// Unpack the release into `dir` and register it with GitHub, as `user`. The token travels on
/// stdin, so it never shows in a process list or the journal. On failure the directory is
/// removed again.
pub fn unpack_and_register(
    config: &Config,
    user: &str,
    home: &str,
    dir: &str,
    reg: &Registration,
    log: &dyn Fn(&str),
) -> Result<(), String> {
    let tarball = tarball(config).filter(|p| p.is_file()).ok_or(
        "The runner release is not installed. An administrator can install it on the Runners page.",
    )?;
    if Path::new(dir).exists() {
        return Err(format!("{dir} already exists. Choose another runner name."));
    }
    log(&format!("Unpacking runner {VERSION} into {dir}"));
    let opts = as_user(user, home);
    let r = run_with(
        "/bin/sh",
        &[
            "-c",
            "umask 022 && mkdir -p \"$0\" && tar -xzf \"$1\" -C \"$0\" && cp \"$0/bin/runsvc.sh\" \"$0/runsvc.sh\"",
            dir,
            &tarball.to_string_lossy(),
        ],
        &opts,
    );
    if !r.success() {
        cleanup_dir(user, home, dir);
        return Err(format!("Unpacking the runner failed: {}", r.combined().trim()));
    }
    log("Registering the runner with GitHub");
    let args = [
        "-c",
        "IFS= read -r ACTIONS_RUNNER_INPUT_TOKEN && export ACTIONS_RUNNER_INPUT_TOKEN && cd \"$0\" && \
         exec ./config.sh --unattended --replace --url \"$1\" --name \"$2\" --work _work \
         ${3:+--labels \"$3\"} ${4:+--runnergroup \"$4\"}",
        dir,
        reg.url,
        reg.name,
        reg.labels,
        reg.group,
    ];
    let opts = as_user(user, home).stdin(format!("{}\n", reg.token).into_bytes());
    let r = run_streaming("/bin/sh", &args, &opts, &mut |l, _| log(l));
    if !r.success() {
        cleanup_dir(user, home, dir);
        return Err(format!(
            "GitHub did not accept the runner (exit code {}). Registration tokens are valid for one hour; get a new one and try again.",
            r.code.unwrap_or(-1)
        ));
    }
    Ok(())
}

fn cleanup_dir(user: &str, home: &str, dir: &str) {
    let _ = run_with("rm", &["-rf", "--", dir], &as_user(user, home).timeout(120));
}

/// Unregister the runner from GitHub with a removal token, as its user.
pub fn unregister(r: &Runner, home: &str, token: &str, log: &dyn Fn(&str)) -> Result<(), String> {
    let opts = as_user(&r.system_user, home).stdin(format!("{token}\n").into_bytes());
    let res = run_streaming(
        "/bin/sh",
        &[
            "-c",
            "IFS= read -r ACTIONS_RUNNER_INPUT_TOKEN && export ACTIONS_RUNNER_INPUT_TOKEN && cd \"$0\" && exec ./config.sh remove",
            &r.dir,
        ],
        &opts,
        &mut |l, _| log(l),
    );
    if res.success() {
        Ok(())
    } else {
        Err(format!(
            "GitHub did not accept the removal (exit code {}). Removal tokens are valid for one hour.",
            res.code.unwrap_or(-1)
        ))
    }
}

/// Delete the runner's directory, as its user.
pub fn delete_dir(r: &Runner, home: &str) {
    cleanup_dir(&r.system_user, home, &r.dir);
}

// ---------- Finding runners installed by hand ----------

/// What a runner's `.runner` file says about it (written by `config.sh`, with a BOM).
#[derive(Deserialize, Debug, Default)]
struct RunnerFile {
    #[serde(rename = "agentName", default)]
    agent_name: String,
    #[serde(rename = "gitHubUrl", default)]
    github_url: String,
}

/// A runner on this machine the panel doesn't manage yet.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub dir: String,
    pub name: String,
    pub github_url: String,
    /// The user its files belong to: who it will run as.
    pub user: String,
    /// The `actions.runner.*` unit `svc.sh` installed for it, if any.
    pub unit: Option<String>,
    /// Why it can't be adopted, if it can't.
    pub problem: Option<String>,
    /// The site of `user`, filled in by the caller.
    pub site_id: Option<i64>,
    pub site_domain: Option<String>,
}

/// `WorkingDirectory=` of a unit file.
fn unit_workdir(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("WorkingDirectory="))
        .map(|v| v.trim().trim_start_matches('-').trim_matches('"').to_string())
}

#[cfg(unix)]
fn owner(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.uid()
}

#[cfg(not(unix))]
fn owner(_meta: &std::fs::Metadata) -> u32 {
    1000
}

fn inspect(dir: &Path, unit: Option<String>) -> Option<Found> {
    let meta = std::fs::symlink_metadata(dir).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let runner_file = dir.join(".runner");
    let rmeta = std::fs::symlink_metadata(&runner_file).ok()?;
    let mut problem = None;
    if !rmeta.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(&runner_file).unwrap_or_default();
    let info: RunnerFile = serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap_or_default();
    let uid = owner(&meta);
    let user = user_of_uid(uid).unwrap_or_else(|| uid.to_string());
    // The real path: the unit and the database refer to it, whatever links led here.
    let d = if cfg!(unix) {
        std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
    } else {
        dir.to_path_buf()
    }
    .to_string_lossy()
    .into_owned();
    if !dir.join(".credentials").is_file() {
        problem = Some("It isn't registered with GitHub (no .credentials).".into());
    } else if uid == 0 {
        problem = Some("It runs as root. Register a new runner under a site instead.".into());
    } else if owner(&rmeta) != uid {
        problem = Some("Its files belong to different users.".into());
    } else if !plain_path(&d) {
        problem = Some("Its path has characters the panel doesn't accept.".into());
    } else if crate::validate::system_user(&user).is_err() {
        problem = Some(format!("Its owner '{user}' isn't a user the panel can run it as."));
    } else if !dir.join("runsvc.sh").is_file() && !dir.join("bin/runsvc.sh").is_file() {
        problem = Some("It has no runsvc.sh; is it a runner directory?".into());
    } else if crate::validate::runner_name(&info.agent_name).is_err() {
        problem = Some("Its name has characters the panel doesn't accept.".into());
    }
    Some(Found {
        dir: d,
        name: info.agent_name,
        github_url: info.github_url,
        user,
        unit,
        problem,
        site_id: None,
        site_domain: None,
    })
}

/// Look for runners the panel doesn't manage: `actions.runner.*` units, and directories with a
/// `.runner` file up to three levels below each home. Symlinks are never followed.
pub fn scan(config: &Config, managed_dirs: &[String]) -> Vec<Found> {
    let key = |d: &str| std::fs::canonicalize(d).unwrap_or_else(|_| PathBuf::from(d));
    let managed: Vec<PathBuf> = managed_dirs.iter().map(|d| key(d)).collect();
    let mut found: Vec<Found> = Vec::new();
    let mut add = |f: Found| {
        let k = key(&f.dir);
        if !managed.contains(&k) && !found.iter().any(|x| key(&x.dir) == k) {
            found.push(f);
        }
    };
    if let Ok(entries) = std::fs::read_dir(&config.systemd_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !(name.starts_with("actions.runner.") && name.ends_with(".service")) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
            if let Some(wd) = unit_workdir(&text) {
                if let Some(f) = inspect(Path::new(&wd), Some(name.trim_end_matches(".service").to_string())) {
                    add(f);
                }
            }
        }
    }
    fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            // Runners never live in these, and they can be huge.
            if matches!(name.as_ref(), "node_modules" | ".git" | "_work" | "htdocs" | "logs" | "databases" | "bin" | "externals")
                || name.starts_with("bin.")
                || name.starts_with("externals.")
            {
                if p.join(".runner").is_file() {
                    out.push(p);
                }
                continue;
            }
            if p.join(".runner").is_file() {
                out.push(p);
                continue;
            }
            if depth > 0 {
                walk(&p, depth - 1, out);
            }
        }
    }
    let mut dirs = Vec::new();
    let home_root = crate::validate::absolute(&config.home_dir);
    if let Ok(entries) = std::fs::read_dir(&home_root) {
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()) {
                walk(&e.path(), 2, &mut dirs);
            }
        }
    }
    for d in dirs {
        if let Some(f) = inspect(&d, None) {
            add(f);
        }
    }
    found.sort_by(|a, b| a.dir.cmp(&b.dir));
    found
}

/// Take over a runner installed by hand: stop and set aside its `svc.sh` unit, and make sure
/// `runsvc.sh` is where the panel's unit starts it. The caller then writes the panel's unit.
pub fn adopt(config: &Config, f: &Found, log: &dyn Fn(&str)) -> Result<(), String> {
    if let Some(problem) = &f.problem {
        return Err(problem.clone());
    }
    if let Some(unit) = &f.unit {
        log(&format!("Stopping {unit}"));
        let _ = systemctl(&["disable", "--now", &format!("{unit}.service")]);
        let path = config.systemd_dir.join(format!("{unit}.service"));
        if path.exists() {
            let aside = config.systemd_dir.join(format!("{unit}.service.cloudpanel-adopted"));
            std::fs::rename(&path, &aside).map_err(|e| format!("Could not move {}: {e}", path.display()))?;
            log(&format!("Moved its unit to {}", aside.display()));
        }
        let _ = systemctl(&["daemon-reload"]);
    }
    if !Path::new(&f.dir).join("runsvc.sh").is_file() {
        let home = home_of(&f.user).unwrap_or_else(|| f.dir.clone());
        let r = run_with(
            "cp",
            &[&format!("{}/bin/runsvc.sh", f.dir), &format!("{}/runsvc.sh", f.dir)],
            &as_user(&f.user, &home).timeout(60),
        );
        if !r.success() {
            return Err(format!("Could not copy runsvc.sh: {}", r.combined().trim()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn runner(dir: &str) -> Runner {
        Runner {
            id: 7,
            site_id: Some(1),
            site_domain: Some("app.example.com".into()),
            name: "build-1".into(),
            github_url: "https://github.com/acme/app".into(),
            labels: "deploy".into(),
            runner_group: String::new(),
            system_user: "appuser".into(),
            dir: dir.into(),
            credential_id: None,
            deploy_token_hash: None,
            adopted: false,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn unit_runs_as_the_site_user_in_its_home() {
        let u = render_unit(
            &runner("/home/appuser/actions-runner/build-1"),
            "/home/appuser",
            "/etc/cloudpanel/runners/7.env",
        );
        assert!(u.contains("User=appuser\n"));
        assert!(u.contains("WorkingDirectory=/home/appuser/actions-runner/build-1\n"));
        assert!(u.contains("ExecStart=/home/appuser/actions-runner/build-1/runsvc.sh\n"));
        assert!(u.contains("KillMode=process\n"));
        assert!(u.contains("NoNewPrivileges=yes\n"));
        assert!(u.contains("ProtectHome=tmpfs\nBindPaths=/home/appuser\nReadWritePaths=/home/appuser\n"));
        assert!(u.contains("EnvironmentFile=-/etc/cloudpanel/runners/7.env\n"));
    }

    #[test]
    fn unit_for_a_runner_outside_its_home_can_write_its_directory() {
        let u = render_unit(&runner("/opt/runner"), "/home/appuser", "/x.env");
        assert!(u.contains("ReadWritePaths=/home/appuser /opt/runner\n"));
    }

    #[test]
    fn env_file_carries_the_deploy_token() {
        let mut c = Config::from_env();
        c.bind_addr = "0.0.0.0:8443".into();
        c.tls_cert = Some("/c".into());
        c.tls_key = Some("/k".into());
        let e = render_env(&c, Some("cpr_abc"));
        assert!(e.contains("CLOUDPANEL_DEPLOY_URL=https://127.0.0.1:8443/api/runner-hook/deploy\n"));
        assert!(e.contains("CLOUDPANEL_DEPLOY_TOKEN=cpr_abc\n"));
        assert!(!render_env(&c, None).contains("TOKEN"));
    }

    #[test]
    fn deploy_tokens_are_random_and_only_their_hash_is_kept() {
        let (a, ha) = new_deploy_token();
        let (b, _) = new_deploy_token();
        assert_ne!(a, b);
        assert!(a.starts_with("cpr_") && a.len() == 68);
        assert_eq!(ha, crate::auth::jwt::token_hash(&a));
        assert!(!ha.contains(&a));
    }

    #[test]
    fn plain_paths_only() {
        assert!(plain_path("/home/u/actions-runner/r-1"));
        assert!(!plain_path("home/u"));
        assert!(!plain_path("/home/u/../root"));
        assert!(!plain_path("/home/u/a b"));
        assert!(!plain_path("/home/u/a\nExecStartPre=/bin/evil"));
        assert!(!plain_path("/home/u/$x"));
    }

    #[test]
    fn api_scope_for_repos_and_orgs() {
        assert_eq!(api_scope("https://github.com/acme/app").unwrap(), "repos/acme/app");
        assert_eq!(api_scope("https://github.com/acme").unwrap(), "orgs/acme");
        assert!(api_scope("https://evil.example/acme").is_err());
    }

    #[test]
    fn workdir_from_an_svc_sh_unit() {
        let unit = "[Service]\nExecStart=/home/u/actions-runner/runsvc.sh\nUser=u\nWorkingDirectory=/home/u/actions-runner\nKillMode=process\n";
        assert_eq!(unit_workdir(unit).as_deref(), Some("/home/u/actions-runner"));
    }

    fn plant(dir: &Path, name: &str, creds: bool) {
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(
            dir.join(".runner"),
            format!("\u{feff}{{\"agentId\":3,\"agentName\":\"{name}\",\"poolId\":1,\"poolName\":\"Default\",\"serverUrl\":\"https://pipelines\",\"gitHubUrl\":\"https://github.com/acme/app\",\"workFolder\":\"_work\"}}"),
        )
        .unwrap();
        if creds {
            std::fs::write(dir.join(".credentials"), "{}").unwrap();
        }
        std::fs::write(dir.join("bin/runsvc.sh"), "#!/bin/bash\n").unwrap();
    }

    #[test]
    fn scan_finds_hand_installed_runners_once_and_skips_managed_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = Config::from_env();
        c.home_dir = tmp.path().join("home");
        c.systemd_dir = tmp.path().join("systemd");
        std::fs::create_dir_all(&c.systemd_dir).unwrap();
        let a = c.home_dir.join("alice/actions-runner");
        let b = c.home_dir.join("bob/runners/one");
        let managed = c.home_dir.join("bob/runners/two");
        let unregistered = c.home_dir.join("carol/actions-runner");
        let deep = c.home_dir.join("dave/a/b/c/d/runner");
        plant(&a, "alice-1", true);
        plant(&b, "bob-1", true);
        plant(&managed, "bob-2", true);
        plant(&unregistered, "carol-1", false);
        plant(&deep, "too-deep", true);
        std::fs::write(
            c.systemd_dir.join("actions.runner.acme-app.alice-1.service"),
            format!("[Service]\nWorkingDirectory={}\n", a.display()),
        )
        .unwrap();

        let found = scan(&c, &[managed.to_string_lossy().into_owned()]);
        let names: Vec<&str> = found.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(names.contains(&"alice-1") && names.contains(&"bob-1") && names.contains(&"carol-1"));
        let alice = found.iter().find(|f| f.name == "alice-1").unwrap();
        assert_eq!(alice.unit.as_deref(), Some("actions.runner.acme-app.alice-1"));
        assert_eq!(alice.github_url, "https://github.com/acme/app");
        let carol = found.iter().find(|f| f.name == "carol-1").unwrap();
        assert!(carol.problem.as_deref().unwrap().contains(".credentials"), "{carol:?}");
    }

    #[cfg(unix)]
    #[test]
    fn scan_does_not_follow_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = Config::from_env();
        c.home_dir = tmp.path().join("home");
        c.systemd_dir = tmp.path().join("systemd");
        let elsewhere = tmp.path().join("elsewhere/runner");
        plant(&elsewhere, "hidden", true);
        std::fs::create_dir_all(c.home_dir.join("eve")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("elsewhere"), c.home_dir.join("eve/link")).unwrap();
        assert!(scan(&c, &[]).is_empty());
    }
}
