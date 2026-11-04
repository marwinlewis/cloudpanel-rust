//! Linux accounts for sites: the site owner plus extra SSH/SFTP users that share its
//! group and home. Keys live in root-owned files under `/etc/ssh/cloudpanel_keys/<user>`
//! so a compromised site cannot rewrite its own authorized keys.

use super::cmd::{run_host, run_with, CmdOpts};
use crate::config::Config;
use crate::fsutil::write_atomic;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub const USERS_GROUP: &str = "cloudpanel-users";
pub const SFTP_GROUP: &str = "cloudpanel-sftp";
const DROPIN_FILE: &str = "cloudpanel.conf";

/// Run a host tool. Missing tools are tolerated only in local development.
fn sys(program: &str, args: &[&str], opts: &CmdOpts) -> Result<String, String> {
    let r = run_host(program, args, opts);
    if r.missing {
        if cfg!(windows) {
            warn!("{program} not available; skipping (development)");
            return Ok(String::new());
        }
        return Err(format!("{program} is not installed on this server"));
    }
    r.into_result(program, "")
}

pub fn user_exists(user: &str) -> bool {
    if cfg!(windows) {
        return false;
    }
    fs::read_to_string("/etc/passwd")
        .map(|p| p.lines().any(|l| l.split(':').next() == Some(user)))
        .unwrap_or(false)
}

pub fn group_exists(group: &str) -> bool {
    fs::read_to_string("/etc/group")
        .map(|p| p.lines().any(|l| l.split(':').next() == Some(group)))
        .unwrap_or(false)
}

fn ensure_groups() -> Result<(), String> {
    for g in [USERS_GROUP, SFTP_GROUP] {
        if cfg!(unix) && !group_exists(g) {
            sys("groupadd", &["-f", g], &CmdOpts::default())?;
        }
    }
    Ok(())
}

/// Pick a free account name based on `base` (appends digits when taken).
pub fn unique_name(base: &str, taken: impl Fn(&str) -> bool) -> String {
    if !user_exists(base) && !taken(base) {
        return base.to_string();
    }
    for i in 2..1000 {
        let mut b = base.to_string();
        b.truncate(28);
        let cand = format!("{b}{i}");
        if !user_exists(&cand) && !taken(&cand) {
            return cand;
        }
    }
    format!("{}{}", &base[..base.len().min(20)], rand_suffix())
}

fn rand_suffix() -> String {
    crate::auth::random_password(6).to_ascii_lowercase()
}

/// Layout of a site's home directory.
pub struct SiteHome {
    pub home: PathBuf,
    pub htdocs: PathBuf,
    pub logs: PathBuf,
    pub databases: PathBuf,
}

pub fn site_home(config: &Config, user: &str, domain: &str) -> SiteHome {
    let home = crate::validate::absolute(&config.home_dir).join(user);
    SiteHome {
        htdocs: home.join("htdocs").join(domain),
        logs: home.join("logs"),
        databases: home.join("databases"),
        home,
    }
}

/// Create the site owner account and its directory layout.
pub fn create_site_user(config: &Config, user: &str, domain: &str) -> Result<SiteHome, String> {
    ensure_groups()?;
    let layout = site_home(config, user, domain);
    let home = layout.home.to_string_lossy().into_owned();
    if !user_exists(user) {
        sys(
            "useradd",
            &[
                "--create-home",
                "--home-dir",
                &home,
                "--shell",
                "/bin/bash",
                "--user-group",
                "--groups",
                USERS_GROUP,
                "--",
                user,
            ],
            &CmdOpts::default(),
        )?;
        info!("created system user {user}");
    }
    for d in [&layout.home, &layout.htdocs, &layout.logs, &layout.databases] {
        fs::create_dir_all(d).map_err(|e| format!("create {}: {e}", d.display()))?;
    }
    crate::fsutil::set_mode(&layout.home, 0o750).map_err(|e| e.to_string())?;
    chown_recursive(&layout.home, user, user)?;
    // Let nginx read static files through the site group.
    if cfg!(unix) {
        let web = if user_exists("www-data") { "www-data" } else { "nginx" };
        if user_exists(web) {
            let _ = sys("usermod", &["-a", "-G", user, "--", web], &CmdOpts::default());
        }
    }
    Ok(layout)
}

/// Extra SSH/SFTP account sharing the site owner's group and home.
pub fn create_ssh_user(owner: &str, user: &str, home: &Path, sftp_only: bool) -> Result<(), String> {
    ensure_groups()?;
    let home = home.to_string_lossy().into_owned();
    let groups = if sftp_only {
        format!("{USERS_GROUP},{SFTP_GROUP}")
    } else {
        USERS_GROUP.to_string()
    };
    let shell = if sftp_only { "/usr/sbin/nologin" } else { "/bin/bash" };
    sys(
        "useradd",
        &[
            "--no-create-home",
            "--home-dir",
            &home,
            "--shell",
            shell,
            "--gid",
            owner,
            "--groups",
            &groups,
            "--",
            user,
        ],
        &CmdOpts::default(),
    )?;
    info!("created ssh user {user} for {owner}");
    Ok(())
}

/// Switch an account between full SSH and SFTP-only.
pub fn set_sftp_only(user: &str, sftp_only: bool) -> Result<(), String> {
    ensure_groups()?;
    if sftp_only {
        sys("gpasswd", &["-a", user, SFTP_GROUP], &CmdOpts::default())?;
        sys(
            "usermod",
            &["--shell", "/usr/sbin/nologin", "--", user],
            &CmdOpts::default(),
        )?;
    } else {
        sys("gpasswd", &["-d", user, SFTP_GROUP], &CmdOpts::default())?;
        sys("usermod", &["--shell", "/bin/bash", "--", user], &CmdOpts::default())?;
    }
    Ok(())
}

/// Set a password via `chpasswd` on stdin (never on the command line).
pub fn set_password(user: &str, password: &str) -> Result<(), String> {
    if password.contains(['\n', '\r', ':']) {
        return Err("Password cannot contain ':' or newlines".into());
    }
    sys(
        "chpasswd",
        &[],
        &CmdOpts::default().stdin(format!("{user}:{password}\n")),
    )
    .map(|_| ())
}

pub fn delete_user(user: &str, remove_home: bool) -> Result<(), String> {
    if cfg!(unix) && !user_exists(user) {
        return Ok(());
    }
    // Stop anything still running as the user first.
    let _ = run_with("pkill", &["-u", user], &CmdOpts::default().timeout(10));
    let mut args = vec![];
    if remove_home {
        args.push("--remove");
    }
    args.push("--");
    args.push(user);
    sys("userdel", &args, &CmdOpts::default())?;
    info!("deleted system user {user}");
    Ok(())
}

pub fn chown_recursive(path: &Path, user: &str, group: &str) -> Result<(), String> {
    if cfg!(windows) {
        return Ok(());
    }
    let p = path.to_string_lossy();
    let r = run_with(
        "chown",
        &["-R", "--no-dereference", &format!("{user}:{group}"), "--", &p],
        &CmdOpts::default().timeout(300),
    );
    r.into_result("chown", "chown is not installed").map(|_| ())
}

/// Chown a single path (no recursion, no symlink following).
pub fn chown_one(path: &Path, user: &str) -> Result<(), String> {
    if cfg!(windows) {
        return Ok(());
    }
    let p = path.to_string_lossy();
    run_with(
        "chown",
        &["--no-dereference", &format!("{user}:{user}"), "--", &p],
        &CmdOpts::default(),
    )
    .into_result("chown", "chown is not installed")
    .map(|_| ())
}

fn keys_dir(config: &Config) -> PathBuf {
    config
        .sshd_config_dir
        .parent()
        .map(|p| p.join("cloudpanel_keys"))
        .unwrap_or_else(|| PathBuf::from("/etc/ssh/cloudpanel_keys"))
}

/// Rewrite the root-owned authorized_keys file for `user`.
pub fn write_authorized_keys(config: &Config, user: &str, keys: &[String]) -> Result<(), String> {
    let dir = keys_dir(config);
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    crate::fsutil::set_mode(&dir, 0o755).map_err(|e| e.to_string())?;
    let path = dir.join(user);
    if keys.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    let mut body = String::from("# Managed by CloudPanel - changes will be overwritten\n");
    for k in keys {
        body.push_str(k);
        body.push('\n');
    }
    write_atomic(&path, body.as_bytes(), 0o644).map_err(|e| format!("write {}: {e}", path.display()))
}

pub fn remove_authorized_keys(config: &Config, user: &str) {
    let _ = fs::remove_file(keys_dir(config).join(user));
}

pub fn render_sshd_dropin(keys_dir: &Path) -> String {
    format!(
        "# Managed by CloudPanel - changes will be overwritten\n\
         Match Group {USERS_GROUP}\n    \
             AuthorizedKeysFile .ssh/authorized_keys {}/%u\n\
         Match Group {SFTP_GROUP}\n    \
             ForceCommand internal-sftp\n    \
             AllowTcpForwarding no\n    \
             X11Forwarding no\n    \
             PermitTTY no\n\
         Match all\n",
        keys_dir.display()
    )
}

/// Install the sshd drop-in once; validated with `sshd -t` and rolled back on failure.
pub fn ensure_sshd_dropin(config: &Config) -> Result<(), String> {
    let dir = &config.sshd_config_dir;
    let path = dir.join(DROPIN_FILE);
    let body = render_sshd_dropin(&keys_dir(config));
    let previous = fs::read_to_string(&path).ok();
    if previous.as_deref() == Some(body.as_str()) {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    write_atomic(&path, body.as_bytes(), 0o644).map_err(|e| format!("write {}: {e}", path.display()))?;
    let test = run_with("sshd", &["-t"], &CmdOpts::default());
    if !test.missing && !test.success() {
        match previous {
            Some(p) => {
                let _ = write_atomic(&path, p.as_bytes(), 0o644);
            }
            None => {
                let _ = fs::remove_file(&path);
            }
        }
        return Err(format!("sshd rejected the configuration: {}", test.combined().trim()));
    }
    if !test.missing {
        for unit in ["ssh", "sshd"] {
            if run_with("systemctl", &["reload", unit], &CmdOpts::default()).success() {
                break;
            }
        }
    }
    info!("installed sshd drop-in {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropin_contains_match_blocks() {
        let s = render_sshd_dropin(Path::new("/etc/ssh/cloudpanel_keys"));
        assert!(s.contains("Match Group cloudpanel-sftp"));
        assert!(s.contains("ForceCommand internal-sftp"));
        assert!(s.contains("AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/cloudpanel_keys/%u"));
        assert!(s.trim_end().ends_with("Match all"));
    }

    #[test]
    fn unique_names() {
        assert_eq!(unique_name("shop", |n| n == "shop"), "shop2");
        assert_eq!(unique_name("blog", |_| false), "blog");
    }
}
