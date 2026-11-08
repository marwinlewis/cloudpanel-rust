//! PHP sites: one PHP-FPM pool per site, running as the site's Linux user. PHP is optional and is
//! chosen when installing the panel (`CLOUDPANEL_PHP=1`).

use super::cmd::{run_with, CmdOpts};
use crate::db::models::Site;
use crate::fsutil::write_atomic;
use std::fs;
use std::path::PathBuf;

fn php_root() -> PathBuf {
    PathBuf::from(std::env::var("CLOUDPANEL_PHP_DIR").unwrap_or_else(|_| "/etc/php".into()))
}

/// A version as `/etc/php` names it: `8.4`. It ends up in paths and unit names.
pub fn valid_version(v: &str) -> bool {
    matches!(v.split_once('.'), Some((a, b))
        if !a.is_empty() && !b.is_empty()
            && a.chars().all(|c| c.is_ascii_digit())
            && b.chars().all(|c| c.is_ascii_digit()))
}

fn version_key(v: &str) -> (u32, u32) {
    let (a, b) = v.split_once('.').unwrap_or((v, "0"));
    (a.parse().unwrap_or(0), b.parse().unwrap_or(0))
}

/// Installed PHP-FPM versions, newest first.
pub fn installed_versions() -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(php_root())
        .map(|dir| {
            dir.flatten()
                .filter(|e| e.path().join("fpm").is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|v| valid_version(v))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
    out
}

pub fn socket_path(domain: &str) -> String {
    format!("/run/php/cloudpanel-{domain}.sock")
}

fn pool_path(version: &str, domain: &str) -> PathBuf {
    php_root()
        .join(version)
        .join("fpm")
        .join("pool.d")
        .join(format!("{domain}.conf"))
}

/// nginx connects to the socket as `www-data`, the user Debian's nginx runs as. CE's nginx runs
/// as root, so this works on a migrated server too.
pub fn render_pool(domain: &str, user: &str) -> String {
    format!(
        "; Managed by CloudPanel - changes will be overwritten\n\
         [{domain}]\n\
         user = {user}\n\
         group = {user}\n\
         listen = {socket}\n\
         listen.owner = www-data\n\
         listen.group = www-data\n\
         listen.mode = 0660\n\
         pm = ondemand\n\
         pm.max_children = 20\n\
         pm.process_idle_timeout = 10s\n\
         pm.max_requests = 500\n\
         request_terminate_timeout = 300s\n\
         catch_workers_output = yes\n\
         php_admin_value[error_log] = /home/{user}/logs/php-error.log\n\
         php_admin_flag[log_errors] = on\n",
        socket = socket_path(domain),
    )
}

fn fpm_unit(version: &str) -> String {
    format!("php{version}-fpm")
}

fn systemctl(action: &str, unit: &str) -> Result<(), String> {
    let r = run_with("systemctl", &[action, unit], &CmdOpts::default().timeout(60));
    if r.missing {
        return Ok(());
    }
    r.into_result("systemctl", "").map(|_| ())
}

/// Write the site's pool and load it. A pool PHP-FPM rejects is put back the way it was, because
/// one bad file stops PHP-FPM from starting, and every other site on that version with it.
pub fn apply(site: &Site) -> Result<(), String> {
    let version = site.php_version.as_deref().ok_or("This site has no PHP version")?;
    if !valid_version(version) {
        return Err(format!("Invalid PHP version: {version}"));
    }
    let path = pool_path(version, &site.domain);
    let previous = fs::read(&path).ok();
    write_atomic(&path, render_pool(&site.domain, &site.system_user).as_bytes(), 0o644)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    let test = run_with(&format!("php-fpm{version}"), &["-t"], &CmdOpts::default().timeout(30));
    if !test.missing && !test.success() {
        match previous {
            Some(p) => {
                let _ = write_atomic(&path, &p, 0o644);
            }
            None => {
                let _ = fs::remove_file(&path);
            }
        }
        return Err(format!("PHP-FPM rejected the pool: {}", test.combined().trim()));
    }
    // A reload brings the new pool up without dropping requests on the others.
    systemctl("reload", &fpm_unit(version)).or_else(|_| systemctl("restart", &fpm_unit(version)))
}

/// Remove the site's pool. A site without a valid version has none.
pub fn remove(site: &Site) -> Result<(), String> {
    let Some(version) = site.php_version.as_deref().filter(|v| valid_version(v)) else {
        return Ok(());
    };
    let path = pool_path(version, &site.domain);
    if path.symlink_metadata().is_err() {
        return Ok(());
    }
    fs::remove_file(&path).map_err(|e| format!("Failed to remove {}: {e}", path.display()))?;
    systemctl("reload", &fpm_unit(version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_strict_because_they_reach_paths_and_unit_names() {
        for good in ["8.4", "7.1", "10.12"] {
            assert!(valid_version(good), "{good}");
        }
        for bad in ["", "8", "8.", ".4", "8.4.1", "../8", "8.4/../..", "8.4 "] {
            assert!(!valid_version(bad), "{bad}");
        }
    }

    #[test]
    fn newest_version_sorts_first_numerically() {
        let mut v = vec!["7.4".to_string(), "8.10".to_string(), "8.4".to_string()];
        v.sort_by_key(|x| std::cmp::Reverse(version_key(x)));
        assert_eq!(v, ["8.10", "8.4", "7.4"]);
    }

    #[test]
    fn pool_runs_as_the_site_user_on_its_own_socket() {
        let p = render_pool("shop.example.com", "shop");
        assert!(p.contains("[shop.example.com]\n"));
        assert!(p.contains("user = shop\ngroup = shop\n"));
        assert!(p.contains("listen = /run/php/cloudpanel-shop.example.com.sock\n"));
        assert!(p.contains("listen.owner = www-data\n"));
        assert!(p.contains("listen.mode = 0660\n"));
    }
}
