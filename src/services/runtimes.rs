//! Language runtimes for app sites. Node.js sites need a system-wide `node`/`npm` (the
//! app units only search /usr/local/bin, /usr/bin and the site's own bin dirs), so the
//! panel installs Node.js LTS from the NodeSource apt repository when it is missing.

use super::cmd::{run_host_streaming, CmdOpts};
use crate::config::Config;
use std::path::Path;
use std::sync::Mutex;

/// Node.js major version installed by the panel (and by install.sh).
pub const NODE_MAJOR: u32 = 22;

/// Serialises installs so two site creations can't run apt at the same time.
static INSTALL_LOCK: Mutex<()> = Mutex::new(());

/// Where app units (and the panel) look for `node`.
const NODE_PATHS: &[&str] = &["/usr/bin/node", "/usr/local/bin/node"];

pub fn node_installed() -> bool {
    NODE_PATHS.iter().any(|p| Path::new(p).is_file()) || super::cmd::which("node")
}

/// True when the panel manages a real Debian/Ubuntu host (not development or tests),
/// so installing system packages is both possible and expected.
pub fn can_install(config: &Config) -> bool {
    cfg!(target_os = "linux")
        && config.systemd_dir.starts_with("/etc/systemd")
        && Path::new("/usr/bin/apt-get").is_file()
}

/// Whether a Node.js site created now needs the runtime installed first.
pub fn node_needed(config: &Config) -> bool {
    can_install(config) && !node_installed()
}

/// Static script run as root outside the panel sandbox; it takes no user input.
fn nodesource_script() -> String {
    format!(
        "set -eu\n\
         export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a\n\
         command -v gpg >/dev/null 2>&1 || {{ apt-get update -q; apt-get install -y -q --no-install-recommends gnupg; }}\n\
         command -v curl >/dev/null 2>&1 || {{ apt-get update -q; apt-get install -y -q --no-install-recommends curl ca-certificates; }}\n\
         install -m 0755 -d /etc/apt/keyrings\n\
         curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg\n\
         chmod a+r /etc/apt/keyrings/nodesource.gpg\n\
         echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_{NODE_MAJOR}.x nodistro main' > /etc/apt/sources.list.d/nodesource.list\n\
         apt-get update -q\n\
         apt-get install -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold nodejs\n\
         node --version\n\
         npm --version\n"
    )
}

/// Install Node.js if it is missing. Logs progress to `log`; a no-op when already present.
pub fn ensure_nodejs(config: &Config, log: &dyn Fn(&str)) -> Result<(), String> {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if node_installed() {
        return Ok(());
    }
    if !can_install(config) {
        return Err("Node.js is not installed and this system has no apt-get; install Node.js manually".into());
    }
    log(&format!(
        "Node.js is not installed; installing Node.js {NODE_MAJOR} LTS (NodeSource)..."
    ));
    let script = nodesource_script();
    let r = run_host_streaming(
        "/bin/sh",
        &["-c", &script],
        &CmdOpts::default().timeout(30 * 60),
        &mut |l, _| log(l),
    );
    if r.missing {
        return Err("/bin/sh is not available".into());
    }
    if !r.success() || !node_installed() {
        return Err(format!(
            "Node.js installation failed (exit code {})",
            r.code.unwrap_or(-1)
        ));
    }
    log("Node.js installed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_pins_major_version() {
        let s = nodesource_script();
        assert!(s.contains("node_22.x nodistro main"));
        assert!(s.starts_with("set -eu\n"));
    }
}
