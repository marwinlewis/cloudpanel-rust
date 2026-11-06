//! A real (Let's Encrypt) certificate for the panel itself, hot-reloaded into the
//! running TLS listener.

use super::nginx::{NginxService, PanelVhost};
use crate::config::Config;
use crate::db;
use crate::db::models::Site;
use crate::state::SharedState;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

pub const SETTING: &str = "panel_tls";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PanelTls {
    pub hostname: String,
    pub cert: String,
    pub key: String,
}

pub fn load(conn: &rusqlite::Connection) -> Option<PanelTls> {
    db::get_setting(conn, SETTING)
        .ok()?
        .and_then(|v| serde_json::from_str(&v).ok())
}

/// Cert/key the panel should serve: the stored Let's Encrypt pair when its files exist,
/// otherwise the paths from the environment.
pub fn effective_paths(config: &Config, stored: Option<&PanelTls>) -> Option<(PathBuf, PathBuf)> {
    if let Some(t) = stored {
        if Path::new(&t.cert).exists() && Path::new(&t.key).exists() {
            return Some((PathBuf::from(&t.cert), PathBuf::from(&t.key)));
        }
    }
    match (&config.tls_cert, &config.tls_key) {
        (Some(c), Some(k)) => Some((c.clone(), k.clone())),
        _ => None,
    }
}

/// Where nginx reaches the panel. None when the bind address can't be understood.
pub fn upstream(config: &Config, tls: bool) -> Option<String> {
    let addr: SocketAddr = config.bind_addr.parse().ok()?;
    let scheme = if tls { "https" } else { "http" };
    let port = addr.port();
    Some(match addr.ip() {
        ip if ip.is_unspecified() && ip.is_ipv6() => format!("{scheme}://[::1]:{port}"),
        ip if ip.is_unspecified() => format!("{scheme}://127.0.0.1:{port}"),
        IpAddr::V6(ip) => format!("{scheme}://[{ip}]:{port}"),
        IpAddr::V4(ip) => format!("{scheme}://{ip}:{port}"),
    })
}

/// A site already answering on this hostname, if any. nginx would pick one of the two
/// server blocks at random, so they can't share it.
pub fn site_on_hostname(sites: &[Site], hostname: &str) -> Option<String> {
    sites
        .iter()
        .find(|s| s.server_names().iter().any(|n| n == hostname))
        .map(|s| s.domain.clone())
}

/// Serve the panel's hostname on port 443 through nginx. Certificates renew in place, and
/// certbot's hook reloads nginx afterwards.
pub fn apply_vhost(config: &Config, stored: &PanelTls, tls: bool, secret: &str) -> Result<(), String> {
    let upstream = upstream(config, tls).ok_or("The panel's bind address could not be read")?;
    NginxService::apply_panel_vhost(
        config,
        &PanelVhost {
            hostname: stored.hostname.clone(),
            cert: stored.cert.clone(),
            key: stored.key.clone(),
            upstream,
            secret: secret.to_string(),
        },
    )
}

/// At startup, set up the nginx site for a hostname configured before this feature existed,
/// so upgrading is enough. Failing here must not stop the panel, which is still on its own
/// port and is how anyone would fix the problem.
pub fn sync_vhost(config: &Config, conn: &rusqlite::Connection, tls: bool, secret: &str) {
    let Some(stored) = load(conn) else {
        return;
    };
    if !(Path::new(&stored.cert).exists() && Path::new(&stored.key).exists()) {
        tracing::warn!(
            "panel certificate for {} is missing; not serving it on port 443",
            stored.hostname
        );
        return;
    }
    let sites = db::list_sites(conn).unwrap_or_default();
    if let Some(site) = site_on_hostname(&sites, &stored.hostname) {
        tracing::warn!(
            "not serving the panel on {} through nginx: the site {site} answers on that name",
            stored.hostname
        );
        return;
    }
    if let Err(e) = apply_vhost(config, &stored, tls, secret) {
        tracing::warn!("could not serve the panel on {} through nginx: {e}", stored.hostname);
    }
}

/// Swap the live listener's certificate. Returns false when the panel runs without TLS.
pub async fn reload(state: &SharedState, cert: &Path, key: &Path) -> Result<bool, String> {
    let cfg = state.tls.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match cfg {
        Some(c) => {
            c.reload_from_pem_file(cert, key)
                .await
                .map_err(|e| format!("Failed to load the new certificate: {e}"))?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Scheduler hook: pick up certbot renewals.
pub fn reload_if_changed(state: &SharedState) {
    let Ok(conn) = state.pool.get() else { return };
    let stored = load(&conn);
    drop(conn);
    if stored.is_none() {
        return;
    }
    let Some((cert, key)) = effective_paths(&state.config, stored.as_ref()) else {
        return;
    };
    let st = state.clone();
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        if let Err(e) = h.block_on(reload(&st, &cert, &key)) {
            tracing::warn!("panel certificate reload: {e}");
        }
    }
}

/// Does `host` resolve to one of this server's addresses?
pub async fn resolves_here(host: &str) -> Result<(), String> {
    let addrs: Vec<std::net::IpAddr> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|e| format!("{host} does not resolve: {e}"))?
        .map(|a| a.ip())
        .collect();
    let local = local_ips();
    if local.is_empty() || addrs.iter().any(|a| local.contains(a)) {
        return Ok(());
    }
    Err(format!(
        "{host} points to {}, which is not an address of this server",
        addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
    ))
}

fn local_ips() -> Vec<std::net::IpAddr> {
    let r = super::cmd::run_with("ip", &["-j", "addr"], &super::cmd::CmdOpts::default().timeout(5));
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&r.stdout) else {
        return vec![];
    };
    let mut out = Vec::new();
    for iface in v.as_array().into_iter().flatten() {
        for a in iface["addr_info"].as_array().into_iter().flatten() {
            if let Some(ip) = a["local"].as_str().and_then(|s| s.parse().ok()) {
                out.push(ip);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::nginx::test_site;

    #[test]
    fn upstream_follows_the_bind_address_and_scheme() {
        let mut c = Config::from_env();
        c.bind_addr = "0.0.0.0:8443".into();
        assert_eq!(upstream(&c, true).unwrap(), "https://127.0.0.1:8443");
        assert_eq!(upstream(&c, false).unwrap(), "http://127.0.0.1:8443");
        c.bind_addr = "10.0.0.5:9000".into();
        assert_eq!(upstream(&c, true).unwrap(), "https://10.0.0.5:9000");
        c.bind_addr = "[::]:8443".into();
        assert_eq!(upstream(&c, true).unwrap(), "https://[::1]:8443");
        c.bind_addr = "not an address".into();
        assert!(upstream(&c, true).is_none());
    }

    #[test]
    fn finds_sites_answering_on_the_hostname() {
        let mut s = test_site("static");
        s.domain = "example.com".into();
        s.include_www = true;
        let sites = vec![s];
        assert_eq!(site_on_hostname(&sites, "example.com").unwrap(), "example.com");
        assert_eq!(site_on_hostname(&sites, "www.example.com").unwrap(), "example.com");
        assert!(site_on_hostname(&sites, "cpanel.example.com").is_none());
    }
}
