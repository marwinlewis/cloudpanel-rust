//! A real (Let's Encrypt) certificate for the panel itself, hot-reloaded into the
//! running TLS listener.

use crate::config::Config;
use crate::db;
use crate::state::SharedState;
use serde::{Deserialize, Serialize};
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
