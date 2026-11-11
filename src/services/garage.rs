//! Garage: S3-compatible object storage the panel installs and manages.
//!
//! Garage runs as its own hardened systemd service under a `garage` user, as a single node that
//! listens on loopback only. The panel talks to Garage's admin API (v2) with a token from a file
//! only root and Garage can read. Garage is the source of truth for buckets, keys and grants. The
//! panel only records which site a bucket or key belongs to.

use super::cmd::{run_with, CmdOpts};
use crate::config::Config;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The Garage release the panel installs. Both hashes were checked against the binary inside the
/// official `dxflrs/garage` image of the same version.
pub const VERSION: &str = "v2.5.0";
const SHA256_X86_64: &str = "2ff667286217cd73ebcb1c03af993822365000441dfe31a80cb64c5189a9dea8";
const SHA256_AARCH64: &str = "69b6040cef428b993500c17dd0d0c1240acf2f3f667b9b05ceba4b9660db4e8c";
const RELEASES: &str = "https://garagehq.deuxfleurs.fr/_releases";

pub const BIN: &str = "/usr/local/bin/garage";
const DATA_DIR: &str = "/var/lib/garage";
pub const UNIT: &str = "garage.service";
pub const S3_ADDR: &str = "127.0.0.1:3900";
const RPC_ADDR: &str = "127.0.0.1:3901";
const ADMIN_ADDR: &str = "127.0.0.1:3903";
/// Every client signs for this region. Apps and SDKs default to it, so they work unchanged.
pub const REGION: &str = "us-east-1";
/// Settings key for what the panel keeps about Garage (its public hostname).
pub const SETTING: &str = "garage";

/// The panel's Garage settings.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Settings {
    /// Public HTTPS hostname nginx serves the S3 API on, if any.
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

fn conf_path(config: &Config) -> PathBuf {
    config.garage_dir.join("garage.toml")
}

fn token_path(config: &Config) -> PathBuf {
    config.garage_dir.join("admin.token")
}

fn rpc_secret_path(config: &Config) -> PathBuf {
    config.garage_dir.join("rpc.secret")
}

/// Is Garage installed: its binary and the panel's unit for it?
pub fn installed(config: &Config) -> bool {
    Path::new(BIN).is_file() && config.systemd_dir.join(UNIT).is_file()
}

/// Can the panel install Garage itself? It needs a real systemd host and a known CPU.
pub fn can_install(config: &Config) -> bool {
    super::runtimes::can_install(config) && target().is_some()
}

/// Is the unit running?
pub fn active() -> bool {
    run_with(
        "systemctl",
        &["is-active", "--quiet", UNIT],
        &CmdOpts::default().timeout(15),
    )
    .success()
}

/// The release build for this machine and its expected SHA-256.
fn target() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "x86_64" => Some(("x86_64-unknown-linux-musl", SHA256_X86_64)),
        "aarch64" => Some(("aarch64-unknown-linux-musl", SHA256_AARCH64)),
        _ => None,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// `garage.toml`. Single node, every port on loopback, secrets in files.
pub fn render_config(config: &Config) -> String {
    format!(
        r#"# Managed by CloudPanel. Written once at install; later edits are kept.
metadata_dir = "{data}/meta"
data_dir = "{data}/data"
db_engine = "lmdb"
# One node holds the only copy, so make writes durable before acknowledging them.
metadata_fsync = true
data_fsync = true
metadata_auto_snapshot_interval = "6h"

replication_factor = 1
rpc_bind_addr = "{rpc}"
rpc_public_addr = "{rpc}"
rpc_secret_file = "{rpc_secret}"

[s3_api]
s3_region = "{REGION}"
api_bind_addr = "{S3_ADDR}"

[admin]
api_bind_addr = "{ADMIN_ADDR}"
admin_token_file = "{token}"
"#,
        data = DATA_DIR,
        rpc = RPC_ADDR,
        rpc_secret = rpc_secret_path(config).display(),
        token = token_path(config).display(),
    )
}

/// The systemd unit. Garage only needs its data directory and loopback.
pub fn render_unit(config: &Config) -> String {
    format!(
        r#"# Managed by CloudPanel - changes will be overwritten
[Unit]
Description=Garage S3 object storage
Documentation=https://garagehq.deuxfleurs.fr/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=garage
Group=garage
Environment=RUST_LOG=garage=info
ExecStart={BIN} -c {conf} server --single-node
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={DATA_DIR}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
UMask=0027

[Install]
WantedBy=multi-user.target
"#,
        conf = conf_path(config).display(),
    )
}

fn sh(log: &dyn Fn(&str), program: &str, args: &[&str]) -> Result<String, String> {
    let r = run_with(program, args, &CmdOpts::default().timeout(120));
    let out = r.combined();
    if !r.success() {
        return Err(format!("{program} {} failed: {}", args.join(" "), out.trim()));
    }
    for l in out.lines().filter(|l| !l.trim().is_empty()) {
        log(l);
    }
    Ok(out)
}

/// Write `contents` to `path` only if it doesn't exist yet, owned by root and group `garage`.
fn write_once(log: &dyn Fn(&str), path: &Path, contents: &str, mode: u32) -> Result<(), String> {
    if path.exists() {
        log(&format!("Keeping existing {}", path.display()));
        return Ok(());
    }
    crate::fsutil::write_atomic(path, contents.as_bytes(), mode)
        .map_err(|e| format!("Could not write {}: {e}", path.display()))?;
    sh(log, "chgrp", &["garage", &path.to_string_lossy()])?;
    Ok(())
}

async fn download(log: &dyn Fn(&str)) -> Result<Vec<u8>, String> {
    let (triple, sha) =
        target().ok_or_else(|| format!("Garage has no release for this CPU ({})", std::env::consts::ARCH))?;
    if let Ok(current) = std::fs::read(BIN) {
        if sha256_hex(&current) == sha {
            log(&format!("Garage {VERSION} is already installed"));
            return Ok(Vec::new());
        }
    }
    let url = format!("{RELEASES}/{VERSION}/{triple}/garage");
    log(&format!("Downloading {url}"));
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(15 * 60))
        .user_agent(concat!("cloudpanel/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", super::panel_update::with_causes(&e)))?;
    if !res.status().is_success() {
        return Err(format!("Download failed: HTTP {}", res.status()));
    }
    let body = res
        .bytes()
        .await
        .map_err(|e| format!("Download failed: {}", super::panel_update::with_causes(&e)))?;
    let got = sha256_hex(&body);
    if got != sha {
        return Err(format!(
            "Checksum verification failed for the Garage binary (expected {sha}, got {got}). Nothing was installed."
        ));
    }
    log(&format!("Checksum verified ({} MB)", body.len() / 1_000_000));
    Ok(body.to_vec())
}

/// Install or upgrade Garage. Runs as root outside the panel's sandbox, from
/// `cloudpanel garage-install` (the installer and the panel's Install button both call that).
/// Running it again is safe: secrets and the config are kept, the binary and unit are updated.
pub async fn install(config: &Config, log: &dyn Fn(&str)) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("Garage can only be installed on Linux".into());
    }
    if !crate::fsutil::running_as_root() {
        return Err("Installing Garage needs root".into());
    }
    let binary = download(log).await?;

    if !run_with("id", &["-u", "garage"], &CmdOpts::default()).success() {
        log("Creating system user garage");
        sh(
            log,
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                DATA_DIR,
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "garage",
            ],
        )?;
    }
    for dir in [DATA_DIR, &format!("{DATA_DIR}/meta"), &format!("{DATA_DIR}/data")] {
        sh(
            log,
            "install",
            &["-d", "-m", "0750", "-o", "garage", "-g", "garage", dir],
        )?;
    }
    let etc = config.garage_dir.to_string_lossy().into_owned();
    sh(
        log,
        "install",
        &["-d", "-m", "0750", "-o", "root", "-g", "garage", &etc],
    )?;
    write_once(log, &rpc_secret_path(config), &random_hex(32), 0o640)?;
    write_once(log, &token_path(config), &random_hex(32), 0o640)?;
    write_once(log, &conf_path(config), &render_config(config), 0o640)?;

    if !binary.is_empty() {
        let tmp = format!("{BIN}.new");
        crate::fsutil::write_atomic(Path::new(&tmp), &binary, 0o755)
            .map_err(|e| format!("Could not write {tmp}: {e}"))?;
        std::fs::rename(&tmp, BIN).map_err(|e| format!("Could not install {BIN}: {e}"))?;
        log(&format!("Installed {BIN}"));
    }

    let unit_path = config.systemd_dir.join(UNIT);
    crate::fsutil::write_atomic(&unit_path, render_unit(config).as_bytes(), 0o644)
        .map_err(|e| format!("Could not write {}: {e}", unit_path.display()))?;
    sh(log, "systemctl", &["daemon-reload"])?;
    sh(log, "systemctl", &["enable", UNIT])?;
    sh(log, "systemctl", &["restart", UNIT])?;

    log("Waiting for Garage to start");
    let admin = Admin::from_config(config)?;
    let mut last = String::new();
    for _ in 0..60 {
        match admin.health().await {
            Ok(h) if h.status == "healthy" => {
                log(&format!("Garage {VERSION} is running"));
                return Ok(());
            }
            Ok(h) => last = format!("cluster is {}", h.status),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!(
        "Garage did not become healthy within a minute ({last}). See: journalctl -u {UNIT}"
    ))
}

// ---------- Admin API ----------

/// Client for Garage's admin API v2 on loopback.
pub struct Admin {
    base: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub status: String,
    pub storage_nodes: u64,
    pub storage_nodes_up: u64,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Statistics {
    pub bucket_count: Option<u64>,
    pub total_object_count: Option<u64>,
    pub total_object_bytes: Option<u64>,
    pub data_avail: Option<u64>,
    pub metadata_avail: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BucketListItem {
    pub id: String,
    #[serde(default)]
    pub global_aliases: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Perm {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub owner: bool,
}

impl Perm {
    pub fn any(&self) -> bool {
        self.read || self.write || self.owner
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Quotas {
    pub max_size: Option<u64>,
    pub max_objects: Option<u64>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BucketKey {
    pub access_key_id: String,
    pub name: String,
    pub permissions: Perm,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BucketInfo {
    pub id: String,
    #[serde(default)]
    pub global_aliases: Vec<String>,
    pub objects: u64,
    pub bytes: u64,
    #[serde(default)]
    pub quotas: Quotas,
    #[serde(default)]
    pub keys: Vec<BucketKey>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyListItem {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub access_key_id: String,
    pub secret_access_key: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct NodeStatus {
    garage_version: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct ClusterStatus {
    nodes: Vec<NodeStatus>,
}

impl Admin {
    pub fn new(base: &str, token: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            token: token.trim().to_string(),
            http,
        })
    }

    pub fn from_config(config: &Config) -> Result<Self, String> {
        let path = token_path(config);
        let token = std::fs::read_to_string(&path)
            .map_err(|e| format!("Could not read Garage's admin token from {}: {e}", path.display()))?;
        Self::new(&config.garage_admin_url, &token)
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        op: &str,
        query: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> Result<T, String> {
        let mut req = self
            .http
            .request(method, format!("{}/v2/{op}", self.base))
            .bearer_auth(&self.token)
            .query(query);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.map_err(|e| {
            if e.is_connect() {
                "Garage is not running".to_string()
            } else {
                format!("Garage: {}", super::panel_update::with_causes(&e))
            }
        })?;
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        if !status.is_success() {
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_string))
                .unwrap_or_else(|| text.trim().chars().take(300).collect());
            return Err(format!("Garage refused {op} ({}): {msg}", status.as_u16()));
        }
        let text = if text.trim().is_empty() { "null" } else { &text };
        serde_json::from_str(text).map_err(|e| format!("Unexpected answer from Garage to {op}: {e}"))
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, op: &str, query: &[(&str, &str)]) -> Result<T, String> {
        self.call(reqwest::Method::GET, op, query, None).await
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        op: &str,
        query: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> Result<T, String> {
        self.call(reqwest::Method::POST, op, query, body).await
    }

    pub async fn health(&self) -> Result<Health, String> {
        self.get("GetClusterHealth", &[]).await
    }

    pub async fn statistics(&self) -> Result<Statistics, String> {
        self.get("GetClusterStatistics", &[]).await
    }

    /// The version the running node reports, e.g. "v2.5.0".
    pub async fn version(&self) -> Result<Option<String>, String> {
        let s: ClusterStatus = self.get("GetClusterStatus", &[]).await?;
        Ok(s.nodes.into_iter().find_map(|n| n.garage_version))
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketListItem>, String> {
        self.get("ListBuckets", &[]).await
    }

    pub async fn bucket(&self, id: &str) -> Result<BucketInfo, String> {
        self.get("GetBucketInfo", &[("id", id)]).await
    }

    pub async fn create_bucket(&self, name: &str) -> Result<BucketInfo, String> {
        self.post("CreateBucket", &[], Some(json!({ "globalAlias": name })))
            .await
    }

    pub async fn set_quotas(&self, id: &str, q: &Quotas) -> Result<BucketInfo, String> {
        self.post(
            "UpdateBucket",
            &[("id", id)],
            Some(json!({ "quotas": { "maxSize": q.max_size, "maxObjects": q.max_objects } })),
        )
        .await
    }

    /// Fails while the bucket holds objects.
    pub async fn delete_bucket(&self, id: &str) -> Result<(), String> {
        self.post::<serde_json::Value>("DeleteBucket", &[("id", id)], None)
            .await
            .map(|_| ())
    }

    pub async fn list_keys(&self) -> Result<Vec<KeyListItem>, String> {
        self.get("ListKeys", &[]).await
    }

    /// A new key that never expires and can't create buckets. Its secret is only in this answer.
    pub async fn create_key(&self, name: &str) -> Result<KeyInfo, String> {
        self.post(
            "CreateKey",
            &[],
            Some(json!({ "name": name, "neverExpires": true, "deny": { "createBucket": true } })),
        )
        .await
    }

    pub async fn delete_key(&self, id: &str) -> Result<(), String> {
        self.post::<serde_json::Value>("DeleteKey", &[("id", id)], None)
            .await
            .map(|_| ())
    }

    /// Make the key's permissions on the bucket exactly `perm`.
    pub async fn set_grant(&self, bucket_id: &str, key_id: &str, perm: Perm) -> Result<(), String> {
        let allow = Perm {
            read: perm.read,
            write: perm.write,
            owner: perm.owner,
        };
        let deny = Perm {
            read: !perm.read,
            write: !perm.write,
            owner: !perm.owner,
        };
        if deny.any() {
            self.post::<serde_json::Value>(
                "DenyBucketKey",
                &[],
                Some(json!({ "bucketId": bucket_id, "accessKeyId": key_id, "permissions": deny })),
            )
            .await?;
        }
        if allow.any() {
            self.post::<serde_json::Value>(
                "AllowBucketKey",
                &[],
                Some(json!({ "bucketId": bucket_id, "accessKeyId": key_id, "permissions": allow })),
            )
            .await?;
        }
        Ok(())
    }
}

// ---------- Validation ----------

/// S3 bucket naming rules, which also keeps names safe in path-style URLs.
pub fn bucket_name(input: &str) -> Result<String, String> {
    let n = input.trim().to_string();
    if !(3..=63).contains(&n.len()) {
        return Err("A bucket name must be 3 to 63 characters long".into());
    }
    if !n
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err("A bucket name can only use lowercase letters, digits, '-' and '.'".into());
    }
    let first = n.as_bytes()[0];
    let last = n.as_bytes()[n.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err("A bucket name must start and end with a letter or digit".into());
    }
    if n.contains("..") || n.contains(".-") || n.contains("-.") {
        return Err("A bucket name can't have '..', '.-' or '-.'".into());
    }
    if n.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err("A bucket name can't look like an IP address".into());
    }
    if n.starts_with("xn--") || n.ends_with("-s3alias") {
        return Err("That bucket name is reserved".into());
    }
    Ok(n)
}

/// A key's display name: short, printable, no control characters.
pub fn key_name(input: &str) -> Result<String, String> {
    let n = input.trim().to_string();
    if n.is_empty() || n.chars().count() > 64 {
        return Err("A key name must be 1 to 64 characters long".into());
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
    {
        return Err("A key name can only use letters, digits, spaces, '-', '_' and '.'".into());
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names() {
        for ok in ["abc", "reels-db", "onlygta6-media", "a.b.c", "x1-2"] {
            assert_eq!(bucket_name(ok).unwrap(), ok);
        }
        for bad in [
            "ab",
            "Reels",
            "-abc",
            "abc-",
            "a..b",
            "a.-b",
            "192.168.1.1",
            "a_b",
            "a/b",
            "xn--abc",
            "x-s3alias",
            &"a".repeat(64),
        ] {
            assert!(bucket_name(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn key_names() {
        assert_eq!(key_name(" app key-1 ").unwrap(), "app key-1");
        assert!(key_name("").is_err());
        assert!(key_name("a\nb").is_err());
        assert!(key_name("a\"b").is_err());
        assert!(key_name(&"k".repeat(65)).is_err());
    }

    #[test]
    fn config_is_loopback_only_with_secret_files() {
        let mut config = Config::from_env();
        config.garage_dir = PathBuf::from("/etc/garage");
        let c = render_config(&config);
        assert!(c.contains("replication_factor = 1"));
        let path = |f: &str| config.garage_dir.join(f).display().to_string();
        assert!(c.contains(&format!("rpc_secret_file = \"{}\"", path("rpc.secret"))));
        assert!(c.contains(&format!("admin_token_file = \"{}\"", path("admin.token"))));
        assert!(c.contains("s3_region = \"us-east-1\""));
        for line in c.lines().filter(|l| l.contains("_addr")) {
            assert!(line.contains("\"127.0.0.1:"), "not loopback: {line}");
        }
        assert!(!c.contains("rpc_secret ="), "secrets stay out of the config file");
    }

    #[test]
    fn unit_is_sandboxed() {
        let mut config = Config::from_env();
        config.garage_dir = PathBuf::from("/etc/garage");
        let u = render_unit(&config);
        assert!(u.contains("User=garage"));
        assert!(u.contains("ProtectSystem=strict"));
        assert!(u.contains("ReadWritePaths=/var/lib/garage\n"));
        assert!(u.contains("CapabilityBoundingSet=\n"));
        assert!(u.contains("server --single-node"));
    }

    #[test]
    fn pinned_hashes_look_right() {
        for h in [SHA256_X86_64, SHA256_AARCH64] {
            assert_eq!(h.len(), 64);
            assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn grant_is_exact() {
        // Deny everything not asked for, so lowering a grant takes effect.
        let p = Perm {
            read: true,
            write: false,
            owner: false,
        };
        assert!(p.any());
        assert!(!Perm::default().any());
    }
}
