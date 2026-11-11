//! WireGuard VPN: one server interface managed by the panel and any number of clients (peers).
//!
//! The panel writes the standard `/etc/wireguard/<interface>.conf` and runs it with the stock
//! `wg-quick@<interface>` unit, so a server that already ran WireGuard keeps working the same way.
//! Such a server's configuration is imported the first time the panel looks: its keys, peers and
//! any lines the panel doesn't manage itself (`PostUp`, `DNS`, `MTU`, extra addresses, ...) are
//! kept and written back unchanged. The original file is saved next to it before the first rewrite.
//!
//! Peer changes are applied with `systemctl reload`, which `wg-quick@` implements with
//! `wg syncconf`, so connected clients stay connected. Server changes restart the interface.

use super::cmd::{run, run_with, CmdOpts, CmdOutcome};
use crate::config::Config;
use crate::fsutil::write_atomic;
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Settings key holding [`Server`] as JSON.
pub const SETTING: &str = "wireguard";
/// First line of every file the panel writes; a file without it was written by someone else.
pub const MARKER: &str = "# Managed by CloudPanel.";
pub const DEFAULT_PORT: u16 = 51820;
pub const DEFAULT_ADDRESS: &str = "10.8.0.1/24";
pub const DEFAULT_ROUTES: &str = "0.0.0.0/0";
const KEEPALIVE: u16 = 25;

/// One configuration write and service change at a time.
static APPLY: Mutex<()> = Mutex::new(());

/// The server side. Stored as JSON in the settings table; `private_key` is encrypted.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Server {
    pub interface: String,
    pub enabled: bool,
    pub listen_port: u16,
    /// The server's own tunnel address with the tunnel network's prefix, e.g. `10.8.0.1/24`.
    pub address: String,
    /// Hostname or IP address clients connect to.
    pub endpoint: String,
    /// DNS servers handed to clients.
    pub dns: Vec<String>,
    /// Route client traffic to the internet through this server (IP forwarding + masquerade).
    pub nat: bool,
    /// The interface masqueraded traffic leaves through; detected from the default route if empty.
    pub out_interface: Option<String>,
    pub public_key: String,
    /// Sealed with [`crate::secrets`].
    pub private_key: String,
    /// `[Interface]` lines from an imported configuration that the panel doesn't manage itself.
    pub extra: Vec<String>,
    /// Set up from a configuration that existed before the panel managed it.
    pub imported: bool,
    /// The UFW rule the panel opened for `listen_port`.
    pub firewall_rule_id: Option<i64>,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            interface: "wg0".into(),
            enabled: false,
            listen_port: DEFAULT_PORT,
            address: DEFAULT_ADDRESS.into(),
            endpoint: String::new(),
            dns: vec!["1.1.1.1".into(), "1.0.0.1".into()],
            nat: true,
            out_interface: None,
            public_key: String::new(),
            private_key: String::new(),
            extra: Vec::new(),
            imported: false,
            firewall_rule_id: None,
        }
    }
}

impl Server {
    pub fn configured(&self) -> bool {
        !self.public_key.is_empty() && !self.private_key.is_empty()
    }
}

/// A peer as written to the server's configuration. Keys are plain here.
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub name: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    /// Tunnel address, e.g. `10.8.0.2`.
    pub address: Option<String>,
    /// Networks behind the peer, routed to it as well (site-to-site), comma-separated.
    pub server_allowed_ips: String,
    /// `[Peer]` lines from an imported configuration that the panel doesn't manage itself.
    pub extra: Vec<String>,
    pub enabled: bool,
}

// ---------- Keys ----------

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn decode_key(key: &str) -> Result<[u8; 32], String> {
    let bytes = b64()
        .decode(key.trim())
        .map_err(|_| "Not a valid WireGuard key".to_string())?;
    bytes.try_into().map_err(|_| "Not a valid WireGuard key".to_string())
}

/// A new private key, clamped like `wg genkey`'s.
pub fn generate_private_key() -> String {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    b64().encode(k)
}

pub fn generate_preshared_key() -> String {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    b64().encode(k)
}

/// The public key for a private key, as `wg pubkey` prints it.
pub fn public_key(private_key: &str) -> Result<String, String> {
    let secret = x25519_dalek::StaticSecret::from(decode_key(private_key)?);
    Ok(b64().encode(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}

/// A well-formed key (any of the three kinds), normalized.
pub fn key(input: &str) -> Result<String, String> {
    Ok(b64().encode(decode_key(input)?))
}

// ---------- Validation ----------

/// A peer's display name, also used as the file name of its configuration.
pub fn client_name(input: &str) -> Result<String, String> {
    let n = input.trim();
    if n.is_empty() || n.chars().count() > 32 {
        return Err("Name must be 1-32 characters".into());
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || " ._-".contains(c)) {
        return Err("Name may only contain letters, digits, spaces, dots, dashes and underscores".into());
    }
    Ok(n.to_string())
}

/// A Linux network interface name.
pub fn interface_name(input: &str) -> Result<String, String> {
    let n = input.trim();
    if n.is_empty() || n.len() > 15 || !n.chars().all(|c| c.is_ascii_alphanumeric() || "_=+.-".contains(c)) {
        return Err("Interface names are 1-15 letters, digits or _=+.-".into());
    }
    Ok(n.to_string())
}

/// The tunnel network as the server's own address in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tunnel {
    pub server: Ipv4Addr,
    pub prefix: u8,
}

impl Tunnel {
    pub fn parse(input: &str) -> Result<Self, String> {
        let s = input.trim();
        let (a, p) = s
            .split_once('/')
            .ok_or("Give the server's tunnel address with a prefix, e.g. 10.8.0.1/24")?;
        let server: Ipv4Addr = a.parse().map_err(|_| format!("'{a}' is not an IPv4 address"))?;
        let prefix: u8 = p
            .parse()
            .ok()
            .filter(|n| (8..=30).contains(n))
            .ok_or("The prefix must be between /8 and /30")?;
        if server.is_unspecified() || server.is_loopback() || server.is_multicast() || server.is_broadcast() {
            return Err(format!("{server} can't be used as a tunnel address"));
        }
        let t = Tunnel { server, prefix };
        if server == t.network() || server == t.broadcast() {
            return Err(format!(
                "{server} is the network's own address; use a host address like {}",
                Ipv4Addr::from(u32::from(t.network()) + 1)
            ));
        }
        Ok(t)
    }

    fn mask(&self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.server) & self.mask())
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.server) | !self.mask())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.server) & self.mask()
    }

    /// `10.8.0.0/24`
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network(), self.prefix)
    }

    /// The first address in the network not taken by the server or `used`.
    pub fn next_free(&self, used: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
        let first = u32::from(self.network()) + 1;
        let last = u32::from(self.broadcast()) - 1;
        (first..=last)
            .map(Ipv4Addr::from)
            .find(|ip| *ip != self.server && !used.contains(ip))
    }

    /// Is `ip` a client address in this network?
    pub fn usable(&self, ip: Ipv4Addr) -> bool {
        self.contains(ip) && ip != self.server && ip != self.network() && ip != self.broadcast()
    }
}

/// A comma-separated list of networks, normalized to `a, b`.
pub fn cidr_list(input: &str, max: usize) -> Result<String, String> {
    let items: Vec<String> = input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(crate::validate::cidr)
        .collect::<Result<_, _>>()?;
    if items.len() > max {
        return Err(format!("At most {max} networks"));
    }
    Ok(items.join(", "))
}

/// The hostname or IP address clients connect to.
pub fn endpoint(input: &str) -> Result<String, String> {
    let s = input.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    crate::validate::domain(s).map_err(|_| format!("'{s}' is not a hostname or IP address"))
}

// ---------- Configuration files ----------

/// iptables rules for routing clients to the internet. Inserted at the top of FORWARD so they
/// come before UFW's chains, whose default forward policy is to drop.
fn nat_rules(tunnel: &Tunnel, out: &str) -> (String, String) {
    let net = tunnel.cidr();
    let up = format!(
        "sysctl -q -w net.ipv4.ip_forward=1; \
         iptables -I FORWARD 1 -i %i -j ACCEPT; \
         iptables -I FORWARD 1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; \
         iptables -t nat -A POSTROUTING -s {net} -o {out} -j MASQUERADE"
    );
    let down = format!(
        "iptables -D FORWARD -i %i -j ACCEPT; \
         iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; \
         iptables -t nat -D POSTROUTING -s {net} -o {out} -j MASQUERADE"
    );
    (up, down)
}

/// The server's `<interface>.conf`. `out_interface` is the resolved interface for NAT.
pub fn render_server(s: &Server, private_key: &str, out_interface: Option<&str>, peers: &[Peer]) -> String {
    let mut c = format!(
        "{MARKER} Manage WireGuard under VPN in the panel; edits made here are overwritten.\n\
         [Interface]\n\
         Address = {}\n\
         ListenPort = {}\n\
         PrivateKey = {private_key}\n",
        s.address, s.listen_port
    );
    if s.nat {
        if let (Ok(t), Some(out)) = (Tunnel::parse(&s.address), out_interface) {
            let (up, down) = nat_rules(&t, out);
            c.push_str(&format!("PostUp = {up}\nPostDown = {down}\n"));
        }
    }
    for line in &s.extra {
        c.push_str(line);
        c.push('\n');
    }
    for p in peers.iter().filter(|p| p.enabled) {
        c.push_str(&format!(
            "\n[Peer]\n# Name = {}\nPublicKey = {}\n",
            p.name, p.public_key
        ));
        if let Some(psk) = &p.preshared_key {
            c.push_str(&format!("PresharedKey = {psk}\n"));
        }
        let mut allowed: Vec<String> = p.address.iter().map(|a| format!("{a}/32")).collect();
        allowed.extend(
            p.server_allowed_ips
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
        c.push_str(&format!("AllowedIPs = {}\n", allowed.join(", ")));
        for line in &p.extra {
            c.push_str(line);
            c.push('\n');
        }
    }
    c
}

/// What a client imports into its WireGuard app.
pub struct ClientConf<'a> {
    pub private_key: &'a str,
    pub preshared_key: Option<&'a str>,
    pub address: &'a str,
    /// Networks the client sends through the tunnel.
    pub routes: &'a str,
}

pub fn render_client(s: &Server, c: &ClientConf) -> String {
    let mut out = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/32\n",
        c.private_key, c.address
    );
    if !s.dns.is_empty() {
        out.push_str(&format!("DNS = {}\n", s.dns.join(", ")));
    }
    let host = match s.endpoint.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => format!("[{v6}]"),
        Err(_) => s.endpoint.clone(),
    };
    out.push_str(&format!("\n[Peer]\nPublicKey = {}\n", s.public_key));
    if let Some(psk) = c.preshared_key {
        out.push_str(&format!("PresharedKey = {psk}\n"));
    }
    out.push_str(&format!(
        "AllowedIPs = {}\nEndpoint = {host}:{}\nPersistentKeepalive = {KEEPALIVE}\n",
        c.routes, s.listen_port
    ));
    out
}

// ---------- Importing an existing configuration ----------

/// A configuration found on the server, ready to be stored.
#[derive(Debug)]
pub struct Imported {
    pub server: Server,
    /// Plain; the caller seals it.
    pub private_key: String,
    pub peers: Vec<Peer>,
    pub notes: Vec<String>,
}

#[derive(Default)]
struct Section {
    kind: String,
    comment: Option<String>,
    lines: Vec<(String, String)>,
}

fn sections(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    let mut comment: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            let c = line.trim_start_matches('#').trim();
            // "# Name = laptop" (the panel's and wg-easy's style) or just "# laptop".
            let name = c
                .split_once('=')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("name"))
                .map(|(_, v)| v.trim())
                .unwrap_or(c);
            // wireguard-install writes "### Client phone".
            let name = name
                .strip_prefix("Client:")
                .or_else(|| name.strip_prefix("Client "))
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(name);
            if !c.starts_with("Managed by CloudPanel") && !name.is_empty() {
                match out.last_mut() {
                    // Right after the header (the panel's style) names the section it's in.
                    Some(sec) if sec.lines.is_empty() && sec.comment.is_none() && sec.kind == "peer" => {
                        sec.comment = Some(name.to_string())
                    }
                    // Otherwise it names the next section (wireguard-install's "### Client x").
                    _ => comment = Some(name.to_string()),
                }
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            out.push(Section {
                kind: line[1..line.len() - 1].trim().to_ascii_lowercase(),
                comment: comment.take(),
                lines: Vec::new(),
            });
            continue;
        }
        if let (Some(sec), Some((k, v))) = (out.last_mut(), line.split_once('=')) {
            let v = v.split(" #").next().unwrap_or(v);
            sec.lines.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// Read an existing `wg-quick` configuration.
pub fn parse_config(text: &str, interface: &str) -> Result<Imported, String> {
    let secs = sections(text);
    let iface = secs
        .iter()
        .find(|s| s.kind == "interface")
        .ok_or("No [Interface] section")?;
    let mut server = Server {
        interface: interface.to_string(),
        imported: true,
        nat: false,
        dns: Server::default().dns,
        ..Server::default()
    };
    let mut private_key = None;
    let mut port = None;
    let mut address = None;
    let mut notes = Vec::new();
    for (k, v) in &iface.lines {
        match k.to_ascii_lowercase().as_str() {
            "privatekey" => private_key = Some(key(v)?),
            "listenport" => port = v.parse::<u16>().ok(),
            "address" => {
                for a in v.split(',').map(str::trim).filter(|a| !a.is_empty()) {
                    if address.is_none() && Tunnel::parse(a).is_ok() {
                        address = Some(a.to_string());
                    } else {
                        server.extra.push(format!("Address = {a}"));
                    }
                }
            }
            "saveconfig" => notes.push("SaveConfig was removed: it would overwrite the panel's changes".into()),
            _ => server.extra.push(format!("{k} = {v}")),
        }
    }
    let private_key = private_key.ok_or("The [Interface] section has no PrivateKey")?;
    server.public_key = public_key(&private_key)?;
    server.listen_port = port.unwrap_or_else(|| {
        notes.push(format!("No ListenPort was set; using {DEFAULT_PORT}"));
        DEFAULT_PORT
    });
    let tunnel = match address {
        Some(a) => {
            server.address = a;
            Tunnel::parse(&server.address).ok()
        }
        None => {
            notes.push("No IPv4 tunnel address was found; new clients need one set under server settings".into());
            server.address = String::new();
            None
        }
    };

    let mut peers = Vec::new();
    let mut names = HashSet::new();
    let mut keys = HashSet::new();
    for (i, sec) in secs.iter().filter(|s| s.kind == "peer").enumerate() {
        let mut peer = Peer {
            name: String::new(),
            public_key: String::new(),
            preshared_key: None,
            address: None,
            server_allowed_ips: String::new(),
            extra: Vec::new(),
            enabled: true,
        };
        let mut others = Vec::new();
        for (k, v) in &sec.lines {
            match k.to_ascii_lowercase().as_str() {
                "publickey" => peer.public_key = key(v)?,
                "presharedkey" => peer.preshared_key = Some(key(v)?),
                "allowedips" => {
                    for a in v.split(',').map(str::trim).filter(|a| !a.is_empty()) {
                        let host = a.strip_suffix("/32").unwrap_or(a);
                        match host.parse::<Ipv4Addr>() {
                            Ok(ip) if peer.address.is_none() && tunnel.map_or(true, |t| t.usable(ip)) => {
                                peer.address = Some(ip.to_string())
                            }
                            _ => others.push(a.to_string()),
                        }
                    }
                }
                _ => peer.extra.push(format!("{k} = {v}")),
            }
        }
        if peer.public_key.is_empty() {
            notes.push(format!("Skipped peer {} with no PublicKey", i + 1));
            continue;
        }
        if !keys.insert(peer.public_key.clone()) {
            notes.push(format!(
                "Skipped peer {}: its PublicKey is used by an earlier peer",
                i + 1
            ));
            continue;
        }
        peer.server_allowed_ips = others.join(", ");
        let base: String = sec
            .comment
            .as_deref()
            .and_then(|c| client_name(c).ok())
            .unwrap_or_else(|| format!("peer-{}", i + 1));
        let mut name = base.clone();
        let mut n = 2;
        while !names.insert(name.to_ascii_lowercase()) {
            name = format!("{}-{n}", base.chars().take(28).collect::<String>());
            n += 1;
        }
        peer.name = name;
        peers.push(peer);
    }
    Ok(Imported {
        server,
        private_key,
        peers,
        notes,
    })
}

/// The configuration to import: `wg0.conf` if there is one, else the first in the directory.
pub fn find_existing(dir: &Path) -> Option<(String, PathBuf)> {
    let preferred = dir.join("wg0.conf");
    if preferred.is_file() {
        return Some(("wg0".into(), preferred));
    }
    let mut found: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "conf") && p.is_file())
        .filter_map(|p| {
            let stem = p.file_stem()?.to_str()?;
            interface_name(stem).ok().map(|n| (n, p.clone()))
        })
        .collect();
    found.sort();
    found.into_iter().next()
}

// ---------- The system ----------

fn conf_path(config: &Config, interface: &str) -> PathBuf {
    config.wireguard_dir.join(format!("{interface}.conf"))
}

fn unit(interface: &str) -> String {
    format!("wg-quick@{interface}.service")
}

/// Are `wg` and `wg-quick` installed?
pub fn installed() -> bool {
    let has = |name: &str| super::cmd::which(name) || Path::new("/usr/bin").join(name).is_file();
    has("wg") && has("wg-quick")
}

/// Can the panel install the tools itself?
pub fn can_install(config: &Config) -> bool {
    super::runtimes::can_install(config)
}

/// Is the `wg-quick` unit for this interface running, or set to start at boot?
pub fn unit_state(interface: &str) -> (bool, bool) {
    let check = |verb: &str| {
        run_with(
            "systemctl",
            &[verb, "--quiet", &unit(interface)],
            &CmdOpts::default().timeout(15),
        )
        .success()
    };
    (check("is-active"), check("is-enabled"))
}

/// The interface the default IPv4 route leaves through.
pub fn default_interface() -> Option<String> {
    let CmdOutcome::Ok(out) = run("ip", &["-4", "route", "show", "default"]) else {
        return None;
    };
    parse_default_route(&out)
}

fn parse_default_route(out: &str) -> Option<String> {
    let mut words = out.lines().next()?.split_whitespace();
    words.find(|w| *w == "dev")?;
    words.next().and_then(|d| interface_name(d).ok())
}

/// Live state of a peer, from `wg show <interface> dump`.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct PeerStatus {
    pub endpoint: Option<String>,
    /// Seconds since the epoch, or none if it never connected.
    pub latest_handshake: Option<i64>,
    pub rx: u64,
    pub tx: u64,
}

/// Peers of a running interface by public key, or None when it isn't up.
pub fn status(interface: &str) -> Option<HashMap<String, PeerStatus>> {
    match run("wg", &["show", interface, "dump"]) {
        CmdOutcome::Ok(out) => Some(parse_dump(&out)),
        _ => None,
    }
}

fn parse_dump(out: &str) -> HashMap<String, PeerStatus> {
    out.lines()
        .skip(1) // the interface itself
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 8 {
                return None;
            }
            let hs: i64 = f[4].parse().unwrap_or(0);
            Some((
                f[0].to_string(),
                PeerStatus {
                    endpoint: Some(f[2].to_string()).filter(|e| e != "(none)"),
                    latest_handshake: (hs > 0).then_some(hs),
                    rx: f[5].parse().unwrap_or(0),
                    tx: f[6].parse().unwrap_or(0),
                },
            ))
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    /// Only peers changed: reload, keeping connected clients connected.
    Peers,
    /// The interface itself changed: restart it.
    Server,
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    super::apps::systemctl(args).map(|_| ())
}

/// Write the configuration and bring the service in line with it.
pub fn apply(config: &Config, s: &Server, private_key: &str, peers: &[Peer], change: Change) -> Result<(), String> {
    let _guard = APPLY.lock().unwrap_or_else(|e| e.into_inner());
    let path = conf_path(config, &s.interface);
    let tools = installed();
    if s.enabled && !tools && cfg!(target_os = "linux") {
        return Err("WireGuard is not installed. Install it from this page first.".into());
    }
    let out_interface = match (&s.out_interface, s.nat && s.enabled) {
        (Some(i), _) => Some(i.clone()),
        (None, true) => Some(
            default_interface()
                .ok_or("Could not find the interface with the default route; set the outgoing interface for NAT")?,
        ),
        (None, false) => None,
    };
    let text = render_server(s, private_key, out_interface.as_deref(), peers);

    // Keep what was there before the panel's first rewrite.
    let old = std::fs::read_to_string(&path).ok();
    if let Some(old) = &old {
        let backup = path.with_extension("conf.pre-cloudpanel");
        if !old.starts_with(MARKER) && !backup.exists() {
            write_atomic(&backup, old.as_bytes(), 0o600).map_err(|e| write_error(&backup, e))?;
        }
    }
    crate::fsutil::create_private_dir(&config.wireguard_dir, 0o700)
        .map_err(|e| write_error(&config.wireguard_dir, e))?;

    if !tools {
        // Development: nothing to run.
        return write_atomic(&path, text.as_bytes(), 0o600).map_err(|e| write_error(&path, e));
    }
    let unit = unit(&s.interface);
    let (active, _) = unit_state(&s.interface);
    // `wg-quick down` runs the PostDown lines of the file as it is then, so the interface has to
    // come down with the old file, or its NAT rules would stay behind after they change.
    let stopped = active && (change == Change::Server || !s.enabled);
    if stopped {
        systemctl(&["stop", &unit])?;
    }
    if let Err(e) = write_atomic(&path, text.as_bytes(), 0o600) {
        if stopped {
            let _ = systemctl(&["start", &unit]);
        }
        return Err(write_error(&path, e));
    }
    if !s.enabled {
        return systemctl(&["disable", "--now", &unit]);
    }
    systemctl(&["enable", &unit])?;
    if !(change == Change::Server || !active) {
        return systemctl(&["reload", &unit]);
    }
    if let Err(e) = systemctl(&["restart", &unit]) {
        // Put back what worked, so a rejected change doesn't leave the VPN down.
        if let Some(old) = old.filter(|_| active) {
            let _ = write_atomic(&path, old.as_bytes(), 0o600);
            let _ = systemctl(&["restart", &unit]);
        }
        return Err(format!("WireGuard failed to start: {e}"));
    }
    Ok(())
}

fn write_error(path: &Path, e: std::io::Error) -> String {
    if e.raw_os_error() == Some(30) {
        // EROFS: the service unit predates WireGuard support and doesn't let the panel write here.
        return format!(
            "{} is read-only for the panel. Re-run the CloudPanel installer to update its service, then try again.",
            path.display()
        );
    }
    format!("Could not write {}: {e}", path.display())
}

/// Install `wireguard-tools` (and iptables for NAT) outside the panel's sandbox.
pub fn install(log: &dyn Fn(&str)) -> Result<(), String> {
    let script = "set -eu\n\
                  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a\n\
                  apt-get update -q\n\
                  apt-get install -y -q --no-install-recommends wireguard-tools iptables\n\
                  install -d -m 0700 /etc/wireguard\n\
                  wg --version\n";
    let r = super::cmd::run_host_streaming(
        "/bin/sh",
        &["-c", script],
        &CmdOpts::default().timeout(15 * 60),
        &mut |l, _| log(l),
    );
    if !r.success() || !installed() {
        return Err(format!(
            "Installing WireGuard failed (exit code {})",
            r.code.unwrap_or(-1)
        ));
    }
    log("WireGuard installed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7748 section 6.1, Alice.
    const RFC_PRIVATE: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    const RFC_PUBLIC: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    // Bob's.
    const OTHER_PUBLIC: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

    #[test]
    fn public_keys_match_wg_pubkey() {
        assert_eq!(public_key(RFC_PRIVATE).unwrap(), RFC_PUBLIC);
        let k = generate_private_key();
        assert_eq!(public_key(&k).unwrap().len(), 44);
        assert!(public_key("not a key").is_err());
        assert!(key("AAAA").is_err());
    }

    #[test]
    fn tunnel_allocation() {
        let t = Tunnel::parse("10.8.0.1/24").unwrap();
        assert_eq!(t.cidr(), "10.8.0.0/24");
        let mut used = HashSet::new();
        assert_eq!(t.next_free(&used), Some("10.8.0.2".parse().unwrap()));
        used.insert("10.8.0.2".parse().unwrap());
        assert_eq!(t.next_free(&used), Some("10.8.0.3".parse().unwrap()));
        let small = Tunnel::parse("192.168.9.1/30").unwrap();
        assert_eq!(small.next_free(&HashSet::new()), Some("192.168.9.2".parse().unwrap()));
        assert_eq!(small.next_free(&["192.168.9.2".parse().unwrap()].into()), None);
        assert!(Tunnel::parse("10.8.0.0/24").is_err());
        assert!(Tunnel::parse("10.8.0.1/31").is_err());
        assert!(Tunnel::parse("10.8.0.1").is_err());
        assert!(!t.usable("10.8.0.1".parse().unwrap()));
        assert!(!t.usable("10.9.0.5".parse().unwrap()));
    }

    #[test]
    fn validation() {
        assert_eq!(client_name("  Phone 1 ").unwrap(), "Phone 1");
        assert!(client_name("a\nb").is_err());
        assert!(client_name("x;rm").is_err());
        assert_eq!(cidr_list("0.0.0.0/0,  ::/0", 4).unwrap(), "0.0.0.0/0, ::/0");
        assert!(cidr_list("0.0.0.0/0, bogus", 4).is_err());
        assert_eq!(endpoint("VPN.Example.com").unwrap(), "vpn.example.com");
        assert_eq!(endpoint("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert!(endpoint("bad host").is_err());
        assert!(interface_name("wg0").is_ok());
        assert!(interface_name("wg0; reboot").is_err());
    }

    fn server() -> Server {
        Server {
            public_key: RFC_PUBLIC.into(),
            private_key: "sealed".into(),
            endpoint: "vpn.example.com".into(),
            enabled: true,
            ..Server::default()
        }
    }

    fn peer(name: &str, addr: &str) -> Peer {
        Peer {
            name: name.into(),
            public_key: RFC_PUBLIC.into(),
            preshared_key: Some(RFC_PUBLIC.into()),
            address: Some(addr.into()),
            server_allowed_ips: String::new(),
            extra: vec![],
            enabled: true,
        }
    }

    #[test]
    fn server_config() {
        let mut off = peer("off", "10.8.0.3");
        off.enabled = false;
        let c = render_server(&server(), RFC_PRIVATE, Some("eth0"), &[peer("laptop", "10.8.0.2"), off]);
        assert!(c.starts_with(MARKER));
        assert!(c.contains("Address = 10.8.0.1/24\nListenPort = 51820\n"));
        assert!(c.contains("-s 10.8.0.0/24 -o eth0 -j MASQUERADE"));
        assert!(c.contains("# Name = laptop\n"));
        assert!(c.contains("AllowedIPs = 10.8.0.2/32\n"));
        assert!(!c.contains("10.8.0.3"), "disabled peers are left out");
        let mut no_nat = server();
        no_nat.nat = false;
        assert!(!render_server(&no_nat, RFC_PRIVATE, Some("eth0"), &[]).contains("PostUp"));
    }

    #[test]
    fn client_config() {
        let mut s = server();
        let conf = ClientConf {
            private_key: RFC_PRIVATE,
            preshared_key: None,
            address: "10.8.0.2",
            routes: DEFAULT_ROUTES,
        };
        let c = render_client(&s, &conf);
        assert!(c.contains("Address = 10.8.0.2/32\nDNS = 1.1.1.1, 1.0.0.1\n"));
        assert!(c.contains("Endpoint = vpn.example.com:51820\n"));
        assert!(!c.contains("PresharedKey"));
        s.endpoint = "2001:db8::1".into();
        s.dns.clear();
        let c = render_client(&s, &conf);
        assert!(c.contains("Endpoint = [2001:db8::1]:51820"));
        assert!(!c.contains("DNS"));
    }

    #[test]
    fn imports_an_existing_config_and_round_trips() {
        let existing = format!(
            "[Interface]\n\
             Address = 10.66.66.1/24, fd42::1/64\n\
             ListenPort = 51900\n\
             PrivateKey = {RFC_PRIVATE}\n\
             SaveConfig = true\n\
             PostUp = iptables -A FORWARD -i wg0 -j ACCEPT\n\
             MTU = 1420\n\
             \n\
             ### Client phone\n\
             [Peer]\n\
             PublicKey = {RFC_PUBLIC}\n\
             PresharedKey = {RFC_PUBLIC}\n\
             AllowedIPs = 10.66.66.2/32, fd42::2/128\n\
             \n\
             [Peer]\n\
             PublicKey = {OTHER_PUBLIC}\n\
             AllowedIPs = 10.66.66.3/32, 192.168.50.0/24\n\
             PersistentKeepalive = 25\n"
        );
        let imp = parse_config(&existing, "wg0").unwrap();
        assert_eq!(imp.private_key, RFC_PRIVATE);
        assert_eq!(imp.server.public_key, RFC_PUBLIC);
        assert_eq!(imp.server.listen_port, 51900);
        assert_eq!(imp.server.address, "10.66.66.1/24");
        assert!(!imp.server.nat, "their own PostUp is kept instead");
        assert_eq!(
            imp.server.extra,
            vec![
                "Address = fd42::1/64",
                "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT",
                "MTU = 1420"
            ]
        );
        assert!(imp.notes.iter().any(|n| n.contains("SaveConfig")));
        assert_eq!(imp.peers.len(), 2);
        assert_eq!(imp.peers[0].name, "phone");
        assert_eq!(imp.peers[0].address.as_deref(), Some("10.66.66.2"));
        assert_eq!(imp.peers[0].server_allowed_ips, "fd42::2/128");
        assert_eq!(imp.peers[1].name, "peer-2");
        assert_eq!(imp.peers[1].server_allowed_ips, "192.168.50.0/24");
        assert_eq!(imp.peers[1].extra, vec!["PersistentKeepalive = 25"]);

        // Written back, then read again: nothing is lost.
        let written = render_server(&imp.server, &imp.private_key, None, &imp.peers);
        let again = parse_config(&written, "wg0").unwrap();
        assert_eq!(again.server, imp.server);
        assert_eq!(again.peers, imp.peers);
        assert!(again.notes.is_empty());
    }

    #[test]
    fn rejects_configs_without_keys() {
        assert!(parse_config("[Interface]\nAddress = 10.0.0.1/24\n", "wg0").is_err());
        assert!(parse_config("[Peer]\nPublicKey = x\n", "wg0").is_err());
    }

    #[test]
    fn finds_the_config_to_import() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_existing(dir.path()).is_none());
        std::fs::write(dir.path().join("vpn1.conf"), "").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "").unwrap();
        assert_eq!(find_existing(dir.path()).unwrap().0, "vpn1");
        std::fs::write(dir.path().join("wg0.conf"), "").unwrap();
        assert_eq!(find_existing(dir.path()).unwrap().0, "wg0");
    }

    #[test]
    fn parses_tool_output() {
        assert_eq!(
            parse_default_route("default via 203.0.113.1 dev ens3 proto dhcp src 203.0.113.9 metric 100\n").as_deref(),
            Some("ens3")
        );
        assert_eq!(parse_default_route(""), None);
        let dump = "priv\tpub\t51820\toff\n\
                    PEER1\tPSK\t198.51.100.7:40000\t10.8.0.2/32\t1762850000\t1024\t2048\t25\n\
                    PEER2\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n";
        let s = parse_dump(dump);
        assert_eq!(s["PEER1"].endpoint.as_deref(), Some("198.51.100.7:40000"));
        assert_eq!(s["PEER1"].latest_handshake, Some(1762850000));
        assert_eq!((s["PEER1"].rx, s["PEER1"].tx), (1024, 2048));
        assert_eq!(s["PEER2"], PeerStatus::default());
    }
}
