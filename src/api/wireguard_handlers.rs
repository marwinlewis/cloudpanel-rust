//! WireGuard VPN: the server interface and its clients. Administrators only.

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::{totp, AdminUser};
use crate::config::Config;
use crate::db::{self, models::WireguardClient, NewRule, NewWireguardClient};
use crate::secrets;
use crate::services::firewall::{Action, FirewallService, Protocol, Rule};
use crate::services::wireguard::{self as wg, Change, Peer, Server, Tunnel};
use crate::state::{blocking, SharedState};
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::net::Ipv4Addr;

const FIREWALL_COMMENT: &str = "WireGuard";

fn load(conn: &Connection) -> ApiResult<Option<Server>> {
    Ok(db::get_setting(conn, wg::SETTING)?.and_then(|v| serde_json::from_str(&v).ok()))
}

fn save(conn: &Connection, s: &Server) -> ApiResult<()> {
    Ok(db::set_json(conn, wg::SETTING, s)?)
}

fn open(config: &Config, sealed: &str) -> ApiResult<String> {
    secrets::decrypt(&config.etc_dir, sealed).map_err(ApiError::internal)
}

fn seal(config: &Config, plain: &str) -> ApiResult<String> {
    secrets::encrypt(&config.etc_dir, plain).map_err(ApiError::internal)
}

fn to_peer(config: &Config, c: &WireguardClient) -> ApiResult<Peer> {
    Ok(Peer {
        name: c.name.clone(),
        public_key: c.public_key.clone(),
        preshared_key: c.preshared_key.as_deref().map(|k| open(config, k)).transpose()?,
        address: c.address.clone(),
        server_allowed_ips: c.server_allowed_ips.clone(),
        extra: c.extra.lines().map(str::to_string).collect(),
        enabled: c.enabled,
    })
}

/// Write the configuration from what `conn` sees (including its open transaction) and apply it.
fn sync(config: &Config, conn: &Connection, change: Change) -> ApiResult<()> {
    let Some(s) = load(conn)?.filter(Server::configured) else {
        return Ok(());
    };
    let private_key = open(config, &s.private_key)?;
    let peers = db::list_wireguard_clients(conn)?
        .iter()
        .map(|c| to_peer(config, c))
        .collect::<ApiResult<Vec<_>>>()?;
    wg::apply(config, &s, &private_key, &peers, change).map_err(ApiError::Unprocessable)
}

/// Take over a WireGuard setup that existed before the panel managed one. Runs until the panel
/// has settings of its own; returns notes about what was imported, or why it couldn't be.
pub fn ensure_imported(config: &Config, conn: &Connection) -> ApiResult<Option<Vec<String>>> {
    if load(conn)?.is_some() {
        return Ok(None);
    }
    let Some((interface, path)) = wg::find_existing(&config.wireguard_dir) else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            return Ok(Some(vec![format!(
                "Found {} but could not read it: {e}",
                path.display()
            )]))
        }
    };
    let imp = match wg::parse_config(&text, &interface) {
        Ok(i) => i,
        Err(e) => {
            return Ok(Some(vec![format!(
                "Found {} but could not import it: {e}",
                path.display()
            )]))
        }
    };
    let (active, enabled) = wg::unit_state(&interface);
    let mut server = imp.server;
    server.enabled = active || enabled;
    server.private_key = seal(config, &imp.private_key)?;

    let tx = conn.unchecked_transaction()?;
    for p in &imp.peers {
        let psk = p.preshared_key.as_deref().map(|k| seal(config, k)).transpose()?;
        db::create_wireguard_client(
            &tx,
            &NewWireguardClient {
                name: &p.name,
                address: p.address.as_deref(),
                public_key: &p.public_key,
                private_key: None,
                preshared_key: psk.as_deref(),
                allowed_ips: wg::DEFAULT_ROUTES,
                server_allowed_ips: &p.server_allowed_ips,
                extra: &p.extra.join("\n"),
                enabled: true,
                imported: true,
            },
        )?;
    }
    save(&tx, &server)?;
    let mut notes = vec![format!(
        "Imported {} with {} peer{} from the existing WireGuard setup.",
        path.display(),
        imp.peers.len(),
        if imp.peers.len() == 1 { "" } else { "s" }
    )];
    notes.extend(imp.notes);
    audit::record_system(
        &tx,
        None,
        None,
        "wireguard.import",
        Some(&interface),
        Some(&notes.join(" ")),
    );
    tx.commit()?;
    tracing::info!("imported WireGuard configuration {}", path.display());
    Ok(Some(notes))
}

/// Keep a UFW rule open for the listen port while the server is enabled.
fn sync_firewall(conn: &Connection, s: &mut Server) -> ApiResult<()> {
    let wanted = s.enabled.then_some(s.listen_port);
    if let Some(id) = s.firewall_rule_id {
        if let Some(r) = db::find_firewall_rule(conn, id)? {
            let same = wanted.is_some()
                && r.port == wanted
                && r.protocol == "udp"
                && r.action == "allow"
                && r.source.is_none();
            if same {
                return Ok(());
            }
            let rule = Rule {
                action: Action::parse(&r.action).unwrap_or(Action::Allow),
                port: r.port,
                port_end: r.port_end,
                protocol: Protocol::parse(&r.protocol).unwrap_or(Protocol::Udp),
                source: r.source.clone(),
            };
            FirewallService::delete(&rule).map_err(ApiError::Unprocessable)?;
            db::delete_firewall_rule(conn, id)?;
        }
        s.firewall_rule_id = None;
    }
    let Some(port) = wanted else {
        return Ok(());
    };
    let new = NewRule {
        port: Some(port),
        port_end: None,
        protocol: "udp",
        action: "allow",
        source: None,
        comment: Some(FIREWALL_COMMENT),
    };
    // An administrator opened it already; that rule stays theirs.
    if db::firewall_rule_exists(conn, &new)? {
        return Ok(());
    }
    let rule = Rule {
        action: Action::Allow,
        port: Some(port),
        port_end: None,
        protocol: Protocol::Udp,
        source: None,
    };
    FirewallService::add(&rule, Some(FIREWALL_COMMENT)).map_err(ApiError::Unprocessable)?;
    db::delete_firewall_rule_with_action(conn, &new, "deny")?;
    s.firewall_rule_id = Some(db::create_firewall_rule(conn, &new)?);
    Ok(())
}

// ---------- Overview ----------

pub async fn get_wireguard(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let (server, clients, notes) = state
        .db(move |conn| {
            let notes = ensure_imported(&config, conn)?;
            Ok((load(conn)?, db::list_wireguard_clients(conn)?, notes))
        })
        .await?;
    let server = server.unwrap_or_default();
    let interface = server.interface.clone();
    let config = state.config.clone();
    let (installed, can_install, (active, at_boot), peers, detected) = blocking(move || {
        let installed = wg::installed();
        let unit = if installed {
            wg::unit_state(&interface)
        } else {
            (false, false)
        };
        Ok((
            installed,
            wg::can_install(&config),
            unit,
            wg::status(&interface),
            wg::default_interface(),
        ))
    })
    .await?;
    let tunnel = Tunnel::parse(&server.address).ok();
    let clients: Vec<_> = clients
        .iter()
        .map(|c| {
            let mut v = serde_json::to_value(c).unwrap_or_default();
            v["has_config"] = json!(c.private_key.is_some() && c.address.is_some());
            v["status"] = json!(peers.as_ref().and_then(|p| p.get(&c.public_key)));
            v
        })
        .collect();
    Ok(Json(json!({
        "installed": installed,
        "can_install": can_install,
        "running": peers.is_some(),
        "active": active,
        "enabled_at_boot": at_boot,
        "detected_interface": detected,
        "import_notes": notes,
        "server": {
            "configured": server.configured(),
            "interface": server.interface,
            "enabled": server.enabled,
            "listen_port": server.listen_port,
            "address": server.address,
            "network": tunnel.map(|t| t.cidr()),
            "endpoint": server.endpoint,
            "dns": server.dns,
            "nat": server.nat,
            "out_interface": server.out_interface,
            "public_key": server.public_key,
            "imported": server.imported,
            "extra": server.extra,
        },
        "clients": clients,
    })))
}

pub async fn install(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    if !wg::can_install(&state.config) {
        return Err(ApiError::BadRequest(
            "This system can't install packages from the panel; install wireguard-tools manually".into(),
        ));
    }
    let actor = admin.0.clone();
    state
        .db(move |conn| {
            audit::record(conn, &actor, "wireguard.install", None, None);
            Ok(())
        })
        .await?;
    let job_id = crate::jobs::spawn(&state.pool, "wireguard.install", None, Some(admin.0.id), move |log| {
        wg::install(&|l| log.line(l))
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- Server ----------

#[derive(Deserialize)]
pub struct ServerRequest {
    pub enabled: bool,
    pub listen_port: u16,
    pub address: String,
    #[serde(default)]
    pub endpoint: String,
    /// Comma-separated.
    #[serde(default)]
    pub dns: String,
    #[serde(default)]
    pub nat: bool,
    #[serde(default)]
    pub out_interface: Option<String>,
}

pub async fn set_server(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<ServerRequest>,
) -> ApiResult<impl IntoResponse> {
    if p.listen_port == 0 {
        return Err(ApiError::BadRequest("Enter a listen port".into()));
    }
    let tunnel = Tunnel::parse(&p.address).map_err(ApiError::BadRequest)?;
    let endpoint = match p.endpoint.trim() {
        "" if p.enabled => {
            return Err(ApiError::BadRequest(
                "Enter the hostname or IP address clients connect to".into(),
            ))
        }
        "" => String::new(),
        e => wg::endpoint(e).map_err(ApiError::BadRequest)?,
    };
    let dns: Vec<String> = p
        .dns
        .split(',')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| {
            d.parse::<std::net::IpAddr>()
                .map(|ip| ip.to_string())
                .map_err(|_| ApiError::BadRequest(format!("DNS server '{d}' is not an IP address")))
        })
        .collect::<ApiResult<_>>()?;
    if dns.len() > 4 {
        return Err(ApiError::BadRequest("At most 4 DNS servers".into()));
    }
    let out_interface = match p.out_interface.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(i) => Some(wg::interface_name(i).map_err(ApiError::BadRequest)?),
        None => None,
    };
    let config = state.config.clone();
    state
        .db(move |conn| {
            let mut s = load(conn)?.unwrap_or_default();
            let address = format!("{}/{}", tunnel.server, tunnel.prefix);
            let clients = db::list_wireguard_clients(conn)?;
            if let Some(c) = clients.iter().find(|c| {
                c.address
                    .as_deref()
                    .and_then(|a| a.parse::<Ipv4Addr>().ok())
                    .is_some_and(|ip| !tunnel.usable(ip))
            }) {
                return Err(ApiError::Conflict(format!(
                    "Client {} uses {}, which isn't a client address in {}. Delete it or keep the current network.",
                    c.name,
                    c.address.as_deref().unwrap_or(""),
                    tunnel.cidr()
                )));
            }
            s.enabled = p.enabled;
            s.listen_port = p.listen_port;
            s.address = address;
            s.endpoint = endpoint;
            s.dns = dns;
            s.nat = p.nat;
            s.out_interface = out_interface;
            if !s.configured() {
                let private_key = wg::generate_private_key();
                s.public_key = wg::public_key(&private_key).map_err(ApiError::internal)?;
                s.private_key = seal(&config, &private_key)?;
            }
            let tx = conn.unchecked_transaction()?;
            save(&tx, &s)?;
            sync(&config, &tx, Change::Server)?;
            sync_firewall(&tx, &mut s)?;
            save(&tx, &s)?;
            let detail = format!(
                "{} port {} network {}",
                if s.enabled { "enabled" } else { "disabled" },
                s.listen_port,
                tunnel.cidr()
            );
            audit::record(&tx, &admin.0, "wireguard.configure", Some(&s.interface), Some(&detail));
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "message": "WireGuard settings applied" })))
}

// ---------- Clients ----------

#[derive(Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(default)]
    pub allowed_ips: Option<String>,
}

fn routes(input: Option<&str>) -> ApiResult<String> {
    let r = wg::cidr_list(input.unwrap_or(wg::DEFAULT_ROUTES), 16).map_err(ApiError::BadRequest)?;
    if r.is_empty() {
        return Err(ApiError::BadRequest(
            "Enter at least one network to route through the tunnel, e.g. 0.0.0.0/0".into(),
        ));
    }
    Ok(r)
}

fn name_taken(e: rusqlite::Error) -> ApiError {
    if db::is_unique_violation(&e) {
        ApiError::Conflict("A client with that name already exists".into())
    } else {
        e.into()
    }
}

pub async fn create_client(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateClientRequest>,
) -> ApiResult<impl IntoResponse> {
    let name = wg::client_name(&p.name).map_err(ApiError::BadRequest)?;
    let allowed_ips = routes(p.allowed_ips.as_deref())?;
    let config = state.config.clone();
    let created = state
        .db(move |conn| {
            let s = load(conn)?
                .filter(Server::configured)
                .ok_or_else(|| ApiError::BadRequest("Set up the WireGuard server first".into()))?;
            let tunnel = Tunnel::parse(&s.address)
                .map_err(|_| ApiError::BadRequest("Set the server's tunnel address first".into()))?;
            let used: HashSet<Ipv4Addr> = db::list_wireguard_clients(conn)?
                .iter()
                .filter_map(|c| c.address.as_deref()?.parse().ok())
                .collect();
            let address = tunnel
                .next_free(&used)
                .ok_or_else(|| ApiError::Conflict(format!("No free addresses left in {}", tunnel.cidr())))?
                .to_string();
            let private_key = wg::generate_private_key();
            let public_key = wg::public_key(&private_key).map_err(ApiError::internal)?;
            let sealed_private = seal(&config, &private_key)?;
            let sealed_psk = seal(&config, &wg::generate_preshared_key())?;
            let tx = conn.unchecked_transaction()?;
            let id = db::create_wireguard_client(
                &tx,
                &NewWireguardClient {
                    name: &name,
                    address: Some(&address),
                    public_key: &public_key,
                    private_key: Some(&sealed_private),
                    preshared_key: Some(&sealed_psk),
                    allowed_ips: &allowed_ips,
                    server_allowed_ips: "",
                    extra: "",
                    enabled: true,
                    imported: false,
                },
            )
            .map_err(name_taken)?;
            sync(&config, &tx, Change::Peers)?;
            audit::record(&tx, &admin.0, "wireguard.client.create", Some(&name), Some(&address));
            let created = db::find_wireguard_client(&tx, id)?;
            tx.commit()?;
            Ok(created)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Deserialize)]
pub struct UpdateClientRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub allowed_ips: Option<String>,
    pub server_allowed_ips: Option<String>,
    /// For an imported client: its private key, so the panel can hand out its configuration.
    pub private_key: Option<String>,
}

pub async fn update_client(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<UpdateClientRequest>,
) -> ApiResult<impl IntoResponse> {
    let name = p
        .name
        .as_deref()
        .map(wg::client_name)
        .transpose()
        .map_err(ApiError::BadRequest)?;
    let allowed_ips = p.allowed_ips.as_deref().map(|r| routes(Some(r))).transpose()?;
    let server_allowed_ips = p
        .server_allowed_ips
        .as_deref()
        .map(|r| wg::cidr_list(r, 16))
        .transpose()
        .map_err(ApiError::BadRequest)?;
    let private_key = match p.private_key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => Some(wg::key(k).map_err(ApiError::BadRequest)?),
        None => None,
    };
    let config = state.config.clone();
    let updated = state
        .db(move |conn| {
            let mut c = db::find_wireguard_client(conn, id)?.ok_or(ApiError::NotFound("Client"))?;
            let mut changes = Vec::new();
            if let Some(n) = name {
                if n != c.name {
                    changes.push(format!("renamed from {}", c.name));
                    c.name = n;
                }
            }
            if let Some(e) = p.enabled {
                if e != c.enabled {
                    changes.push(if e { "enabled" } else { "disabled" }.to_string());
                    c.enabled = e;
                }
            }
            if let Some(r) = allowed_ips {
                c.allowed_ips = r;
            }
            if let Some(r) = server_allowed_ips {
                if r != c.server_allowed_ips {
                    changes.push(format!("routes to it: {}", if r.is_empty() { "none" } else { &r }));
                    c.server_allowed_ips = r;
                }
            }
            if let Some(k) = private_key {
                if wg::public_key(&k).map_err(ApiError::BadRequest)? != c.public_key {
                    return Err(ApiError::BadRequest(
                        "That private key doesn't belong to this client's public key".into(),
                    ));
                }
                c.private_key = Some(seal(&config, &k)?);
                changes.push("private key added".into());
            }
            let tx = conn.unchecked_transaction()?;
            db::save_wireguard_client(&tx, &c).map_err(name_taken)?;
            sync(&config, &tx, Change::Peers)?;
            audit::record(
                &tx,
                &admin.0,
                "wireguard.client.update",
                Some(&c.name),
                Some(&changes.join(", ")).filter(|s| !s.is_empty()).map(String::as_str),
            );
            let updated = db::find_wireguard_client(&tx, id)?;
            tx.commit()?;
            Ok(updated)
        })
        .await?;
    Ok(Json(updated))
}

pub async fn delete_client(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let c = db::find_wireguard_client(conn, id)?.ok_or(ApiError::NotFound("Client"))?;
            let tx = conn.unchecked_transaction()?;
            db::delete_wireguard_client(&tx, id)?;
            sync(&config, &tx, Change::Peers)?;
            audit::record(
                &tx,
                &admin.0,
                "wireguard.client.delete",
                Some(&c.name),
                c.address.as_deref(),
            );
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

/// The client's configuration file, which holds its private key. Every view is audited.
async fn client_config(id: i64, admin: AdminUser, state: &SharedState) -> ApiResult<(String, String)> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let c = db::find_wireguard_client(conn, id)?.ok_or(ApiError::NotFound("Client"))?;
            let s = load(conn)?
                .filter(Server::configured)
                .ok_or_else(|| ApiError::BadRequest("Set up the WireGuard server first".into()))?;
            if s.endpoint.is_empty() {
                return Err(ApiError::BadRequest(
                    "Set the server's public hostname or IP address first".into(),
                ));
            }
            let (Some(sealed), Some(address)) = (c.private_key.as_deref(), c.address.as_deref()) else {
                return Err(ApiError::BadRequest(
                    "This client was imported and the panel doesn't have its private key. Add the key, or create a new client.".into(),
                ));
            };
            let private_key = open(&config, sealed)?;
            let psk = c.preshared_key.as_deref().map(|k| open(&config, k)).transpose()?;
            let text = wg::render_client(
                &s,
                &wg::ClientConf {
                    private_key: &private_key,
                    preshared_key: psk.as_deref(),
                    address,
                    routes: &c.allowed_ips,
                },
            );
            audit::record(conn, &admin.0, "wireguard.client.config", Some(&c.name), None);
            Ok((c.name, text))
        })
        .await
}

pub async fn get_client_config(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let (name, text) = client_config(id, admin, &state).await?;
    let (width, modules) = totp::qr_matrix(&text).map_err(ApiError::internal)?;
    Ok(Json(
        json!({ "name": name, "config": text, "qr": { "width": width, "modules": modules } }),
    ))
}

pub async fn download_client_config(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<Response> {
    let (name, text) = client_config(id, admin, &state).await?;
    let mut res = text.into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        crate::api::download::disposition(&format!("{name}.conf")),
    );
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_setup_is_imported_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::from_env();
        config.etc_dir = dir.path().join("etc");
        config.wireguard_dir = dir.path().join("wireguard");
        std::fs::create_dir_all(&config.wireguard_dir).unwrap();
        let server_key = wg::generate_private_key();
        let peer_key = wg::public_key(&wg::generate_private_key()).unwrap();
        std::fs::write(
            config.wireguard_dir.join("wg0.conf"),
            format!(
                "[Interface]\nAddress = 10.7.0.1/24\nListenPort = 51821\nPrivateKey = {server_key}\n\n\
                 # Name = office\n[Peer]\nPublicKey = {peer_key}\nAllowedIPs = 10.7.0.2/32\n"
            ),
        )
        .unwrap();
        let conn = db::test_conn();

        let notes = ensure_imported(&config, &conn).unwrap().unwrap();
        assert!(notes[0].contains("1 peer"), "{notes:?}");
        let s = load(&conn).unwrap().unwrap();
        assert!(s.imported && s.configured());
        assert_eq!((s.listen_port, s.address.as_str()), (51821, "10.7.0.1/24"));
        assert_eq!(open(&config, &s.private_key).unwrap(), server_key);
        let clients = db::list_wireguard_clients(&conn).unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].name, "office");
        assert_eq!(clients[0].address.as_deref(), Some("10.7.0.2"));
        assert!(clients[0].imported && clients[0].private_key.is_none());

        assert!(ensure_imported(&config, &conn).unwrap().is_none(), "only once");
        assert_eq!(db::list_wireguard_clients(&conn).unwrap().len(), 1);
    }

    #[test]
    fn nothing_to_import() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::from_env();
        config.wireguard_dir = dir.path().join("missing");
        assert!(ensure_imported(&config, &db::test_conn()).unwrap().is_none());
    }
}
