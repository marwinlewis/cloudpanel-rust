//! Managing the email service's data: domains, keys, forwards, webhooks and status. Shared by the
//! CLI (`cloudpanel mail-*`) and the panel's API, so both apply the same rules. Nothing here prints.
//!
//! Functions that change forwards return whether Postfix's tables must be rewritten; the caller does
//! that (`install::sync_postfix` as root, or `cloudpanel mail-postfix-sync` from the sandboxed panel).

use super::{dkim, dns, events, install, keys, store, MailConfig};
use rusqlite::Connection;
use serde::Serialize;

/// Why an operation failed, so the API can pick a status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Bad input (400).
    Invalid(String),
    /// The thing doesn't exist (404).
    NotFound(String),
    /// It already exists or clashes with something (409).
    Conflict(String),
    /// Storage or the system failed (422 / exit code 1).
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid(m) | Error::NotFound(m) | Error::Conflict(m) | Error::Failed(m) => f.write_str(m),
        }
    }
}

impl From<Error> for String {
    fn from(e: Error) -> String {
        e.to_string()
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Failed(format!("Email database: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Permissions an API key can have.
pub const PERMISSIONS: &[&str] = &["sending", "full"];

pub fn clean_domain(d: &str) -> Result<String> {
    crate::validate::domain(&d.trim().to_ascii_lowercase()).map_err(|e| Error::Invalid(e.to_string()))
}

pub fn clean_address(a: &str) -> Result<String> {
    crate::validate::email(&a.trim().to_ascii_lowercase()).map_err(|e| Error::Invalid(e.to_string()))
}

pub fn open(mc: &MailConfig) -> Result<Connection> {
    store::open(&mc.db_path()).map_err(|e| Error::Failed(format!("Could not open {}: {e}", mc.db_path().display())))
}

fn require_domain(conn: &Connection, domain: &str) -> Result<store::Domain> {
    store::get_domain(conn, domain)?.ok_or_else(|| Error::NotFound(format!("{domain} isn't a sending domain")))
}

// ---------- Install ----------

/// The mail hostname must not be one a site or the panel already answers on.
pub fn check_hostname_free(sites: &[crate::db::models::Site], panel_host: Option<&str>, hostname: &str) -> Result<()> {
    if let Some(site) = crate::services::panel_cert::site_on_hostname(sites, hostname) {
        return Err(Error::Conflict(format!(
            "The site {site} already answers on {hostname}. Use a dedicated name such as mail.{hostname}."
        )));
    }
    if panel_host.is_some_and(|h| h.eq_ignore_ascii_case(hostname)) {
        return Err(Error::Conflict(format!("{hostname} is the panel's own hostname")));
    }
    Ok(())
}

// ---------- Domains ----------

/// Add a sending domain with a DKIM key (reusing a key file left from an earlier add).
pub fn add_domain(conn: &Connection, mc: &MailConfig, domain: &str) -> Result<store::Domain> {
    let domain = clean_domain(domain)?;
    if store::get_domain(conn, &domain)?.is_some() {
        return Err(Error::Conflict(format!("{domain} is already a sending domain")));
    }
    let path = mc.dkim_key_path(&domain);
    let pem = match std::fs::read_to_string(&path) {
        Ok(p) => p,
        Err(_) => {
            let p = dkim::generate_key_pem().map_err(Error::Failed)?;
            std::fs::create_dir_all(mc.dkim_dir()).map_err(|e| Error::Failed(e.to_string()))?;
            install::write_owned(&path, p.as_bytes(), 0o600).map_err(Error::Failed)?;
            p
        }
    };
    let public = dkim::public_key_b64(&pem).map_err(Error::Failed)?;
    store::add_domain(conn, &domain, &public)?;
    require_domain(conn, &domain)
}

/// A DNS record to publish, in a shape the API can send.
#[derive(Debug, Clone, Serialize)]
pub struct RecordOut {
    pub kind: &'static str,
    pub name: String,
    pub value: String,
    pub priority: Option<u16>,
    pub purpose: &'static str,
    pub required: bool,
}

/// DKIM and SPF must be right before a domain can send; MX and DMARC are advised.
pub fn is_required(r: &dns::Record, domain: &str) -> bool {
    r.name.contains("._domainkey.") || (r.kind == "TXT" && r.name == domain)
}

fn record_out(r: dns::Record, domain: &str) -> RecordOut {
    let required = is_required(&r, domain);
    RecordOut {
        kind: r.kind,
        name: r.name,
        value: r.value,
        priority: r.priority,
        purpose: r.purpose,
        required,
    }
}

pub fn records(mc: &MailConfig, d: &store::Domain) -> Vec<RecordOut> {
    dns::records(&d.name, &mc.hostname, &d.dkim_public)
        .into_iter()
        .map(|r| record_out(r, &d.name))
        .collect()
}

pub fn domain_records(conn: &Connection, mc: &MailConfig, domain: &str) -> Result<Vec<RecordOut>> {
    let domain = clean_domain(domain)?;
    Ok(records(mc, &require_domain(conn, &domain)?))
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckOut {
    pub record: RecordOut,
    pub ok: bool,
    pub found: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    pub domain: String,
    pub verified: bool,
    /// Empty when the check was skipped (`force`).
    pub checks: Vec<CheckOut>,
}

/// Apply DNS check results: verified when every required record is right.
pub fn apply_checks(domain: &str, checks: Vec<dns::Check>) -> (bool, Vec<CheckOut>) {
    let out: Vec<CheckOut> = checks
        .into_iter()
        .map(|c| CheckOut {
            ok: c.ok,
            found: c.found,
            record: record_out(c.record, domain),
        })
        .collect();
    let verified = out.iter().all(|c| c.ok || !c.record.required);
    (verified, out)
}

/// Check a domain's DNS (blocking: it queries the resolver) and record the result. With `force`,
/// mark it verified without looking.
pub fn verify_domain(conn: &Connection, mc: &MailConfig, domain: &str, force: bool) -> Result<Verification> {
    let domain = clean_domain(domain)?;
    let d = require_domain(conn, &domain)?;
    if force {
        store::set_domain_verified(conn, &domain, true)?;
        return Ok(Verification {
            domain,
            verified: true,
            checks: Vec::new(),
        });
    }
    let (verified, checks) = apply_checks(&domain, dns::check(&domain, &mc.hostname, &d.dkim_public));
    store::set_domain_verified(conn, &domain, verified)?;
    Ok(Verification {
        domain,
        verified,
        checks,
    })
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DomainRemoval {
    pub forwards_removed: usize,
    pub keys_revoked: usize,
}

impl DomainRemoval {
    pub fn needs_postfix_sync(&self) -> bool {
        self.forwards_removed > 0
    }
}

/// Remove a domain, its DKIM key, its forwards and the keys limited to it.
pub fn remove_domain(conn: &Connection, mc: &MailConfig, domain: &str) -> Result<DomainRemoval> {
    let domain = clean_domain(domain)?;
    if !store::remove_domain(conn, &domain)? {
        return Err(Error::NotFound(format!("{domain} isn't a sending domain")));
    }
    let _ = std::fs::remove_file(mc.dkim_key_path(&domain));
    let mut out = DomainRemoval::default();
    for f in store::list_forwards(conn)? {
        if super::domain_of(&f.address).as_deref() == Some(domain.as_str()) {
            store::remove_forward(conn, &f.address)?;
            out.forwards_removed += 1;
        }
    }
    for k in store::list_keys(conn)? {
        if k.domain.as_deref() == Some(domain.as_str()) {
            store::remove_key(conn, &k.id)?;
            out.keys_revoked += 1;
        }
    }
    Ok(out)
}

// ---------- API keys ----------

/// Create a key. Returns it and the full secret, which is shown once.
pub fn create_key(
    conn: &Connection,
    name: &str,
    domain: Option<&str>,
    permission: &str,
    hourly_limit: u32,
) -> Result<(store::ApiKey, String)> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(Error::Invalid("The key name must be 1-64 characters".into()));
    }
    if !PERMISSIONS.contains(&permission) {
        return Err(Error::Invalid("The permission must be sending or full".into()));
    }
    if hourly_limit == 0 || hourly_limit > 1_000_000 {
        return Err(Error::Invalid("The hourly limit must be between 1 and 1000000".into()));
    }
    let domain = match domain.map(str::trim).filter(|d| !d.is_empty()) {
        Some(d) => {
            let d = clean_domain(d)?;
            require_domain(conn, &d)?;
            Some(d)
        }
        None => None,
    };
    let (key, full) = keys::generate(name, permission, domain, hourly_limit);
    store::add_key(conn, &key)?;
    Ok((key, full))
}

pub fn revoke_key(conn: &Connection, id: &str) -> Result<()> {
    if !store::remove_key(conn, id.trim())? {
        return Err(Error::NotFound(format!("No key with id {}", id.trim())));
    }
    Ok(())
}

// ---------- Forwards ----------

/// Forward mail for `address` (on a sending domain) to `to`. Postfix needs a sync afterwards.
pub fn add_forward(conn: &Connection, address: &str, to: &str) -> Result<store::Forward> {
    let address = clean_address(address)?;
    let to = clean_address(to)?;
    if address == to {
        return Err(Error::Invalid("An address can't forward to itself".into()));
    }
    let domain = super::domain_of(&address).unwrap_or_default();
    if store::get_domain(conn, &domain)?.is_none() {
        return Err(Error::Invalid(format!(
            "{domain} isn't a sending domain. Add it first."
        )));
    }
    let forwards = store::list_forwards(conn)?;
    if forwards.iter().any(|f| f.address == to) {
        return Err(Error::Invalid(format!(
            "{to} is itself forwarded; pick the final mailbox"
        )));
    }
    if forwards.iter().any(|f| f.forward_to == address) {
        return Err(Error::Invalid(format!(
            "Another address forwards to {address}; it can't forward on in turn"
        )));
    }
    store::add_forward(conn, &address, &to)?;
    store::list_forwards(conn)?
        .into_iter()
        .find(|f| f.address == address)
        .ok_or_else(|| Error::Failed("The forward wasn't saved".into()))
}

/// Remove a forward. Postfix needs a sync afterwards.
pub fn remove_forward(conn: &Connection, address: &str) -> Result<String> {
    let address = clean_address(address)?;
    if !store::remove_forward(conn, &address)? {
        return Err(Error::NotFound(format!("No forward for {address}")));
    }
    Ok(address)
}

// ---------- Webhooks ----------

/// Add a webhook. Returns it and its signing secret, which is shown once.
pub fn add_webhook(conn: &Connection, url: &str, kinds: &[String]) -> Result<(store::Webhook, String)> {
    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| Error::Invalid(format!("Invalid URL {}", url.trim())))?;
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
        return Err(Error::Invalid(
            "Webhook URLs must use https (http only for localhost)".into(),
        ));
    }
    if parsed.as_str().len() > 2048 {
        return Err(Error::Invalid("The URL is too long".into()));
    }
    let mut list: Vec<String> = Vec::new();
    for k in kinds.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !events::EVENT_TYPES.contains(&k) {
            return Err(Error::Invalid(format!(
                "Unknown event {k}. Use: {}",
                events::EVENT_TYPES.join(", ")
            )));
        }
        if !list.iter().any(|x| x == k) {
            list.push(k.to_string());
        }
    }
    let hook = store::Webhook {
        id: super::new_id(),
        url: parsed.to_string(),
        events: list,
        secret: events::new_secret(),
        created_at: super::now(),
    };
    store::add_webhook(conn, &hook)?;
    let secret = hook.secret.clone();
    Ok((hook, secret))
}

pub fn remove_webhook(conn: &Connection, id: &str) -> Result<()> {
    if !store::remove_webhook(conn, id.trim())? {
        return Err(Error::NotFound(format!("No webhook with id {}", id.trim())));
    }
    Ok(())
}

// ---------- Log ----------

pub const LOG_STATUSES: &[&str] = &["queued", "sent", "delivered", "delivery_delayed", "bounced", "failed"];

#[derive(Debug, Clone, Serialize)]
pub struct MessageDetail {
    #[serde(flatten)]
    pub message: store::MessageLog,
    pub events: Vec<store::Event>,
}

pub fn message(conn: &Connection, id: &str) -> Result<MessageDetail> {
    let message =
        store::get_message(conn, id.trim())?.ok_or_else(|| Error::NotFound(format!("No email {}", id.trim())))?;
    let events = store::events_for(conn, &message.id)?;
    Ok(MessageDetail { message, events })
}

pub fn messages(conn: &Connection, limit: u32, status: Option<&str>) -> Result<Vec<store::MessageLog>> {
    let status = status.map(str::trim).filter(|s| !s.is_empty());
    Ok(store::list_messages(conn, limit.clamp(1, 1000), status)?)
}

// ---------- Status ----------

#[derive(Debug, Clone, Serialize)]
pub struct Port {
    pub name: &'static str,
    pub addr: String,
    pub listening: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub hostname: String,
    /// `systemctl is-active` for the service, postfix and postsrsd.
    pub units: Vec<(String, String)>,
    pub ports: Vec<Port>,
    pub outbound_25: bool,
    pub domains: usize,
    pub verified_domains: usize,
    pub keys: usize,
    pub forwards: usize,
}

/// Units, local ports, outbound port 25 and counts. Blocking (it probes the network).
pub fn status(conn: &Connection, mc: &MailConfig) -> Result<Status> {
    use crate::services::cmd::{run_with, CmdOpts};
    let active = |u: &str| {
        let s = run_with("systemctl", &["is-active", u], &CmdOpts::default().timeout(10))
            .stdout
            .trim()
            .to_string();
        if s.is_empty() {
            "unknown".to_string()
        } else {
            s
        }
    };
    let units = [super::UNIT, "postfix", "postsrsd"]
        .iter()
        .map(|u| (u.to_string(), active(u)))
        .collect();
    let ports = [
        ("SMTP 587", "127.0.0.1:587".to_string()),
        ("SMTPS 465", "127.0.0.1:465".to_string()),
        ("Inbound 25", "127.0.0.1:25".to_string()),
        ("API", mc.http_addr.clone()),
    ]
    .into_iter()
    .map(|(name, addr)| {
        let listening = addr
            .parse()
            .ok()
            .is_some_and(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_secs(2)).is_ok());
        Port { name, addr, listening }
    })
    .collect();
    let domains = store::list_domains(conn)?;
    Ok(Status {
        hostname: mc.hostname.clone(),
        units,
        ports,
        outbound_25: install::outbound_25_open(),
        verified_domains: domains.iter().filter(|d| d.verified).count(),
        domains: domains.len(),
        keys: store::list_keys(conn)?.len(),
        forwards: store::list_forwards(conn)?.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mc(dir: &std::path::Path) -> MailConfig {
        let mut mc = MailConfig::from_env();
        mc.state_dir = dir.to_path_buf();
        mc.hostname = "mail.example.com".into();
        mc
    }

    fn setup() -> (tempfile::TempDir, MailConfig, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mc = mc(dir.path());
        let conn = store::open_memory();
        (dir, mc, conn)
    }

    #[test]
    fn domain_add_list_remove_cascades() {
        let (_d, mc, conn) = setup();
        let d = add_domain(&conn, &mc, " Example.COM ").unwrap();
        assert_eq!(d.name, "example.com");
        assert!(!d.verified);
        assert!(mc.dkim_key_path("example.com").exists());
        assert!(matches!(add_domain(&conn, &mc, "example.com"), Err(Error::Conflict(_))));
        assert!(matches!(add_domain(&conn, &mc, "not a domain"), Err(Error::Invalid(_))));

        let recs = domain_records(&conn, &mc, "example.com").unwrap();
        assert_eq!(recs.len(), 4);
        assert_eq!(recs.iter().filter(|r| r.required).count(), 2);

        add_forward(&conn, "hi@example.com", "me@gmail.com").unwrap();
        create_key(&conn, "bound", Some("example.com"), "sending", 10).unwrap();
        create_key(&conn, "any", None, "full", 10).unwrap();

        let r = remove_domain(&conn, &mc, "example.com").unwrap();
        assert_eq!(r.forwards_removed, 1);
        assert_eq!(r.keys_revoked, 1);
        assert!(r.needs_postfix_sync());
        assert!(!mc.dkim_key_path("example.com").exists());
        assert_eq!(store::list_keys(&conn).unwrap().len(), 1);
        assert!(matches!(
            remove_domain(&conn, &mc, "example.com"),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn key_validation() {
        let (_d, mc, conn) = setup();
        add_domain(&conn, &mc, "example.com").unwrap();
        for (name, domain, perm, limit) in [
            ("", None, "sending", 10),
            (&"x".repeat(65)[..], None, "sending", 10),
            ("ok", None, "admin", 10),
            ("ok", None, "sending", 0),
            ("ok", Some("other.com"), "sending", 10),
        ] {
            assert!(
                create_key(&conn, name, domain, perm, limit).is_err(),
                "{name} {domain:?} {perm} {limit}"
            );
        }
        let (k, full) = create_key(&conn, "gmail", Some("example.com"), "sending", 500).unwrap();
        assert!(full.starts_with("cp_"));
        assert_eq!(keys::parse(&full), Some(k.id.as_str()));
        revoke_key(&conn, &k.id).unwrap();
        assert!(matches!(revoke_key(&conn, &k.id), Err(Error::NotFound(_))));
    }

    #[test]
    fn forward_validation() {
        let (_d, mc, conn) = setup();
        add_domain(&conn, &mc, "example.com").unwrap();
        assert!(add_forward(&conn, "a@example.com", "a@example.com").is_err());
        assert!(add_forward(&conn, "a@other.com", "me@gmail.com").is_err());
        assert!(add_forward(&conn, "bad", "me@gmail.com").is_err());
        add_forward(&conn, "a@example.com", "me@gmail.com").unwrap();
        // Chains are refused both ways.
        assert!(add_forward(&conn, "b@example.com", "a@example.com").is_err());
        assert!(add_forward(&conn, "me@example.com", "x@gmail.com").is_ok());
        let f = add_forward(&conn, "a@example.com", "other@gmail.com").unwrap();
        assert_eq!(f.forward_to, "other@gmail.com");
        assert_eq!(remove_forward(&conn, "A@example.com").unwrap(), "a@example.com");
        assert!(matches!(
            remove_forward(&conn, "a@example.com"),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn webhook_validation() {
        let (_d, _mc, conn) = setup();
        assert!(add_webhook(&conn, "http://example.com/h", &[]).is_err());
        assert!(add_webhook(&conn, "nope", &[]).is_err());
        assert!(add_webhook(&conn, "https://example.com/h", &["email.opened".into()]).is_err());
        assert!(add_webhook(&conn, "http://localhost:9000/h", &[]).is_ok());
        let (w, secret) = add_webhook(
            &conn,
            "https://example.com/h",
            &["email.bounced".into(), "email.bounced".into()],
        )
        .unwrap();
        assert_eq!(w.events, vec!["email.bounced".to_string()]);
        assert!(!secret.is_empty());
        remove_webhook(&conn, &w.id).unwrap();
        assert!(remove_webhook(&conn, &w.id).is_err());
    }

    #[test]
    fn verify_rule_needs_dkim_and_spf_only() {
        let recs = dns::records("example.com", "mail.example.com", "AAAA");
        let checks = |oks: [bool; 4]| {
            recs.iter()
                .cloned()
                .zip(oks)
                .map(|(record, ok)| dns::Check {
                    record,
                    ok,
                    found: vec![],
                })
                .collect::<Vec<_>>()
        };
        // DKIM, SPF, MX, DMARC
        assert!(apply_checks("example.com", checks([true, true, false, false])).0);
        assert!(!apply_checks("example.com", checks([false, true, true, true])).0);
        assert!(!apply_checks("example.com", checks([true, false, true, true])).0);
    }

    #[test]
    fn force_verify() {
        let (_d, mc, conn) = setup();
        add_domain(&conn, &mc, "example.com").unwrap();
        let v = verify_domain(&conn, &mc, "example.com", true).unwrap();
        assert!(v.verified && v.checks.is_empty());
        assert!(store::get_domain(&conn, "example.com").unwrap().unwrap().verified);
    }

    #[test]
    fn hostname_clash() {
        assert!(check_hostname_free(&[], Some("Panel.example.com"), "panel.example.com").is_err());
        assert!(check_hostname_free(&[], Some("panel.example.com"), "mail.example.com").is_ok());
    }
}
