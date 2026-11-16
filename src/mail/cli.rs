//! `cloudpanel mail-*`: setting up and managing the email service from the shell (as root).

use super::{dkim, dns, events, install, keys, store, MailConfig};
use crate::config::Config;
use clap::Subcommand;

/// Variant names become the commands (`MailInstall` is `mail-install`), so they share the prefix.
#[allow(clippy::enum_variant_names)]
#[derive(Subcommand, Debug)]
pub enum MailCommand {
    /// Install or update the email sending service (Postfix, SMTP on 587/465, API, forwarding)
    MailInstall {
        /// Public mail hostname: the MX target, SMTP server and API address, e.g. mail.example.com
        #[arg(long)]
        hostname: String,
        /// Address for Let's Encrypt's expiry notices (agrees to its terms)
        #[arg(long)]
        email: Option<String>,
        /// Use a self-signed certificate instead of Let's Encrypt
        #[arg(long)]
        self_signed: bool,
    },
    /// Remove the email service's unit, nginx site and firewall ports (keeps Postfix and data)
    MailUninstall,
    /// Run the email service (used by cloudpanel-mail.service)
    MailServe,
    /// Copy a renewed certificate to the email service (used by certbot's deploy hook)
    MailCertSync,
    /// Add a sending domain and print the DNS records to publish
    MailDomainAdd {
        #[arg(long)]
        domain: String,
    },
    /// Check a domain's DNS records and mark it verified when DKIM and SPF are right
    MailDomainVerify {
        #[arg(long)]
        domain: String,
        /// Mark it verified without looking at DNS (split-horizon DNS, tests)
        #[arg(long)]
        force: bool,
    },
    /// List sending domains
    MailDomainList,
    /// Print a domain's DNS records again
    MailDns {
        #[arg(long)]
        domain: String,
    },
    /// Remove a sending domain, its DKIM key and its forwards
    MailDomainRemove {
        #[arg(long)]
        domain: String,
    },
    /// Create an API key (shown once). It is the SMTP password and the API's Bearer token
    MailKeyCreate {
        #[arg(long)]
        name: String,
        /// Only allow sending from this domain
        #[arg(long)]
        domain: Option<String>,
        /// full can read every email's status through the API; sending only its own
        #[arg(long, default_value = "sending", value_parser = ["sending", "full"])]
        permission: String,
        #[arg(long, default_value_t = super::DEFAULT_HOURLY_LIMIT)]
        hourly_limit: u32,
    },
    /// List API keys
    MailKeyList,
    /// Revoke an API key
    MailKeyRevoke {
        #[arg(long)]
        id: String,
    },
    /// Forward mail for an address on a sending domain to another mailbox (e.g. Gmail)
    MailForwardAdd {
        #[arg(long)]
        address: String,
        #[arg(long)]
        to: String,
    },
    /// List forwards
    MailForwardList,
    /// Remove a forward
    MailForwardRemove {
        #[arg(long)]
        address: String,
    },
    /// Call a URL when emails are sent, delivered, delayed or bounce (prints the signing secret)
    MailWebhookAdd {
        #[arg(long)]
        url: String,
        /// Comma-separated: email.sent, email.delivered, email.delivery_delayed, email.bounced (default: all)
        #[arg(long)]
        events: Option<String>,
    },
    /// List webhooks
    MailWebhookList,
    /// Remove a webhook
    MailWebhookRemove {
        #[arg(long)]
        id: String,
    },
    /// Show sent emails, or one email's events with --id
    MailLog {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        id: Option<String>,
    },
    /// Check the email service: units, ports, outbound port 25, domains
    MailStatus,
}

type R = Result<(), String>;

fn audit(config: &Config, action: &str, target: Option<&str>) {
    if let Ok(pool) = crate::db::init_db(&config.db_path) {
        if let Ok(conn) = pool.get() {
            crate::audit::record_system(&conn, None, None, action, target, Some("cli"));
        }
    }
}

fn open(mc: &MailConfig) -> Result<rusqlite::Connection, String> {
    store::open(&mc.db_path()).map_err(|e| format!("Could not open {}: {e}", mc.db_path().display()))
}

fn print_records(domain: &str, host: &str, dkim_public: &str) {
    println!("Add these DNS records for {domain}:\n");
    for r in dns::records(domain, host, dkim_public) {
        let prio = r.priority.map(|p| format!(" (priority {p})")).unwrap_or_default();
        println!("  {} {}{prio}\n    {}\n    # {}\n", r.kind, r.name, r.value, r.purpose);
    }
    println!("Also set the reverse DNS (PTR) of this server's IP to {host} at your hosting provider.");
    println!("Then run: cloudpanel mail-domain-verify --domain {domain}");
}

fn clean_domain(d: &str) -> Result<String, String> {
    crate::validate::domain(&d.trim().to_ascii_lowercase()).map_err(|e| e.to_string())
}

fn clean_address(a: &str) -> Result<String, String> {
    crate::validate::email(&a.trim().to_ascii_lowercase()).map_err(|e| e.to_string())
}

fn pad(s: &str, n: usize) -> String {
    format!("{s:<n$}")
}

/// Run one mail command. Returns the process exit code.
pub async fn run(config: &Config, cmd: MailCommand) -> Result<i32, String> {
    let mc = MailConfig::from_env();
    let needs_install = !matches!(cmd, MailCommand::MailInstall { .. } | MailCommand::MailServe);
    if needs_install && cfg!(target_os = "linux") && !install::installed(config) {
        return Err("The email service isn't installed. Run: cloudpanel mail-install --hostname mail.example.com --email you@example.com".into());
    }
    let result = run_inner(config, &mc, cmd).await;
    // Root just wrote to the service's database; give it back.
    if crate::fsutil::running_as_root() {
        install::fix_db_ownership(&mc);
    }
    result.map(|()| 0)
}

async fn run_inner(config: &Config, mc: &MailConfig, cmd: MailCommand) -> R {
    match cmd {
        MailCommand::MailInstall {
            hostname,
            email,
            self_signed,
        } => {
            let hostname = clean_domain(&hostname)?;
            let email = email.map(|e| clean_address(&e)).transpose()?;
            if let Ok(pool) = crate::db::init_db(&config.db_path) {
                if let Ok(conn) = pool.get() {
                    let sites = crate::db::list_sites(&conn).unwrap_or_default();
                    if let Some(site) = crate::services::panel_cert::site_on_hostname(&sites, &hostname) {
                        return Err(format!("The site {site} already answers on {hostname}. Use a dedicated name such as mail.{hostname}."));
                    }
                    if crate::services::panel_cert::load(&conn)
                        .is_some_and(|t| t.hostname.eq_ignore_ascii_case(&hostname))
                    {
                        return Err(format!("{hostname} is the panel's own hostname"));
                    }
                }
            }
            let opts = install::InstallOptions {
                hostname: hostname.clone(),
                email,
                self_signed,
            };
            install::install(config, mc, &opts, &|l| println!("{l}")).await?;
            audit(config, "mail.install", Some(&hostname));
            println!("\nThe email service is running on {hostname}.");
            println!(
                "  SMTP  {hostname}:587 (STARTTLS) and :465 (SSL/TLS), username {}",
                super::SMTP_USERNAME
            );
            println!("  API   https://{hostname}/emails");
            println!("\nNext: cloudpanel mail-domain-add --domain example.com");
            Ok(())
        }
        MailCommand::MailUninstall => {
            install::uninstall(config, &|l| println!("{l}"))?;
            audit(config, "mail.uninstall", None);
            Ok(())
        }
        MailCommand::MailServe => super::serve::run(mc.clone()).await,
        MailCommand::MailCertSync => install::sync_cert(mc),
        MailCommand::MailDomainAdd { domain } => {
            let domain = clean_domain(&domain)?;
            let conn = open(mc)?;
            if store::get_domain(&conn, &domain).map_err(|e| e.to_string())?.is_some() {
                return Err(format!(
                    "{domain} is already a sending domain. Its records: cloudpanel mail-dns --domain {domain}"
                ));
            }
            let path = mc.dkim_key_path(&domain);
            let pem = match std::fs::read_to_string(&path) {
                Ok(p) => p,
                Err(_) => {
                    let p = dkim::generate_key_pem()?;
                    std::fs::create_dir_all(mc.dkim_dir()).map_err(|e| e.to_string())?;
                    install::write_owned(&path, p.as_bytes(), 0o600)?;
                    p
                }
            };
            let public = dkim::public_key_b64(&pem)?;
            store::add_domain(&conn, &domain, &public).map_err(|e| e.to_string())?;
            audit(config, "mail.domain_add", Some(&domain));
            print_records(&domain, &mc.hostname, &public);
            Ok(())
        }
        MailCommand::MailDns { domain } => {
            let domain = clean_domain(&domain)?;
            let d = store::get_domain(&open(mc)?, &domain)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("{domain} isn't a sending domain"))?;
            print_records(&domain, &mc.hostname, &d.dkim_public);
            Ok(())
        }
        MailCommand::MailDomainVerify { domain, force } => {
            let domain = clean_domain(&domain)?;
            let conn = open(mc)?;
            let d = store::get_domain(&conn, &domain)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("{domain} isn't a sending domain"))?;
            if force {
                store::set_domain_verified(&conn, &domain, true).map_err(|e| e.to_string())?;
                audit(config, "mail.domain_verify", Some(&domain));
                println!("{domain} marked verified without a DNS check.");
                return Ok(());
            }
            let (host, public, dom) = (mc.hostname.clone(), d.dkim_public.clone(), domain.clone());
            let checks = tokio::task::spawn_blocking(move || dns::check(&dom, &host, &public))
                .await
                .map_err(|e| e.to_string())?;
            let mut required_ok = true;
            for c in &checks {
                let required =
                    c.record.name.contains("._domainkey.") || (c.record.kind == "TXT" && c.record.name == domain);
                let mark = if c.ok {
                    "ok     "
                } else if required {
                    "MISSING"
                } else {
                    "missing"
                };
                println!("{mark} {} {}", c.record.kind, c.record.name);
                if !c.ok {
                    println!("        want: {}", c.record.value);
                    for f in &c.found {
                        println!("        have: {f}");
                    }
                }
                required_ok &= c.ok || !required;
            }
            store::set_domain_verified(&conn, &domain, required_ok).map_err(|e| e.to_string())?;
            if required_ok {
                audit(config, "mail.domain_verify", Some(&domain));
                println!("\n{domain} is verified and can send.");
                Ok(())
            } else {
                Err(format!("\n{domain} isn't verified yet: DKIM and SPF are required. DNS changes can take a while to show up."))
            }
        }
        MailCommand::MailDomainList => {
            let conn = open(mc)?;
            println!("{} {} CREATED", pad("DOMAIN", 36), pad("STATUS", 10));
            for d in store::list_domains(&conn).map_err(|e| e.to_string())? {
                println!(
                    "{} {} {}",
                    pad(&d.name, 36),
                    pad(if d.verified { "verified" } else { "pending" }, 10),
                    d.created_at
                );
            }
            Ok(())
        }
        MailCommand::MailDomainRemove { domain } => {
            let domain = clean_domain(&domain)?;
            let conn = open(mc)?;
            if !store::remove_domain(&conn, &domain).map_err(|e| e.to_string())? {
                return Err(format!("{domain} isn't a sending domain"));
            }
            let _ = std::fs::remove_file(mc.dkim_key_path(&domain));
            let mut removed = 0;
            for f in store::list_forwards(&conn).map_err(|e| e.to_string())? {
                if super::domain_of(&f.address).as_deref() == Some(domain.as_str()) {
                    store::remove_forward(&conn, &f.address).map_err(|e| e.to_string())?;
                    removed += 1;
                }
            }
            if removed > 0 {
                install::sync_postfix(&conn)?;
            }
            audit(config, "mail.domain_remove", Some(&domain));
            println!("Removed {domain} ({removed} forward(s)). Remove its DNS records too.");
            Ok(())
        }
        MailCommand::MailKeyCreate {
            name,
            domain,
            permission,
            hourly_limit,
        } => {
            let name = name.trim().to_string();
            if name.is_empty() || name.len() > 64 {
                return Err("--name must be 1-64 characters".into());
            }
            let conn = open(mc)?;
            let domain = match domain {
                Some(d) => {
                    let d = clean_domain(&d)?;
                    if store::get_domain(&conn, &d).map_err(|e| e.to_string())?.is_none() {
                        return Err(format!(
                            "{d} isn't a sending domain. Add it first: cloudpanel mail-domain-add --domain {d}"
                        ));
                    }
                    Some(d)
                }
                None => None,
            };
            if hourly_limit == 0 {
                return Err("--hourly-limit must be at least 1".into());
            }
            let (key, full) = keys::generate(&name, &permission, domain.clone(), hourly_limit);
            store::add_key(&conn, &key).map_err(|e| e.to_string())?;
            audit(config, "mail.key_create", Some(&key.id));
            let host = &mc.hostname;
            let from = domain.as_deref().unwrap_or("example.com");
            println!("API key (shown once, store it now):\n\n  {full}\n");
            println!("Gmail > Settings > Accounts > Send mail as > Add another email address:");
            println!("  SMTP server  {host}");
            println!("  Port         587 (TLS) or 465 (SSL)");
            println!("  Username     {}", super::SMTP_USERNAME);
            println!("  Password     the API key above\n");
            println!("HTTP API:");
            println!("  curl -X POST https://{host}/emails \\");
            println!("    -H 'Authorization: Bearer {full}' -H 'Content-Type: application/json' \\");
            println!("    -d '{{\"from\":\"you@{from}\",\"to\":\"someone@example.org\",\"subject\":\"Hello\",\"text\":\"Hi\"}}'");
            Ok(())
        }
        MailCommand::MailKeyList => {
            let conn = open(mc)?;
            println!(
                "{} {} {} {} {} LAST USED",
                pad("ID", 13),
                pad("NAME", 20),
                pad("PERMISSION", 10),
                pad("DOMAIN", 24),
                pad("PER HOUR", 8)
            );
            for k in store::list_keys(&conn).map_err(|e| e.to_string())? {
                println!(
                    "{} {} {} {} {} {}",
                    pad(&k.id, 13),
                    pad(&k.name, 20),
                    pad(&k.permission, 10),
                    pad(k.domain.as_deref().unwrap_or("any"), 24),
                    pad(&k.hourly_limit.to_string(), 8),
                    k.last_used_at.as_deref().unwrap_or("never")
                );
            }
            Ok(())
        }
        MailCommand::MailKeyRevoke { id } => {
            let conn = open(mc)?;
            if !store::remove_key(&conn, id.trim()).map_err(|e| e.to_string())? {
                return Err(format!("No key with id {id}"));
            }
            audit(config, "mail.key_revoke", Some(&id));
            println!("Key {id} revoked. Clients using it can no longer send.");
            Ok(())
        }
        MailCommand::MailForwardAdd { address, to } => {
            let address = clean_address(&address)?;
            let to = clean_address(&to)?;
            if address == to {
                return Err("An address can't forward to itself".into());
            }
            let conn = open(mc)?;
            let domain = super::domain_of(&address).unwrap_or_default();
            if store::get_domain(&conn, &domain).map_err(|e| e.to_string())?.is_none() {
                return Err(format!(
                    "{domain} isn't a sending domain. Add it first: cloudpanel mail-domain-add --domain {domain}"
                ));
            }
            if store::list_forwards(&conn)
                .map_err(|e| e.to_string())?
                .iter()
                .any(|f| f.address == to)
            {
                return Err(format!("{to} is itself forwarded; pick the final mailbox"));
            }
            store::add_forward(&conn, &address, &to).map_err(|e| e.to_string())?;
            install::sync_postfix(&conn)?;
            audit(config, "mail.forward_add", Some(&address));
            println!(
                "Mail to {address} now goes to {to}. The domain's MX record must point to {}.",
                mc.hostname
            );
            Ok(())
        }
        MailCommand::MailForwardList => {
            for f in store::list_forwards(&open(mc)?).map_err(|e| e.to_string())? {
                println!("{} -> {}", f.address, f.forward_to);
            }
            Ok(())
        }
        MailCommand::MailForwardRemove { address } => {
            let address = clean_address(&address)?;
            let conn = open(mc)?;
            if !store::remove_forward(&conn, &address).map_err(|e| e.to_string())? {
                return Err(format!("No forward for {address}"));
            }
            install::sync_postfix(&conn)?;
            audit(config, "mail.forward_remove", Some(&address));
            println!("Mail to {address} is no longer accepted.");
            Ok(())
        }
        MailCommand::MailWebhookAdd { url, events: kinds } => {
            let parsed = reqwest::Url::parse(url.trim()).map_err(|_| format!("Invalid URL {url}"))?;
            let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
                return Err("Webhook URLs must use https (http only for localhost)".into());
            }
            let kinds: Vec<String> = kinds
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if let Some(bad) = kinds.iter().find(|k| !events::EVENT_TYPES.contains(&k.as_str())) {
                return Err(format!("Unknown event {bad}. Use: {}", events::EVENT_TYPES.join(", ")));
            }
            let hook = store::Webhook {
                id: super::new_id(),
                url: parsed.to_string(),
                events: kinds,
                secret: events::new_secret(),
                created_at: super::now(),
            };
            store::add_webhook(&open(mc)?, &hook).map_err(|e| e.to_string())?;
            audit(config, "mail.webhook_add", Some(&hook.url));
            println!("Webhook {} added.", hook.id);
            println!("Signing secret (shown once): {}", hook.secret);
            println!("Requests carry svix-id, svix-timestamp and svix-signature headers, as Resend's do.");
            Ok(())
        }
        MailCommand::MailWebhookList => {
            for w in store::list_webhooks(&open(mc)?).map_err(|e| e.to_string())? {
                let ev = if w.events.is_empty() {
                    "all events".into()
                } else {
                    w.events.join(",")
                };
                println!("{}  {}  {ev}", w.id, w.url);
            }
            Ok(())
        }
        MailCommand::MailWebhookRemove { id } => {
            if !store::remove_webhook(&open(mc)?, id.trim()).map_err(|e| e.to_string())? {
                return Err(format!("No webhook with id {id}"));
            }
            audit(config, "mail.webhook_remove", Some(&id));
            println!("Webhook {id} removed.");
            Ok(())
        }
        MailCommand::MailLog { limit, status, id } => {
            let conn = open(mc)?;
            if let Some(id) = id {
                let m = store::get_message(&conn, &id)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("No email {id}"))?;
                println!(
                    "{}  {}  {} -> {}  {:?}",
                    m.created_at,
                    m.status,
                    m.from,
                    m.to.join(", "),
                    m.subject
                );
                println!(
                    "  message-id {}  queue {}",
                    m.message_id,
                    m.queue_id.as_deref().unwrap_or("-")
                );
                for e in store::events_for(&conn, &m.id).map_err(|e| e.to_string())? {
                    println!(
                        "  {} {} {} {}",
                        e.created_at,
                        e.kind,
                        e.recipient.unwrap_or_default(),
                        e.detail.unwrap_or_default()
                    );
                }
                return Ok(());
            }
            for m in store::list_messages(&conn, limit.min(1000), status.as_deref()).map_err(|e| e.to_string())? {
                println!(
                    "{}  {}  {}  {} -> {}  {}",
                    m.created_at,
                    m.id,
                    pad(&m.status, 16),
                    m.from,
                    m.to.join(","),
                    m.subject
                );
            }
            Ok(())
        }
        MailCommand::MailStatus => {
            use crate::services::cmd::{run_with, CmdOpts};
            let active = |u: &str| {
                run_with("systemctl", &["is-active", u], &CmdOpts::default())
                    .stdout
                    .trim()
                    .to_string()
            };
            println!("Hostname          {}", mc.hostname);
            println!("{}  {}", pad(super::UNIT, 16), active(super::UNIT));
            println!("{}  {}", pad("postfix", 16), active("postfix"));
            println!("{}  {}", pad("postsrsd", 16), active("postsrsd"));
            for (name, addr) in [
                ("SMTP 587", "127.0.0.1:587"),
                ("SMTPS 465", "127.0.0.1:465"),
                ("Inbound 25", "127.0.0.1:25"),
                ("API", mc.http_addr.as_str()),
            ] {
                let up = addr.parse().ok().is_some_and(|a| {
                    std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_secs(2)).is_ok()
                });
                println!("{}  {}", pad(name, 16), if up { "listening" } else { "NOT listening" });
            }
            let out25 = tokio::task::spawn_blocking(install::outbound_25_open)
                .await
                .unwrap_or(false);
            println!("{}  {}", pad("Outbound 25", 16), if out25 { "open" } else { "BLOCKED" });
            if !out25 {
                println!("\n{}", install::PORT_25_WARNING);
            }
            let conn = open(mc)?;
            let domains = store::list_domains(&conn).map_err(|e| e.to_string())?;
            println!(
                "\nDomains: {} ({} verified), keys: {}, forwards: {}",
                domains.len(),
                domains.iter().filter(|d| d.verified).count(),
                store::list_keys(&conn).map_err(|e| e.to_string())?.len(),
                store::list_forwards(&conn).map_err(|e| e.to_string())?.len()
            );
            Ok(())
        }
    }
}
