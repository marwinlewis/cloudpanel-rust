//! `cloudpanel mail-*`: setting up and managing the email service from the shell (as root).

use super::{install, manage, store, MailConfig};
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
    /// Rewrite Postfix's forwarding tables from the database (used by the panel)
    #[command(hide = true)]
    MailPostfixSync,
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
    Ok(manage::open(mc)?)
}

fn print_records(domain: &str, records: &[manage::RecordOut], host: &str) {
    println!("Add these DNS records for {domain}:\n");
    for r in records {
        let prio = r.priority.map(|p| format!(" (priority {p})")).unwrap_or_default();
        println!("  {} {}{prio}\n    {}\n    # {}\n", r.kind, r.name, r.value, r.purpose);
    }
    println!("Also set the reverse DNS (PTR) of this server's IP to {host} at your hosting provider.");
    println!("Then run: cloudpanel mail-domain-verify --domain {domain}");
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
            let hostname = manage::clean_domain(&hostname)?;
            let email = email.map(|e| manage::clean_address(&e)).transpose()?;
            if let Ok(pool) = crate::db::init_db(&config.db_path) {
                if let Ok(conn) = pool.get() {
                    let sites = crate::db::list_sites(&conn).unwrap_or_default();
                    let panel = crate::services::panel_cert::load(&conn).map(|t| t.hostname);
                    manage::check_hostname_free(&sites, panel.as_deref(), &hostname)?;
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
        MailCommand::MailPostfixSync => install::sync_postfix(&open(mc)?),
        MailCommand::MailDomainAdd { domain } => {
            let conn = open(mc)?;
            let d = manage::add_domain(&conn, mc, &domain)?;
            audit(config, "mail.domain_add", Some(&d.name));
            print_records(&d.name, &manage::records(mc, &d), &mc.hostname);
            Ok(())
        }
        MailCommand::MailDns { domain } => {
            let recs = manage::domain_records(&open(mc)?, mc, &domain)?;
            let domain = manage::clean_domain(&domain)?;
            print_records(&domain, &recs, &mc.hostname);
            Ok(())
        }
        MailCommand::MailDomainVerify { domain, force } => {
            let mc2 = mc.clone();
            let v = tokio::task::spawn_blocking(move || -> Result<manage::Verification, String> {
                Ok(manage::verify_domain(&open(&mc2)?, &mc2, &domain, force)?)
            })
            .await
            .map_err(|e| e.to_string())??;
            if force {
                audit(config, "mail.domain_verify", Some(&v.domain));
                println!("{} marked verified without a DNS check.", v.domain);
                return Ok(());
            }
            for c in &v.checks {
                let mark = if c.ok {
                    "ok     "
                } else if c.record.required {
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
            }
            if v.verified {
                audit(config, "mail.domain_verify", Some(&v.domain));
                println!("\n{} is verified and can send.", v.domain);
                Ok(())
            } else {
                Err(format!(
                    "\n{} isn't verified yet: DKIM and SPF are required. DNS changes can take a while to show up.",
                    v.domain
                ))
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
            let conn = open(mc)?;
            let r = manage::remove_domain(&conn, mc, &domain)?;
            if r.needs_postfix_sync() {
                install::sync_postfix(&conn)?;
            }
            let domain = manage::clean_domain(&domain)?;
            audit(config, "mail.domain_remove", Some(&domain));
            println!(
                "Removed {domain} ({} forward(s), {} key(s)). Remove its DNS records too.",
                r.forwards_removed, r.keys_revoked
            );
            Ok(())
        }
        MailCommand::MailKeyCreate {
            name,
            domain,
            permission,
            hourly_limit,
        } => {
            let conn = open(mc)?;
            let (key, full) = manage::create_key(&conn, &name, domain.as_deref(), &permission, hourly_limit)?;
            audit(config, "mail.key_create", Some(&key.id));
            let host = &mc.hostname;
            let from = key.domain.as_deref().unwrap_or("example.com");
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
            manage::revoke_key(&open(mc)?, &id)?;
            audit(config, "mail.key_revoke", Some(id.trim()));
            println!("Key {} revoked. Clients using it can no longer send.", id.trim());
            Ok(())
        }
        MailCommand::MailForwardAdd { address, to } => {
            let conn = open(mc)?;
            let f = manage::add_forward(&conn, &address, &to)?;
            install::sync_postfix(&conn)?;
            audit(config, "mail.forward_add", Some(&f.address));
            println!(
                "Mail to {} now goes to {}. The domain's MX record must point to {}.",
                f.address, f.forward_to, mc.hostname
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
            let conn = open(mc)?;
            let address = manage::remove_forward(&conn, &address)?;
            install::sync_postfix(&conn)?;
            audit(config, "mail.forward_remove", Some(&address));
            println!("Mail to {address} is no longer accepted.");
            Ok(())
        }
        MailCommand::MailWebhookAdd { url, events: kinds } => {
            let kinds: Vec<String> = kinds
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            let (hook, secret) = manage::add_webhook(&open(mc)?, &url, &kinds)?;
            audit(config, "mail.webhook_add", Some(&hook.url));
            println!("Webhook {} added.", hook.id);
            println!("Signing secret (shown once): {secret}");
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
            manage::remove_webhook(&open(mc)?, &id)?;
            audit(config, "mail.webhook_remove", Some(id.trim()));
            println!("Webhook {} removed.", id.trim());
            Ok(())
        }
        MailCommand::MailLog { limit, status, id } => {
            let conn = open(mc)?;
            if let Some(id) = id {
                let d = manage::message(&conn, &id)?;
                let m = &d.message;
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
                for e in d.events {
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
            for m in manage::messages(&conn, limit, status.as_deref())? {
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
            let mc2 = mc.clone();
            let s = tokio::task::spawn_blocking(move || -> Result<manage::Status, String> {
                Ok(manage::status(&open(&mc2)?, &mc2)?)
            })
            .await
            .map_err(|e| e.to_string())??;
            println!("Hostname          {}", s.hostname);
            for (unit, state) in &s.units {
                println!("{}  {state}", pad(unit, 16));
            }
            for p in &s.ports {
                println!(
                    "{}  {}",
                    pad(p.name, 16),
                    if p.listening { "listening" } else { "NOT listening" }
                );
            }
            println!(
                "{}  {}",
                pad("Outbound 25", 16),
                if s.outbound_25 { "open" } else { "BLOCKED" }
            );
            if !s.outbound_25 {
                println!("\n{}", install::PORT_25_WARNING);
            }
            println!(
                "\nDomains: {} ({} verified), keys: {}, forwards: {}",
                s.domains, s.verified_domains, s.keys, s.forwards
            );
            Ok(())
        }
    }
}
