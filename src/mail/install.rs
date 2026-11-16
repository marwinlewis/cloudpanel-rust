//! Setting up the email service on the host: Postfix (queue, delivery, inbound forwarding),
//! postsrsd (SRS for forwarded mail), the service's user, unit, certificate and firewall ports.
//! Runs as root from `cloudpanel mail-install`. Running it again is safe.

use super::{store, MailConfig, ENV_FILE, UNIT, USER};
use crate::config::Config;
use crate::services::cmd::{run_with, CmdOpts};
use std::path::{Path, PathBuf};

const VIRTUAL_MAP: &str = "/etc/postfix/cloudpanel_virtual";
const VIRTUAL_DOMAINS: &str = "/etc/postfix/cloudpanel_virtual_domains";
const SELF_SIGNED_DIR: &str = "/etc/cloudpanel/mail";
const DEPLOY_HOOK: &str = "/etc/letsencrypt/renewal-hooks/deploy/cloudpanel-mail";
/// Ports opened in the firewall: inbound mail, implicit TLS and STARTTLS submission.
pub const PORTS: [u16; 3] = [25, 465, 587];

pub struct InstallOptions {
    pub hostname: String,
    pub email: Option<String>,
    pub self_signed: bool,
}

fn sh(log: &dyn Fn(&str), program: &str, args: &[&str]) -> Result<String, String> {
    sh_opts(log, program, args, CmdOpts::default().timeout(600))
}

fn sh_opts(log: &dyn Fn(&str), program: &str, args: &[&str], opts: CmdOpts) -> Result<String, String> {
    let r = run_with(program, args, &opts);
    let out = r.combined();
    if !r.success() {
        return Err(format!("{program} {} failed: {}", args.join(" "), out.trim()));
    }
    for l in out.lines().filter(|l| !l.trim().is_empty()).take(20) {
        log(l);
    }
    Ok(out)
}

fn ok(program: &str, args: &[&str]) -> bool {
    run_with(program, args, &CmdOpts::default().timeout(60)).success()
}

/// Is the service set up on this host?
pub fn installed(config: &Config) -> bool {
    config.systemd_dir.join(UNIT).is_file()
}

/// The service user's uid and gid.
pub fn service_owner() -> Option<(u32, u32)> {
    let uid = run_with("id", &["-u", USER], &CmdOpts::default())
        .stdout
        .trim()
        .parse()
        .ok()?;
    let gid = run_with("id", &["-g", USER], &CmdOpts::default())
        .stdout
        .trim()
        .parse()
        .ok()?;
    Some((uid, gid))
}

/// Give the database (and its WAL files) back to the service after root touched it.
pub fn fix_db_ownership(mc: &MailConfig) {
    let Some(owner) = service_owner() else { return };
    let db = mc.db_path();
    for p in [
        db.clone(),
        PathBuf::from(format!("{}-wal", db.display())),
        PathBuf::from(format!("{}-shm", db.display())),
    ] {
        if p.exists() {
            let _ = crate::fsutil::lchown(&p, Some(owner));
        }
    }
}

/// Write `contents` owned by the service user with `mode`.
pub fn write_owned(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    crate::fsutil::write_atomic(path, contents, mode)
        .map_err(|e| format!("Could not write {}: {e}", path.display()))?;
    if let Some(owner) = service_owner() {
        crate::fsutil::lchown(path, Some(owner)).map_err(|e| format!("Could not chown {}: {e}", path.display()))?;
    }
    Ok(())
}

// ---------- Postfix maps ----------

/// `address destination` lines and `domain OK` lines for the forwards.
pub fn render_maps(forwards: &[store::Forward]) -> (String, String) {
    let mut map = String::from("# Managed by CloudPanel (cloudpanel mail-forward-*). Changes are overwritten.\n");
    let mut domains: Vec<String> = Vec::new();
    for f in forwards {
        map.push_str(&format!("{} {}\n", f.address, f.forward_to));
        if let Some(d) = super::domain_of(&f.address) {
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
    }
    domains.sort();
    let mut dom = String::from("# Managed by CloudPanel. Domains that receive mail here to forward it.\n");
    for d in domains {
        dom.push_str(&format!("{d} OK\n"));
    }
    (map, dom)
}

/// Rewrite Postfix's forwarding tables from the database and reload it.
pub fn sync_postfix(conn: &rusqlite::Connection) -> Result<(), String> {
    let forwards = store::list_forwards(conn).map_err(|e| e.to_string())?;
    let (map, dom) = render_maps(&forwards);
    for (path, content) in [(VIRTUAL_MAP, map), (VIRTUAL_DOMAINS, dom)] {
        crate::fsutil::write_atomic(Path::new(path), content.as_bytes(), 0o644)
            .map_err(|e| format!("Could not write {path}: {e}"))?;
        let r = run_with("postmap", &[path], &CmdOpts::default().timeout(30));
        if !r.success() {
            return Err(format!("postmap {path} failed: {}", r.combined().trim()));
        }
    }
    let r = run_with("postfix", &["reload"], &CmdOpts::default().timeout(30));
    if !r.success() {
        return Err(format!("postfix reload failed: {}", r.combined().trim()));
    }
    Ok(())
}

/// `main.cf` settings. Outbound mail only comes in through `sendmail` from the service (and root);
/// port 25 accepts nothing but mail for forwarding addresses, from anyone, including localhost.
pub fn main_cf(hostname: &str) -> Vec<String> {
    [
        format!("myhostname = {hostname}"),
        "myorigin = $myhostname".into(),
        "mydestination = $myhostname, localhost.localdomain, localhost".into(),
        "inet_interfaces = all".into(),
        "inet_protocols = all".into(),
        "mynetworks = 127.0.0.0/8 [::1]/128".into(),
        "smtpd_relay_restrictions = reject_unauth_destination".into(),
        "smtpd_recipient_restrictions = reject_unauth_destination".into(),
        format!("authorized_submit_users = root, {USER}"),
        format!("virtual_alias_domains = hash:{VIRTUAL_DOMAINS}"),
        format!("virtual_alias_maps = hash:{VIRTUAL_MAP}"),
        "message_size_limit = 36700160".into(),
        "smtpd_tls_security_level = may".into(),
        "smtp_tls_security_level = may".into(),
        "smtpd_tls_protocols = >=TLSv1.2".into(),
        "smtp_tls_loglevel = 1".into(),
        "smtpd_helo_required = yes".into(),
        "disable_vrfy_command = yes".into(),
        "maximal_queue_lifetime = 2d".into(),
        "bounce_queue_lifetime = 2d".into(),
    ]
    .to_vec()
}

/// Which postsrsd this is, and the Postfix lookup tables for it.
fn srs_maps() -> Option<(String, String)> {
    if Path::new("/etc/postsrsd.conf").exists() {
        // postsrsd 2.x (Debian 13): a socketmap inside Postfix's chroot.
        Some(("socketmap:unix:srs:forward".into(), "socketmap:unix:srs:reverse".into()))
    } else if Path::new("/etc/default/postsrsd").exists() {
        // postsrsd 1.x (Debian 12): TCP lookup tables.
        Some(("tcp:127.0.0.1:10001".into(), "tcp:127.0.0.1:10002".into()))
    } else {
        None
    }
}

/// Set `key` to `value` in a `key = value` / `KEY=value` file, adding it when missing.
pub fn set_config_line(text: &str, key: &str, line: &str) -> String {
    let mut found = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            let t = l.trim_start().trim_start_matches('#').trim_start();
            let is_key = t.starts_with(key) && t[key.len()..].trim_start().starts_with('=');
            if is_key && !found {
                found = true;
                line.to_string()
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        out.push(line.to_string());
    }
    out.join("\n") + "\n"
}

fn configure_srs(log: &dyn Fn(&str), hostname: &str) -> Result<(), String> {
    let Some((fwd, rev)) = srs_maps() else {
        log("postsrsd is not available: forwarded mail is sent without SRS and may fail SPF checks.");
        return Ok(());
    };
    if Path::new("/etc/postsrsd.conf").exists() {
        let text = std::fs::read_to_string("/etc/postsrsd.conf").unwrap_or_default();
        let text = set_config_line(&text, "srs-domain", &format!("srs-domain = \"{hostname}\""));
        crate::fsutil::write_atomic(Path::new("/etc/postsrsd.conf"), text.as_bytes(), 0o644)
            .map_err(|e| format!("Could not write /etc/postsrsd.conf: {e}"))?;
    } else {
        let text = std::fs::read_to_string("/etc/default/postsrsd").unwrap_or_default();
        let text = set_config_line(&text, "SRS_DOMAIN", &format!("SRS_DOMAIN={hostname}"));
        crate::fsutil::write_atomic(Path::new("/etc/default/postsrsd"), text.as_bytes(), 0o644)
            .map_err(|e| format!("Could not write /etc/default/postsrsd: {e}"))?;
    }
    // Only mail that arrives on port 25 (to be forwarded, or bounces of forwarded mail) goes
    // through SRS. Mail sent by the service keeps its own envelope sender, so DMARC stays aligned.
    sh(
        log,
        "postconf",
        &["-M", "cleanup_srs/unix=cleanup_srs unix n - y - 0 cleanup"],
    )?;
    for p in [
        format!("cleanup_srs/unix/sender_canonical_maps={fwd}"),
        "cleanup_srs/unix/sender_canonical_classes=envelope_sender".into(),
        format!("cleanup_srs/unix/recipient_canonical_maps={rev}"),
        "cleanup_srs/unix/recipient_canonical_classes=envelope_recipient,header_recipient".into(),
        "smtp/inet/cleanup_service_name=cleanup_srs".into(),
    ] {
        sh(log, "postconf", &["-P", &p])?;
    }
    sh(log, "systemctl", &["enable", "postsrsd"])?;
    sh(log, "systemctl", &["restart", "postsrsd"])?;
    Ok(())
}

// ---------- Certificate ----------

fn self_signed(log: &dyn Fn(&str), hostname: &str) -> Result<(PathBuf, PathBuf), String> {
    let dir = Path::new(SELF_SIGNED_DIR);
    crate::fsutil::create_private_dir(dir, 0o700).map_err(|e| format!("Could not create {SELF_SIGNED_DIR}: {e}"))?;
    let (cert, key) = (dir.join("selfsigned.crt"), dir.join("selfsigned.key"));
    if !cert.exists() || !key.exists() {
        log("Creating a self-signed certificate");
        sh(
            log,
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-subj",
                &format!("/CN={hostname}"),
                "-addext",
                &format!("subjectAltName=DNS:{hostname}"),
                "-keyout",
                &key.to_string_lossy(),
                "-out",
                &cert.to_string_lossy(),
            ],
        )?;
        crate::fsutil::set_mode(&key, 0o600).map_err(|e| e.to_string())?;
    }
    Ok((cert, key))
}

/// Copy the certificate where the service can read it, and tell the service to reload it.
pub fn sync_cert(mc: &MailConfig) -> Result<(), String> {
    let (Some(cert), Some(key)) = (&mc.cert_source, &mc.key_source) else {
        return Err("No certificate is configured. Run cloudpanel mail-install.".into());
    };
    let c = std::fs::read(cert).map_err(|e| format!("Could not read {}: {e}", cert.display()))?;
    let k = std::fs::read(key).map_err(|e| format!("Could not read {}: {e}", key.display()))?;
    let dir = mc.tls_cert.parent().unwrap_or(&mc.state_dir).to_path_buf();
    crate::fsutil::create_private_dir(&dir, 0o700).map_err(|e| e.to_string())?;
    if let Some(owner) = service_owner() {
        let _ = crate::fsutil::lchown(&dir, Some(owner));
    }
    write_owned(&mc.tls_cert, &c, 0o644)?;
    write_owned(&mc.tls_key, &k, 0o600)?;
    let _ = run_with("systemctl", &["reload", UNIT], &CmdOpts::default().timeout(30));
    Ok(())
}

// ---------- Unit ----------

pub fn render_unit(binary: &str, state_dir: &str) -> String {
    format!(
        r#"# Managed by CloudPanel - changes will be overwritten
[Unit]
Description=CloudPanel email sending service (SMTP + API)
Documentation=https://github.com/marwinlewis/cloudpanel-rust
After=network-online.target postfix.service
Wants=network-online.target postfix.service

[Service]
Type=simple
User={USER}
Group={USER}
# postdrop: hand mail to Postfix through sendmail. systemd-journal: follow delivery results.
SupplementaryGroups=postdrop systemd-journal
EnvironmentFile={ENV_FILE}
ExecStart={binary} mail-serve
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={state_dir} /var/spool/postfix/maildrop /var/spool/postfix/public
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
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
"#
    )
}

fn render_env(hostname: &str, state_dir: &Path, cert: &Path, key: &Path, acme_email: &str) -> String {
    format!(
        "# Managed by CloudPanel (cloudpanel mail-install)\nCLOUDPANEL_MAIL_HOST={hostname}\nCLOUDPANEL_MAIL_DIR={}\nCLOUDPANEL_MAIL_CERT_SOURCE={}\nCLOUDPANEL_MAIL_KEY_SOURCE={}\nCLOUDPANEL_MAIL_ACME_EMAIL={acme_email}\n",
        state_dir.display(),
        cert.display(),
        key.display()
    )
}

/// Can this server reach other mail servers on port 25? Many clouds block it.
pub fn outbound_25_open() -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addrs) = ("gmail-smtp-in.l.google.com", 25).to_socket_addrs() else {
        return false;
    };
    addrs
        .take(2)
        .any(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_secs(6)).is_ok())
}

pub const PORT_25_WARNING: &str = "Outbound port 25 looks blocked: this server can't reach Gmail's mail servers. \
Many providers (DigitalOcean, AWS, Google Cloud, new Hetzner accounts) block it until you ask them to lift it. \
Until then mail is accepted and queued but not delivered.";

/// Install or update everything. `log` gets progress lines.
pub async fn install(
    config: &Config,
    mc: &MailConfig,
    opts: &InstallOptions,
    log: &dyn Fn(&str),
) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("The email service can only be installed on Linux".into());
    }
    if !crate::fsutil::running_as_root() {
        return Err("Installing the email service needs root".into());
    }
    let host = opts.hostname.as_str();

    log("Installing Postfix and postsrsd");
    sh_opts(
        log,
        "debconf-set-selections",
        &[],
        CmdOpts::default()
            .stdin(format!(
                "postfix postfix/main_mailer_type select No configuration\npostfix postfix/mailname string {host}\n"
            ))
            .timeout(60),
    )?;
    sh_opts(
        log,
        "apt-get",
        &[
            "install",
            "-y",
            "-q",
            "--no-install-recommends",
            "postfix",
            "postsrsd",
            "openssl",
        ],
        CmdOpts::default().env("DEBIAN_FRONTEND", "noninteractive").timeout(900),
    )?;
    if !Path::new("/etc/postfix/main.cf").exists() {
        // "No configuration" leaves main.cf out; start from Debian's template.
        let _ = std::fs::copy("/usr/share/postfix/main.cf.debian", "/etc/postfix/main.cf");
    }

    if !ok("id", &["-u", USER]) {
        log(&format!("Creating system user {USER}"));
        let home = mc.state_dir.to_string_lossy();
        sh(
            log,
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                &home,
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                USER,
            ],
        )?;
    }
    let state = mc.state_dir.to_string_lossy().into_owned();
    for (dir, mode) in [
        (state.clone(), "0750"),
        (mc.dkim_dir().to_string_lossy().into_owned(), "0700"),
        (format!("{state}/tls"), "0700"),
    ] {
        sh(log, "install", &["-d", "-m", mode, "-o", USER, "-g", USER, &dir])?;
    }
    // Creates the schema, owned by the service.
    store::open(&mc.db_path()).map_err(|e| format!("Could not create the mail database: {e}"))?;
    fix_db_ownership(mc);

    log("Getting a TLS certificate");
    // Re-runs (panel upgrades) reuse the address given the first time, and keep a working
    // Let's Encrypt certificate rather than falling back to a self-signed one.
    let email = opts.email.clone().or_else(|| super::env("CLOUDPANEL_MAIL_ACME_EMAIL")).unwrap_or_default();
    let existing_le = match (&mc.cert_source, &mc.key_source) {
        (Some(c), Some(k)) if c.starts_with("/etc/letsencrypt") && c.exists() && k.exists() && mc.hostname == host => {
            Some((c.clone(), k.clone()))
        }
        _ => None,
    };
    let fallback = |why: String| -> Result<(PathBuf, PathBuf), String> {
        if let Some(pair) = existing_le.clone() {
            log(&format!("{why}; keeping the current Let's Encrypt certificate."));
            return Ok(pair);
        }
        log(&format!("{why}; using a self-signed certificate for now. Run cloudpanel mail-install again to replace it."));
        self_signed(log, host)
    };
    let (cert, key) = if opts.self_signed {
        self_signed(log, host)?
    } else if email.is_empty() {
        fallback("No --email given for Let's Encrypt".into())?
    } else {
        match crate::services::panel_cert::resolves_here(host).await {
            Ok(()) => match crate::services::SslService::issue_letsencrypt(&[host.to_string()], &email) {
                Ok((c, k)) => (PathBuf::from(c), PathBuf::from(k)),
                Err(e) => fallback(format!("Let's Encrypt failed ({e})"))?,
            },
            Err(e) => fallback(e)?,
        }
    };
    crate::fsutil::write_atomic(
        Path::new(ENV_FILE),
        render_env(host, &mc.state_dir, &cert, &key, &email).as_bytes(),
        0o644,
    )
    .map_err(|e| format!("Could not write {ENV_FILE}: {e}"))?;
    let mc = MailConfig::from_env();
    sync_cert(&mc)?;
    if cert.starts_with("/etc/letsencrypt") {
        let binary = std::env::current_exe().map_err(|e| e.to_string())?;
        let hook = format!(
            "#!/bin/sh\n# Managed by CloudPanel: give a renewed mail certificate to the email service.\ncase \"$RENEWED_LINEAGE\" in */{host}) {} mail-cert-sync ;; esac\n",
            binary.display()
        );
        if let Some(dir) = Path::new(DEPLOY_HOOK).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        crate::fsutil::write_atomic(Path::new(DEPLOY_HOOK), hook.as_bytes(), 0o755)
            .map_err(|e| format!("Could not write {DEPLOY_HOOK}: {e}"))?;
    }

    log("Configuring Postfix");
    let (c, k) = (cert.to_string_lossy(), key.to_string_lossy());
    let mut settings = main_cf(host);
    settings.push(format!("smtpd_tls_cert_file = {c}"));
    settings.push(format!("smtpd_tls_key_file = {k}"));
    let mut args = vec!["-e".to_string()];
    args.extend(settings);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    sh(log, "postconf", &args)?;
    // Submission is ours, not Postfix's.
    let _ = run_with(
        "postconf",
        &["-M#", "submission/inet", "smtps/inet", "submissions/inet"],
        &CmdOpts::default(),
    );
    {
        let conn = store::open(&mc.db_path()).map_err(|e| e.to_string())?;
        let forwards = store::list_forwards(&conn).map_err(|e| e.to_string())?;
        let (map, dom) = render_maps(&forwards);
        for (path, content) in [(VIRTUAL_MAP, map), (VIRTUAL_DOMAINS, dom)] {
            crate::fsutil::write_atomic(Path::new(path), content.as_bytes(), 0o644).map_err(|e| e.to_string())?;
            sh(log, "postmap", &[path])?;
        }
    }
    fix_db_ownership(&mc);
    configure_srs(log, host)?;
    sh(log, "systemctl", &["enable", "postfix"])?;
    sh(log, "systemctl", &["restart", "postfix"])?;

    log("Setting up the email API on nginx");
    if let Err(e) = crate::services::NginxService::apply_mail_vhost(config, host, &c, &k, &mc.http_addr) {
        log(&format!(
            "The API's nginx site could not be set up ({e}); SMTP still works."
        ));
    }

    log(&format!("Installing {UNIT}"));
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    let unit = render_unit(&binary.to_string_lossy(), &state);
    let unit_path = config.systemd_dir.join(UNIT);
    crate::fsutil::write_atomic(&unit_path, unit.as_bytes(), 0o644)
        .map_err(|e| format!("Could not write {}: {e}", unit_path.display()))?;
    sh(log, "systemctl", &["daemon-reload"])?;
    sh(log, "systemctl", &["enable", UNIT])?;
    sh(log, "systemctl", &["restart", UNIT])?;

    if ok("ufw", &["status"])
        && run_with("ufw", &["status"], &CmdOpts::default())
            .stdout
            .contains("Status: active")
    {
        for p in PORTS {
            let _ = run_with(
                "ufw",
                &["allow", &format!("{p}/tcp"), "comment", "Mail"],
                &CmdOpts::default(),
            );
        }
        log("Opened ports 25, 465 and 587 in the firewall");
    }

    if !outbound_25_open() {
        log(PORT_25_WARNING);
    }
    Ok(())
}

/// Stop and remove the service, its nginx site and certbot hook. Postfix and the data stay.
pub fn uninstall(config: &Config, log: &dyn Fn(&str)) -> Result<(), String> {
    let _ = run_with(
        "systemctl",
        &["disable", "--now", UNIT],
        &CmdOpts::default().timeout(60),
    );
    let _ = std::fs::remove_file(config.systemd_dir.join(UNIT));
    let _ = run_with("systemctl", &["daemon-reload"], &CmdOpts::default());
    let _ = std::fs::remove_file(DEPLOY_HOOK);
    if let Err(e) = crate::services::NginxService::remove_mail_vhost(config) {
        log(&format!("Could not remove the API's nginx site: {e}"));
    }
    for p in PORTS {
        let _ = run_with("ufw", &["delete", "allow", &format!("{p}/tcp")], &CmdOpts::default());
    }
    log(&format!(
        "Removed {UNIT}. Postfix is still installed and its data is in {}; remove them with apt-get purge postfix postsrsd if you no longer need them.",
        MailConfig::from_env().state_dir.display()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_maps() {
        let f = |a: &str, t: &str| store::Forward {
            address: a.into(),
            forward_to: t.into(),
            created_at: String::new(),
        };
        let (map, dom) = render_maps(&[
            f("me@example.com", "me@gmail.com"),
            f("hi@example.com", "x@gmail.com"),
            f("a@b.org", "c@d.io"),
        ]);
        assert!(map.contains("\nme@example.com me@gmail.com\n"));
        assert_eq!(
            dom.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>(),
            vec!["b.org OK", "example.com OK"]
        );
    }

    #[test]
    fn postfix_is_never_an_open_relay() {
        let cf = main_cf("mail.example.com");
        let get = |k: &str| cf.iter().find(|l| l.starts_with(&format!("{k} ="))).cloned().unwrap();
        assert_eq!(
            get("smtpd_relay_restrictions"),
            "smtpd_relay_restrictions = reject_unauth_destination"
        );
        assert!(!cf.iter().any(|l| l.contains("permit_mynetworks")));
        assert_eq!(
            get("authorized_submit_users"),
            format!("authorized_submit_users = root, {USER}")
        );
    }

    #[test]
    fn config_lines() {
        let t = "# SRS_DOMAIN=example.com\nSRS_SECRET=/etc/postsrsd.secret\n";
        assert_eq!(
            set_config_line(t, "SRS_DOMAIN", "SRS_DOMAIN=mail.x.com"),
            "SRS_DOMAIN=mail.x.com\nSRS_SECRET=/etc/postsrsd.secret\n"
        );
        assert_eq!(
            set_config_line("a = 1", "srs-domain", "srs-domain = \"h\""),
            "a = 1\nsrs-domain = \"h\"\n"
        );
        // A key that merely starts the same isn't replaced.
        assert_eq!(
            set_config_line("SRS_DOMAINS=x", "SRS_DOMAIN", "SRS_DOMAIN=y"),
            "SRS_DOMAINS=x\nSRS_DOMAIN=y\n"
        );
    }

    #[test]
    fn unit_is_unprivileged() {
        let u = render_unit("/usr/local/bin/cloudpanel", "/var/lib/cloudpanel-mail");
        assert!(u.contains(&format!("User={USER}")));
        assert!(u.contains("ExecStart=/usr/local/bin/cloudpanel mail-serve"));
        assert!(u.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(u.contains("ReadWritePaths=/var/lib/cloudpanel-mail /var/spool/postfix/maildrop"));
    }
}
