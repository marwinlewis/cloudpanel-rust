//! Moves the Let's Encrypt renewal of a site imported from CloudPanel CE to certbot, one domain at
//! a time, so that CE's nightly job is no longer needed.
//!
//! An imported vhost is kept byte for byte, and it reads its certificate from
//! `/etc/nginx/ssl-certificates/<domain>.{crt,key}`. So the certificate is issued through the site's
//! existing document root, without touching nginx, and a certbot hook copies each renewal to the
//! paths the vhost already uses. Sites keep answering throughout: nginx only ever reloads.

use super::cmd::{run_host_simple, CmdOutcome};
use super::{NginxService, SslService};
use crate::db::models::Site;
use crate::fsutil::write_atomic;
use crate::validate;
use std::fs;
use std::path::{Path, PathBuf};

const LETSENCRYPT_DIR: &str = "/etc/letsencrypt";
/// Sorts before `cloudpanel-reload-nginx`, so nginx reloads after the files are in place.
const HOOK_NAME: &str = "cloudpanel-ce-certs";

/// Copies a renewed certificate over the one an imported vhost reads. Other certificates have no
/// file there, so they are left alone.
const HOOK: &str = r#"#!/bin/sh
# Installed by CloudPanel. Sites imported from CloudPanel CE read their certificate from
# /etc/nginx/ssl-certificates, so each renewal is copied there. nginx reloads in the next hook.
name=$(basename "$RENEWED_LINEAGE")
dir=/etc/nginx/ssl-certificates
[ -f "$dir/$name.crt" ] || exit 0
install -m 644 "$RENEWED_LINEAGE/fullchain.pem" "$dir/$name.crt"
install -m 600 "$RENEWED_LINEAGE/privkey.pem" "$dir/$name.key"
"#;

/// Who renews an imported site's certificate.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Renewal {
    /// Moved: certbot has this domain.
    Certbot,
    /// A Let's Encrypt certificate only CE's nightly job renews, so it can be moved.
    CloudPanelCe,
    /// Self-signed or uploaded: nothing renews it, and nothing can be moved.
    NotLetsEncrypt,
}

impl Renewal {
    pub fn as_str(self) -> &'static str {
        match self {
            Renewal::Certbot => "certbot",
            Renewal::CloudPanelCe => "cloudpanel_ce",
            Renewal::NotLetsEncrypt => "none",
        }
    }
}

pub fn has_certbot_lineage(domain: &str) -> bool {
    Path::new(LETSENCRYPT_DIR)
        .join("renewal")
        .join(format!("{domain}.conf"))
        .exists()
}

/// Who renews this site's certificate. `None` for a site the panel manages itself, or without HTTPS.
pub fn renewal(site: &Site) -> Option<Renewal> {
    if site.vhost_managed || !site.ssl_enabled {
        return None;
    }
    if has_certbot_lineage(&site.domain) {
        return Some(Renewal::Certbot);
    }
    let cert = site.ssl_cert_path.as_deref().and_then(SslService::cert_info)?;
    Some(if is_lets_encrypt(&cert.issuer) {
        Renewal::CloudPanelCe
    } else {
        Renewal::NotLetsEncrypt
    })
}

fn is_lets_encrypt(issuer: &str) -> bool {
    issuer.contains("Let's Encrypt")
}

/// The names to ask for: those on the current certificate, the site's own first. A wildcard can't
/// be validated through a document root.
fn names_to_request(cert_names: &[String], domain: &str) -> Result<Vec<String>, String> {
    if let Some(w) = cert_names.iter().find(|n| n.starts_with("*.")) {
        return Err(format!(
            "its certificate covers the wildcard {w}, which needs DNS validation, so it can't be moved automatically"
        ));
    }
    let mut names = vec![domain.to_string()];
    for n in cert_names {
        if !names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
            let n = validate::domain(n).map_err(|e| format!("its certificate names {n}: {e}"))?;
            names.push(n);
        }
    }
    Ok(names)
}

fn certbot_args<'a>(
    names: &'a [String],
    root: &'a str,
    email: &'a str,
    server: Option<&'a str>,
    dry_run: bool,
) -> Vec<&'a str> {
    let mut args = vec![
        "certonly",
        "--webroot",
        "-w",
        root,
        "--non-interactive",
        "--agree-tos",
        "--keep-until-expiring",
        "--expand",
        "--cert-name",
        names.first().map_or("", String::as_str),
        "-m",
        email,
    ];
    if let Some(server) = server {
        // For testing against a local ACME server, whose certificate isn't publicly trusted.
        args.extend(["--server", server, "--no-verify-ssl"]);
    }
    if dry_run {
        args.push("--dry-run");
    }
    for n in names {
        args.extend(["-d", n]);
    }
    args
}

fn install_hook() -> Result<(), String> {
    let dir = Path::new(LETSENCRYPT_DIR).join("renewal-hooks").join("deploy");
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(HOOK_NAME);
    write_atomic(&path, HOOK.as_bytes(), 0o755).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Keep what CE issued the first time, next to it. nginx only reads `*.crt` and `*.key` it is told to.
fn keep_original(path: &Path) -> Result<(), String> {
    let mut saved = path.as_os_str().to_owned();
    saved.push(".ce");
    let saved = PathBuf::from(saved);
    if !saved.exists() {
        fs::copy(path, &saved).map_err(|e| format!("copy {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Issue the certificate through certbot and put it where the vhost reads it. With `dry_run`, this
/// only checks that Let's Encrypt can validate the domain, and changes nothing.
pub fn take_over(site: &Site, email: &str, dry_run: bool) -> Result<(), String> {
    if site.vhost_managed {
        return Err("Only sites imported from CloudPanel CE need this".into());
    }
    let domain = validate::domain(&site.domain)?;
    let cert_path = site.ssl_cert_path.as_deref().ok_or("This site has no certificate")?;
    let key_path = site.ssl_key_path.as_deref().ok_or("This site has no private key")?;
    let cert = SslService::cert_info(cert_path).ok_or_else(|| format!("{cert_path} can't be read"))?;
    if !is_lets_encrypt(&cert.issuer) && !has_certbot_lineage(&domain) {
        return Err(format!(
            "its certificate is from {}, not Let's Encrypt, so it isn't renewed automatically and has nothing to move",
            cert.issuer
        ));
    }
    let names = names_to_request(&cert.names, &domain)?;
    let root = site.document_root.as_deref().ok_or("This site has no document root")?;
    if !Path::new(root).is_dir() {
        return Err(format!("its document root {root} doesn't exist"));
    }
    let server = std::env::var("CLOUDPANEL_ACME_SERVER").ok().filter(|s| !s.is_empty());
    match run_host_simple(
        "certbot",
        &certbot_args(&names, root, email, server.as_deref(), dry_run),
    ) {
        CmdOutcome::Ok(_) => {}
        CmdOutcome::Failed(e) => return Err(format!("certbot failed: {e}")),
        CmdOutcome::Missing => return Err("certbot is not installed on this server".into()),
    }
    if dry_run {
        return Ok(());
    }

    install_hook()?;
    let live = Path::new(LETSENCRYPT_DIR).join("live").join(&domain);
    let new_cert = fs::read(live.join("fullchain.pem")).map_err(|e| format!("read the new certificate: {e}"))?;
    let new_key = fs::read(live.join("privkey.pem")).map_err(|e| format!("read the new private key: {e}"))?;
    if !SslService::cert_info_pem(&new_cert).is_some_and(|c| c.covers(&domain)) {
        return Err(format!("certbot's new certificate doesn't cover {domain}"));
    }
    let old_cert = fs::read(cert_path).map_err(|e| format!("read {cert_path}: {e}"))?;
    let old_key = fs::read(key_path).map_err(|e| format!("read {key_path}: {e}"))?;
    let (cert_file, key_file) = (Path::new(cert_path), Path::new(key_path));
    keep_original(cert_file)?;
    keep_original(key_file)?;
    write_atomic(cert_file, &new_cert, 0o644).map_err(|e| format!("write {cert_path}: {e}"))?;
    write_atomic(key_file, &new_key, 0o600).map_err(|e| format!("write {key_path}: {e}"))?;
    if let Err(e) = NginxService::test() {
        let _ = write_atomic(cert_file, &old_cert, 0o644);
        let _ = write_atomic(key_file, &old_key, 0o600);
        return Err(e);
    }
    NginxService::reload()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn asks_for_what_the_certificate_covers_with_the_site_first() {
        let n = names_to_request(&names(&["www.example.com", "example.com"]), "example.com").unwrap();
        assert_eq!(n, ["example.com", "www.example.com"]);
        let n = names_to_request(&names(&["example.com", "other.example.com"]), "example.com").unwrap();
        assert_eq!(n, ["example.com", "other.example.com"]);
    }

    #[test]
    fn the_site_is_requested_even_if_its_certificate_stopped_covering_it() {
        assert_eq!(
            names_to_request(&names(&["www.example.com"]), "example.com").unwrap(),
            ["example.com", "www.example.com"]
        );
    }

    #[test]
    fn a_wildcard_is_refused_because_a_webroot_cant_validate_it() {
        let e = names_to_request(&names(&["example.com", "*.example.com"]), "example.com").unwrap_err();
        assert!(e.contains("wildcard"));
    }

    #[test]
    fn a_name_that_could_reach_the_command_line_is_refused() {
        assert!(names_to_request(&names(&["--webroot-path=/etc"]), "example.com").is_err());
    }

    #[test]
    fn certbot_validates_through_the_webroot_without_touching_nginx() {
        let n = names(&["example.com", "www.example.com"]);
        let a = certbot_args(&n, "/home/x/htdocs/example.com", "me@example.com", None, false);
        assert!(a.contains(&"--webroot"));
        assert!(!a.contains(&"--nginx"));
        assert!(!a.contains(&"--dry-run"));
        assert!(!a.contains(&"--no-verify-ssl"));
        assert_eq!(a.iter().filter(|x| **x == "-d").count(), 2);
        let i = a.iter().position(|x| *x == "--cert-name").unwrap();
        assert_eq!(a[i + 1], "example.com");
    }

    #[test]
    fn a_dry_run_and_a_test_server_are_passed_on() {
        let n = names(&["example.com"]);
        let a = certbot_args(&n, "/r", "me@example.com", Some("https://pebble/dir"), true);
        assert!(a.contains(&"--dry-run"));
        assert!(a.contains(&"https://pebble/dir"));
        assert!(a.contains(&"--no-verify-ssl"));
    }

    #[test]
    fn only_lets_encrypt_is_moved() {
        assert!(is_lets_encrypt("Let's Encrypt"));
        assert!(is_lets_encrypt("(STAGING) Let's Encrypt"));
        assert!(!is_lets_encrypt("static.test.local"));
        assert!(!is_lets_encrypt("Cloudflare, Inc."));
    }

    #[test]
    fn the_hook_runs_before_nginx_reloads_and_skips_other_certificates() {
        assert!(HOOK_NAME < "cloudpanel-reload-nginx");
        assert!(HOOK.contains(r#"[ -f "$dir/$name.crt" ] || exit 0"#));
        assert!(HOOK.contains("-m 600"), "the private key stays private");
    }
}
