use super::cmd::{run_host_simple, CmdOutcome};
use crate::fsutil::{create_private_dir, write_atomic};
use std::path::Path;
use tracing::info;

pub struct SslService;

const MAX_PEM_BYTES: usize = 64 * 1024;

/// A certificate from [`SslService::issue_for_site`].
#[derive(Debug, PartialEq, Eq)]
pub struct Issued {
    pub cert_path: String,
    pub key_path: String,
    /// Set when the certificate covers fewer names than the site asked for.
    pub warning: Option<String>,
}

/// certbot's arguments. `--expand` lets an existing certificate gain names, such as www when
/// a site turns its redirect on; without it certbot refuses in non-interactive mode.
fn certbot_args<'a>(names: &'a [String], email: &'a str) -> Vec<&'a str> {
    let mut args: Vec<&str> = vec![
        "certonly",
        "--nginx",
        "--non-interactive",
        "--agree-tos",
        "--keep-until-expiring",
        "--expand",
        "--cert-name",
        names.first().map_or("", String::as_str),
        "-m",
        email,
    ];
    for n in names {
        args.push("-d");
        args.push(n);
    }
    args
}

/// Does this name resolve at all? Used to avoid asking for a name that is bound to fail.
fn resolves(name: &str) -> bool {
    use std::net::ToSocketAddrs;
    (name, 80).to_socket_addrs().is_ok_and(|mut a| a.next().is_some())
}

/// Get a certificate for `names`, giving up on the extra names rather than on HTTPS: www is on
/// by default, and one bad name would otherwise fail the whole certificate. `issue` asks for a
/// certificate and `resolve` checks DNS.
fn issue_with_fallback<I, R>(names: &[String], issue: I, resolve: R) -> Result<Issued, String>
where
    I: Fn(&[String]) -> Result<(String, String), String>,
    R: Fn(&str) -> bool,
{
    let primary = names.first().ok_or("No domain given")?.clone();
    let done = |(cert_path, key_path): (String, String), warning| Issued {
        cert_path,
        key_path,
        warning,
    };
    let extras: Vec<&String> = names.iter().skip(1).collect();
    if extras.is_empty() {
        return issue(names).map(|p| done(p, None));
    }
    let list = |v: &[&String]| v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
    let only_primary = std::slice::from_ref(&primary);

    let unresolved: Vec<&String> = extras.iter().copied().filter(|n| !resolve(n)).collect();
    if !unresolved.is_empty() {
        let names_left: Vec<String> = names.iter().filter(|n| !unresolved.contains(n)).cloned().collect();
        let warning = format!(
            "{} has no DNS record yet, so the certificate doesn't cover it. Add the record, then replace the \
             certificate.",
            list(&unresolved)
        );
        return issue(&names_left).map(|p| done(p, Some(warning)));
    }
    match issue(names) {
        Ok(p) => Ok(done(p, None)),
        Err(first) => match issue(only_primary) {
            Ok(p) => Ok(done(
                p,
                Some(format!(
                    "Let's Encrypt could not validate {}, so the certificate only covers {primary}. Check that \
                     name's DNS, then replace the certificate. certbot said: {}",
                    list(&extras),
                    tail(&first, 400)
                )),
            )),
            Err(_) => Err(first),
        },
    }
}

impl SslService {
    /// Issue a certificate for a site. See [`issue_with_fallback`].
    pub fn issue_for_site(names: &[String], email: &str) -> Result<Issued, String> {
        issue_with_fallback(names, |n| Self::issue_letsencrypt(n, email), resolves)
    }

    /// Issue a Let's Encrypt certificate with certbot. `names[0]` is the primary domain.
    /// Every value has already been validated (no leading '-', strict charset).
    pub fn issue_letsencrypt(names: &[String], email: &str) -> Result<(String, String), String> {
        let primary = names.first().ok_or("No domain given")?;
        info!("Requesting Let's Encrypt certificate for {}", names.join(", "));

        // Outside the sandbox, because its nginx plugin tests nginx's config. See `NginxService::test`.
        match run_host_simple("certbot", &certbot_args(names, email)) {
            CmdOutcome::Ok(_) => Ok((
                format!("/etc/letsencrypt/live/{primary}/fullchain.pem"),
                format!("/etc/letsencrypt/live/{primary}/privkey.pem"),
            )),
            CmdOutcome::Failed(e) => Err(format!("certbot failed: {}", tail(&e, 1200))),
            CmdOutcome::Missing => Err("certbot is not installed on this server".into()),
        }
    }

    /// Validate and store a user-supplied certificate chain and private key.
    pub fn install_custom_cert(
        ssl_dir: &Path,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(String, String), String> {
        if cert_pem.len() > MAX_PEM_BYTES || key_pem.len() > MAX_PEM_BYTES {
            return Err("Certificate or key is too large".into());
        }
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|_| "Certificate is not valid PEM".to_string())?;
        if certs.is_empty() {
            return Err("No certificate found (expected -----BEGIN CERTIFICATE-----)".into());
        }
        rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|_| "Private key is not valid PEM".to_string())?
            .ok_or("No private key found (expected -----BEGIN PRIVATE KEY-----)")?;

        let dir = ssl_dir.join(domain);
        create_private_dir(ssl_dir, 0o700).map_err(|e| format!("Failed to create SSL directory: {e}"))?;
        create_private_dir(&dir, 0o700).map_err(|e| format!("Failed to create SSL directory: {e}"))?;

        let cert_path = dir.join("fullchain.pem");
        let key_path = dir.join("privkey.pem");
        write_atomic(&cert_path, normalize(cert_pem).as_bytes(), 0o644)
            .map_err(|e| format!("Failed to write certificate: {e}"))?;
        write_atomic(&key_path, normalize(key_pem).as_bytes(), 0o600)
            .map_err(|e| format!("Failed to write private key: {e}"))?;

        Ok((
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        ))
    }

    /// Force-renew a Let's Encrypt certificate now.
    pub fn renew_letsencrypt(cert_name: &str) -> Result<(), String> {
        match run_host_simple(
            "certbot",
            &[
                "renew",
                "--cert-name",
                cert_name,
                "--force-renewal",
                "--non-interactive",
            ],
        ) {
            CmdOutcome::Ok(_) => Ok(()),
            CmdOutcome::Failed(e) => Err(format!("certbot failed: {}", tail(&e, 1200))),
            CmdOutcome::Missing => Err("certbot is not installed on this server".into()),
        }
    }

    pub fn is_letsencrypt(cert_path: &str) -> bool {
        cert_path.starts_with("/etc/letsencrypt/")
    }

    /// Parse the leaf certificate of a PEM file.
    pub fn cert_info(cert_path: &str) -> Option<CertInfo> {
        let pem = std::fs::read(cert_path).ok()?;
        Self::cert_info_pem(&pem)
    }

    pub fn cert_info_pem(pem: &[u8]) -> Option<CertInfo> {
        let der = rustls_pemfile::certs(&mut &pem[..]).next()?.ok()?;
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
        let not_after = cert.validity().not_after.timestamp();
        let not_before = cert.validity().not_before.timestamp();
        let mut names: Vec<String> = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for n in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(d) = n {
                    names.push(d.to_string());
                }
            }
        }
        let now = chrono::Utc::now().timestamp();
        let issuer_org = cert
            .issuer()
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok())
            .map(str::to_string);
        let issuer_cn = cert
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|c| c.as_str().ok())
            .map(str::to_string);
        let subject = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|c| c.as_str().ok())
            .unwrap_or("")
            .to_string();
        let info = CertInfo {
            issuer: issuer_org.or(issuer_cn).unwrap_or_else(|| "unknown".into()),
            subject,
            names,
            not_before: chrono::DateTime::from_timestamp(not_before, 0).unwrap_or_default(),
            not_after: chrono::DateTime::from_timestamp(not_after, 0).unwrap_or_default(),
            days_left: (not_after - now) / 86400,
        };
        Some(info)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CertInfo {
    pub issuer: String,
    pub subject: String,
    pub names: Vec<String>,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub days_left: i64,
}

impl CertInfo {
    /// Whether the certificate is valid for `host`, including through a wildcard.
    pub fn covers(&self, host: &str) -> bool {
        let matches = |pattern: &str| {
            let pattern = pattern.to_ascii_lowercase();
            let host = host.to_ascii_lowercase();
            if let Some(suffix) = pattern.strip_prefix("*.") {
                return host.split_once('.').is_some_and(|(_, rest)| rest == suffix);
            }
            pattern == host
        };
        if self.names.is_empty() {
            return matches(&self.subject);
        }
        self.names.iter().any(|n| matches(n))
    }
}

fn normalize(pem: &str) -> String {
    let mut s = pem.replace("\r\n", "\n").trim().to_string();
    s.push('\n');
    s
}

fn tail(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn names() -> Vec<String> {
        vec!["example.com".to_string(), "www.example.com".to_string()]
    }

    fn paths() -> (String, String) {
        ("c".to_string(), "k".to_string())
    }

    #[test]
    fn certbot_can_expand_and_gets_every_name() {
        let n = names();
        let args = certbot_args(&n, "me@example.com");
        assert!(args.contains(&"--expand"));
        assert!(args.contains(&"--non-interactive"));
        assert_eq!(args.iter().filter(|a| **a == "-d").count(), 2);
        let cert_name = args.iter().position(|a| *a == "--cert-name").unwrap();
        assert_eq!(args[cert_name + 1], "example.com");
    }

    #[test]
    fn both_names_when_all_goes_well() {
        let i = issue_with_fallback(
            &names(),
            |n| {
                assert_eq!(n.len(), 2);
                Ok(paths())
            },
            |_| true,
        )
        .unwrap();
        assert_eq!(i.warning, None);
    }

    #[test]
    fn skips_www_without_dns_and_says_so() {
        let asked = RefCell::new(Vec::new());
        let i = issue_with_fallback(
            &names(),
            |n| {
                asked.borrow_mut().push(n.to_vec());
                Ok(paths())
            },
            |host| host == "example.com",
        )
        .unwrap();
        assert_eq!(asked.borrow().as_slice(), &[vec!["example.com".to_string()]]);
        assert!(i.warning.unwrap().contains("www.example.com has no DNS record"));
    }

    #[test]
    fn retries_without_www_when_validation_fails() {
        let asked = RefCell::new(0);
        let i = issue_with_fallback(
            &names(),
            |n| {
                *asked.borrow_mut() += 1;
                if n.len() == 2 {
                    Err("www failed".to_string())
                } else {
                    Ok(paths())
                }
            },
            |_| true,
        )
        .unwrap();
        assert_eq!(*asked.borrow(), 2);
        let w = i.warning.unwrap();
        assert!(w.contains("only covers example.com"));
        assert!(w.contains("www failed"));
    }

    #[test]
    fn reports_the_original_error_if_the_naked_domain_fails_too() {
        let e = issue_with_fallback(
            &names(),
            |n| Err(if n.len() == 2 { "first" } else { "second" }.to_string()),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(e, "first");
    }

    #[test]
    fn a_single_name_has_no_fallback() {
        let n = vec!["example.com".to_string()];
        assert_eq!(
            issue_with_fallback(&n, |_| Err("no".to_string()), |_| true).unwrap_err(),
            "no"
        );
    }

    #[test]
    fn coverage_checks_names_and_wildcards() {
        let info = |names: &[&str]| CertInfo {
            issuer: String::new(),
            subject: "example.com".into(),
            names: names.iter().map(|s| s.to_string()).collect(),
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now(),
            days_left: 1,
        };
        assert!(info(&["example.com", "www.example.com"]).covers("www.example.com"));
        assert!(!info(&["example.com"]).covers("www.example.com"));
        assert!(info(&["*.example.com"]).covers("www.example.com"));
        assert!(!info(&["*.example.com"]).covers("a.b.example.com"));
        assert!(!info(&[]).covers("www.example.com"));
    }
}
