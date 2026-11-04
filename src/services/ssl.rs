use super::cmd::{run, CmdOutcome};
use crate::fsutil::{create_private_dir, write_atomic};
use std::path::Path;
use tracing::info;

pub struct SslService;

const MAX_PEM_BYTES: usize = 64 * 1024;

impl SslService {
    /// Issue a Let's Encrypt certificate with certbot. `names[0]` is the primary domain.
    /// Every value has already been validated (no leading '-', strict charset).
    pub fn issue_letsencrypt(names: &[String], email: &str) -> Result<(String, String), String> {
        let primary = names.first().ok_or("No domain given")?;
        info!("Requesting Let's Encrypt certificate for {}", names.join(", "));

        let mut args: Vec<&str> = vec![
            "certonly",
            "--nginx",
            "--non-interactive",
            "--agree-tos",
            "--keep-until-expiring",
            "--cert-name",
            primary,
            "-m",
            email,
        ];
        for n in names {
            args.push("-d");
            args.push(n);
        }

        match run("certbot", &args) {
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
        match run(
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
