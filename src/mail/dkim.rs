//! DKIM (RFC 6376): rsa-sha256 with relaxed/relaxed canonicalization, signed with `ring`.
//!
//! Keys are 2048-bit RSA in PKCS#8 PEM, generated with `openssl genpkey` and stored per domain,
//! readable only by the mail service. The DNS record publishes the SubjectPublicKeyInfo.

use base64::Engine;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use sha2::{Digest, Sha256};
use std::path::Path;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Headers signed when present, in this order. `from` is signed once more than it appears, so a
/// second From added later breaks the signature instead of being trusted.
const SIGNED_HEADERS: &[&str] = &[
    "from",
    "reply-to",
    "subject",
    "date",
    "to",
    "cc",
    "message-id",
    "in-reply-to",
    "references",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "list-unsubscribe",
    "list-unsubscribe-post",
];

/// A loaded signing key.
pub struct Signer {
    key: RsaKeyPair,
    domain: String,
    selector: String,
}

/// Normalize line endings to CRLF.
pub fn to_crlf(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 40);
    let mut prev = 0u8;
    for &b in raw {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

/// Split a CRLF message into its header block (without the blank line) and body.
pub fn split(msg: &[u8]) -> (&[u8], &[u8]) {
    if msg.starts_with(b"\r\n") {
        return (&[], &msg[2..]);
    }
    match msg.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (&msg[..i + 2], &msg[i + 4..]),
        None => (msg, &[]),
    }
}

/// Unfolded header fields `(name, raw value)` in order. The raw value keeps its folding.
pub fn header_fields(block: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(block);
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some(last) = fields.last_mut() {
                last.1.push_str("\r\n");
                last.1.push_str(line);
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            fields.push((name.to_string(), value.to_string()));
        }
    }
    fields
}

fn collapse_wsp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            in_ws = true;
        } else {
            if in_ws {
                out.push(' ');
            }
            in_ws = false;
            out.push(c);
        }
    }
    if in_ws {
        out.push(' ');
    }
    out
}

/// Relaxed header canonicalization (RFC 6376 3.4.2), with the trailing CRLF.
pub fn relaxed_header(name: &str, value: &str) -> String {
    let unfolded = value.replace("\r\n", "");
    let v = collapse_wsp(&unfolded);
    format!("{}:{}\r\n", name.trim().to_ascii_lowercase(), v.trim())
}

/// Relaxed body canonicalization (RFC 6376 3.4.4).
pub fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut lines: Vec<String> = text
        .split("\r\n")
        .map(|l| collapse_wsp(l).trim_end_matches(' ').to_string())
        .collect();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    if lines.is_empty() {
        return Vec::new();
    }
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out.into_bytes()
}

/// DER length bytes.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

/// Wrap a PKCS#1 RSAPublicKey in a SubjectPublicKeyInfo, which is what DKIM's `p=` carries.
pub fn spki_from_pkcs1(pkcs1: &[u8]) -> Vec<u8> {
    const ALG: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut bit = vec![0x03];
    bit.extend(der_len(pkcs1.len() + 1));
    bit.push(0);
    bit.extend_from_slice(pkcs1);
    let mut out = vec![0x30];
    out.extend(der_len(ALG.len() + bit.len()));
    out.extend_from_slice(&ALG);
    out.extend(bit);
    out
}

/// Read a PKCS#8 PEM private key into DER.
fn pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    match rustls_pemfile::private_key(&mut pem.as_bytes()) {
        Ok(Some(rustls::pki_types::PrivateKeyDer::Pkcs8(k))) => Ok(k.secret_pkcs8_der().to_vec()),
        Ok(Some(_)) => Err("DKIM key must be PKCS#8 (BEGIN PRIVATE KEY)".into()),
        _ => Err("DKIM key is not valid PEM".into()),
    }
}

/// Generate a 2048-bit RSA key as PKCS#8 PEM with openssl.
pub fn generate_key_pem() -> Result<String, String> {
    let r = crate::services::cmd::run_with(
        "openssl",
        &["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        &crate::services::cmd::CmdOpts::default().timeout(60),
    );
    if !r.success() {
        return Err(format!("openssl genpkey failed: {}", r.combined().trim()));
    }
    Ok(r.stdout)
}

/// The base64 `p=` value for a PEM private key.
pub fn public_key_b64(pem: &str) -> Result<String, String> {
    let key = RsaKeyPair::from_pkcs8(&pkcs8_der(pem)?).map_err(|e| format!("DKIM key rejected: {e}"))?;
    Ok(B64.encode(spki_from_pkcs1(ring::signature::KeyPair::public_key(&key).as_ref())))
}

/// The TXT record value for `<selector>._domainkey.<domain>`.
pub fn dns_value(public_b64: &str) -> String {
    format!("v=DKIM1; k=rsa; p={public_b64}")
}

impl Signer {
    pub fn from_pem(pem: &str, domain: &str, selector: &str) -> Result<Self, String> {
        let key = RsaKeyPair::from_pkcs8(&pkcs8_der(pem)?).map_err(|e| format!("DKIM key rejected: {e}"))?;
        Ok(Self {
            key,
            domain: domain.to_string(),
            selector: selector.to_string(),
        })
    }

    pub fn load(path: &Path, domain: &str, selector: &str) -> Result<Self, String> {
        let pem = std::fs::read_to_string(path).map_err(|e| format!("Could not read {}: {e}", path.display()))?;
        Self::from_pem(&pem, domain, selector)
    }

    /// Return the message (CRLF line endings) with a DKIM-Signature header on top.
    pub fn sign(&self, raw: &[u8], timestamp: i64) -> Result<Vec<u8>, String> {
        let msg = to_crlf(raw);
        let (head, body) = split(&msg);
        let fields = header_fields(head);

        let bh = B64.encode(Sha256::digest(relaxed_body(body)));

        // Pick the fields to sign, each name's instances from the bottom up.
        let mut names: Vec<String> = Vec::new();
        let mut data = String::new();
        for &want in SIGNED_HEADERS {
            let mut found: Vec<&(String, String)> = fields
                .iter()
                .filter(|(n, _)| n.trim().eq_ignore_ascii_case(want))
                .collect();
            found.reverse();
            for (n, v) in found {
                names.push(want.to_string());
                data.push_str(&relaxed_header(n, v));
            }
            if want == "from" {
                // The extra, absent instance hashes as nothing.
                names.push("from".into());
            }
        }
        if !fields.iter().any(|(n, _)| n.trim().eq_ignore_ascii_case("from")) {
            return Err("The message has no From header".into());
        }

        let unsigned = format!(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
            self.domain,
            self.selector,
            timestamp,
            names.join(":"),
            bh
        );
        let sig_header = relaxed_header("DKIM-Signature", &unsigned);
        data.push_str(sig_header.trim_end_matches("\r\n"));

        let rng = ring::rand::SystemRandom::new();
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &rng, data.as_bytes(), &mut sig)
            .map_err(|_| "DKIM signing failed".to_string())?;
        let b = B64.encode(sig);

        // Fold at the existing spaces, and the signature in chunks; both are invisible to verifiers.
        let mut header = String::from("DKIM-Signature: ");
        header.push_str(&unsigned.replace("; ", ";\r\n\t"));
        for (i, chunk) in b.as_bytes().chunks(72).enumerate() {
            if i > 0 {
                header.push_str("\r\n\t ");
            }
            header.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        }
        header.push_str("\r\n");

        let mut out = header.into_bytes();
        out.extend_from_slice(&msg);
        Ok(out)
    }
}

/// Check a signature made by [`Signer::sign`].
#[cfg(test)]
pub fn verify(signed: &[u8], spki_b64: &str) -> Result<(), String> {
    let msg = to_crlf(signed);
    let (head, body) = split(&msg);
    let fields = header_fields(head);
    let (sig_name, sig_value) = fields
        .iter()
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("dkim-signature"))
        .ok_or("no DKIM-Signature")?;
    let unfolded: String = sig_value.replace("\r\n", "");
    let tags: Vec<(String, String)> = unfolded
        .split(';')
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.chars().filter(|c| !c.is_whitespace()).collect()))
        .collect();
    let tag = |k: &str| tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let bh = tag("bh").ok_or("no bh")?;
    if bh != B64.encode(Sha256::digest(relaxed_body(body))) {
        return Err("body hash mismatch".into());
    }
    let mut data = String::new();
    let mut used: std::collections::HashMap<String, usize> = Default::default();
    for name in tag("h").ok_or("no h")?.split(':') {
        let name = name.to_ascii_lowercase();
        let all: Vec<&(String, String)> = fields
            .iter()
            .filter(|(n, _)| n.trim().eq_ignore_ascii_case(&name) && !n.trim().eq_ignore_ascii_case("dkim-signature"))
            .collect();
        let k = used.entry(name.clone()).or_default();
        if *k < all.len() {
            let (n, v) = all[all.len() - 1 - *k];
            data.push_str(&relaxed_header(n, v));
        }
        *k += 1;
    }
    // The signature header with b= emptied.
    let stripped = {
        let i = unfolded.find("b=").ok_or("no b")?;
        // `bh=` comes before `b=` in our order, so find the standalone tag.
        let mut start = i;
        for (pos, _) in unfolded.match_indices("b=") {
            let before = unfolded[..pos].trim_end();
            if before.ends_with(';') || before.is_empty() {
                start = pos;
            }
        }
        let end = unfolded[start..].find(';').map_or(unfolded.len(), |e| start + e);
        format!("{}b={}", &unfolded[..start], &unfolded[end..])
    };
    data.push_str(relaxed_header(sig_name, &stripped).trim_end_matches("\r\n"));
    let sig = B64.decode(tag("b").ok_or("no b")?).map_err(|_| "bad b")?;
    let spki = B64.decode(spki_b64).map_err(|_| "bad key")?;
    // ring wants the PKCS#1 key inside the SPKI's BIT STRING: skip our fixed 15-byte AlgorithmIdentifier.
    let pkcs1 = {
        let idx = spki.windows(2).skip(15).position(|w| w[0] == 0x03).ok_or("bad spki")? + 15;
        let (len, hdr) = match spki[idx + 1] {
            n if n < 0x80 => (n as usize, 2),
            n => {
                let k = (n & 0x7f) as usize;
                (
                    spki[idx + 2..idx + 2 + k]
                        .iter()
                        .fold(0usize, |a, b| (a << 8) | *b as usize),
                    2 + k,
                )
            }
        };
        spki[idx + hdr + 1..idx + hdr + len].to_vec()
    };
    ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, pkcs1)
        .verify(data.as_bytes(), &sig)
        .map_err(|_| "signature mismatch".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = include_str!("testdata/dkim-test-key.pem");

    #[test]
    fn relaxed_canonicalization_matches_rfc_example() {
        // RFC 6376 section 3.4.5.
        assert_eq!(relaxed_header("A", " X"), "a:X\r\n");
        assert_eq!(relaxed_header("B ", " Y\t\r\n\tZ  "), "b:Y Z\r\n");
        assert_eq!(relaxed_body(b" C \r\nD \t E\r\n\r\n\r\n"), b" C\r\nD E\r\n");
        assert_eq!(relaxed_body(b""), b"");
        assert_eq!(relaxed_body(b"\r\n\r\n"), b"");
        assert_eq!(relaxed_body(b"no newline"), b"no newline\r\n");
    }

    #[test]
    fn line_endings_and_split() {
        assert_eq!(to_crlf(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
        let m = to_crlf(b"From: a@b\nSubject: x\n\nhello\n");
        let (h, b) = split(&m);
        assert_eq!(h, b"From: a@b\r\nSubject: x\r\n");
        assert_eq!(b, b"hello\r\n");
        let f = header_fields(b"Subject: one\r\n two\r\nTo: x\r\n");
        assert_eq!(f[0].1, " one\r\n two");
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn spki_has_rsa_header() {
        let spki = spki_from_pkcs1(&[0x30, 0x03, 0x02, 0x01, 0x05]);
        assert_eq!(&spki[..2], &[0x30, 0x17]);
        assert_eq!(spki[17], 0x03);
        // Long-form lengths for 2048-bit keys.
        assert_eq!(der_len(270), vec![0x82, 0x01, 0x0e]);
    }

    #[test]
    fn signs_and_verifies() {
        let signer = Signer::from_pem(KEY, "example.com", "cloudpanel").unwrap();
        let p = public_key_b64(KEY).unwrap();
        assert!(dns_value(&p).starts_with("v=DKIM1; k=rsa; p=MIIBIjAN"));
        let msg = b"From: Me <me@example.com>\nTo: you@example.org\nSubject: Hello   there\n\tfolded\nMessage-ID: <1@x>\n\nHi  there \n\n\n";
        let signed = signer.sign(msg, 1_700_000_000).unwrap();
        let text = String::from_utf8(signed.clone()).unwrap();
        assert!(text.starts_with("DKIM-Signature: v=1;\r\n\ta=rsa-sha256;\r\n\tc=relaxed/relaxed;\r\n\td=example.com;"));
        assert!(text.contains("h=from:from:subject:to:message-id;"));
        verify(&signed, &p).unwrap();

        // Changing the body or a signed header breaks it; re-folding doesn't.
        let tampered = text.replace("Hi  there", "Hi there!");
        assert!(verify(tampered.as_bytes(), &p).is_err());
        let tampered = text.replace("Subject: Hello", "Subject: Hullo");
        assert!(verify(tampered.as_bytes(), &p).is_err());
        let refolded = text.replace("Subject: Hello   there", "Subject: Hello\r\n there");
        verify(refolded.as_bytes(), &p).unwrap();
        // A second From added later fails because from is oversigned.
        let added = text.replace("To: you", "From: evil@example.net\r\nTo: you");
        assert!(verify(added.as_bytes(), &p).is_err());
    }

    #[test]
    fn needs_from() {
        let signer = Signer::from_pem(KEY, "example.com", "cloudpanel").unwrap();
        assert!(signer.sign(b"To: x@y\n\nbody\n", 1).is_err());
    }
}
