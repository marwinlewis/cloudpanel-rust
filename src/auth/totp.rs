//! TOTP two-factor authentication (RFC 6238: SHA-1, 6 digits, 30 s) and single-use
//! recovery codes (stored as SHA-256 hashes).

use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "CloudPanel";

fn build(secret_b32: &str, account: &str) -> Result<TOTP, String> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|_| "invalid TOTP secret".to_string())?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1, // accept one step of clock skew either side
        30,
        bytes,
        Some(ISSUER.to_string()),
        account.to_string(),
    )
    .map_err(|e| e.to_string())
}

pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

pub fn otpauth_url(secret_b32: &str, account: &str) -> Result<String, String> {
    Ok(build(secret_b32, account)?.get_url())
}

/// Check a 6-digit code (spaces are ignored).
pub fn verify(secret_b32: &str, account: &str, code: &str) -> bool {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    build(secret_b32, account)
        .and_then(|t| t.check_current(&code).map_err(|e| e.to_string()))
        .unwrap_or(false)
}

#[cfg(test)]
pub fn current_code(secret_b32: &str, account: &str) -> String {
    build(secret_b32, account).unwrap().generate_current().unwrap()
}

/// QR code as a square module matrix (`'1'` = dark) so the UI can draw it as SVG
/// without inserting server-provided markup.
pub fn qr_matrix(data: &str) -> Result<(usize, String), String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| e.to_string())?;
    let width = code.width();
    let bits = code
        .to_colors()
        .into_iter()
        .map(|c| if c == qrcode::Color::Dark { '1' } else { '0' })
        .collect();
    Ok((width, bits))
}

fn hash_code(code: &str) -> String {
    let norm: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    format!("{:x}", Sha256::digest(norm.as_bytes()))
}

/// Ten random recovery codes like `k3f9-2mxq`. Returns (plain codes, JSON of hashes).
pub fn generate_recovery_codes() -> (Vec<String>, String) {
    let codes: Vec<String> = (0..10)
        .map(|_| {
            let r = crate::auth::random_password(8).to_ascii_lowercase();
            format!("{}-{}", &r[..4], &r[4..])
        })
        .collect();
    let hashes: Vec<String> = codes.iter().map(|c| hash_code(c)).collect();
    (codes, serde_json::to_string(&hashes).unwrap_or_else(|_| "[]".into()))
}

/// If `code` matches an unused recovery code, return the remaining hashes as JSON.
pub fn consume_recovery_code(stored_json: &str, code: &str) -> Option<String> {
    let mut hashes: Vec<String> = serde_json::from_str(stored_json).unwrap_or_default();
    let h = hash_code(code);
    let pos = hashes.iter().position(|x| x == &h)?;
    hashes.remove(pos);
    Some(serde_json::to_string(&hashes).unwrap_or_else(|_| "[]".into()))
}

pub fn remaining_recovery_codes(stored_json: &str) -> usize {
    serde_json::from_str::<Vec<String>>(stored_json)
        .map(|v| v.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_roundtrip() {
        let s = generate_secret();
        let code = current_code(&s, "admin");
        assert!(verify(&s, "admin", &code));
        assert!(!verify(&s, "admin", "000000") || code == "000000");
        assert!(!verify(&s, "admin", "12345"));
        assert!(otpauth_url(&s, "admin")
            .unwrap()
            .starts_with("otpauth://totp/CloudPanel:admin?"));
        let (w, bits) = qr_matrix("otpauth://totp/x").unwrap();
        assert_eq!(bits.len(), w * w);
    }

    #[test]
    fn recovery_codes_are_single_use() {
        let (codes, json) = generate_recovery_codes();
        assert_eq!(codes.len(), 10);
        let left = consume_recovery_code(&json, &codes[3].to_uppercase()).unwrap();
        assert_eq!(remaining_recovery_codes(&left), 9);
        assert!(consume_recovery_code(&left, &codes[3]).is_none());
        assert!(consume_recovery_code(&json, "nope-nope").is_none());
    }
}
