//! Encryption at rest for credentials stored in the database (S3 keys, SMTP passwords,
//! webhook URLs). ChaCha20-Poly1305 with a random 256-bit key kept in
//! `/etc/cloudpanel/secret.key` (mode 600), separate from the database file.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::path::Path;

const PREFIX: &str = "v1:";

fn load_key(etc_dir: &Path) -> Result<[u8; 32], String> {
    let path = etc_dir.join("secret.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(bytes.trim_ascii()) {
            if decoded.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&decoded);
                return Ok(k);
            }
        }
        return Err(format!("{} is corrupt", path.display()));
    }
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    crate::fsutil::create_private_dir(etc_dir, 0o700).map_err(|e| e.to_string())?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(k);
    crate::fsutil::write_atomic(&path, encoded.as_bytes(), 0o600).map_err(|e| e.to_string())?;
    Ok(k)
}

pub fn encrypt(etc_dir: &Path, plaintext: &str) -> Result<String, String> {
    let key = load_key(etc_dir)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| "encryption failed".to_string())?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    Ok(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    ))
}

pub fn decrypt(etc_dir: &Path, stored: &str) -> Result<String, String> {
    let b64 = stored.strip_prefix(PREFIX).ok_or("unsupported secret format")?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "corrupt secret".to_string())?;
    if blob.len() < 12 + 16 {
        return Err("corrupt secret".into());
    }
    let key = load_key(etc_dir)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(&blob[..12]), &blob[12..])
        .map_err(|_| "secret could not be decrypted (was the key replaced?)".to_string())?;
    String::from_utf8(pt).map_err(|_| "corrupt secret".to_string())
}

/// Encrypt a serializable value as JSON.
pub fn seal<T: serde::Serialize>(etc_dir: &Path, value: &T) -> Result<String, String> {
    encrypt(etc_dir, &serde_json::to_string(value).map_err(|e| e.to_string())?)
}

pub fn open<T: serde::de::DeserializeOwned>(etc_dir: &Path, stored: &str) -> Result<T, String> {
    serde_json::from_str(&decrypt(etc_dir, stored)?).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let s = encrypt(dir.path(), "s3cr3t").unwrap();
        assert!(s.starts_with("v1:"));
        assert_eq!(decrypt(dir.path(), &s).unwrap(), "s3cr3t");
        let mut bad = s.clone();
        bad.pop();
        bad.push(if s.ends_with('A') { 'B' } else { 'A' });
        assert!(decrypt(dir.path(), &bad).is_err());
    }
}
