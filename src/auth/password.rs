use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{distributions::Alphanumeric, Rng};
use std::sync::OnceLock;

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Hashing failed: {}", e))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Spend the same time as a real verification so missing users can't be told apart by timing.
pub fn verify_dummy(password: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash = DUMMY.get_or_init(|| hash_password("cloudpanel-dummy-password").unwrap_or_default());
    let _ = verify_password(password, hash);
}

pub fn random_password(len: usize) -> String {
    rand::rngs::OsRng
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
        // Salted: the same password hashes differently each time.
        assert_ne!(h, hash_password("correct horse battery").unwrap());
    }

    #[test]
    fn malformed_hash_never_verifies() {
        assert!(!verify_password("x", ""));
        assert!(!verify_password("x", "not-a-hash"));
        verify_dummy("anything");
    }

    #[test]
    fn random_passwords() {
        let a = random_password(24);
        assert_eq!(a.len(), 24);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, random_password(24));
        assert!(random_password(0).is_empty());
    }
}
