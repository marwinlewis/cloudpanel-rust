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
