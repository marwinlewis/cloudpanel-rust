//! Signing in: what it reveals, how hard it is to guess, and the second factor.

use super::*;
use crate::auth::{hash_password, totp};
use serde_json::json;

fn login_req() -> axum::http::request::Builder {
    api("POST", "/auth/login")
}

async fn try_login(h: &Harness, peer: &str, user: &str, password: &str) -> Response {
    send(
        h,
        peer,
        login_req(),
        json_body(&json!({"username": user, "password": password})),
    )
    .await
}

/// Turn on 2FA for `admin`, returning its secret and recovery codes.
fn enable_2fa(h: &Harness) -> (String, Vec<String>) {
    let conn = h.pool.get().unwrap();
    let id = user_id(h, "admin");
    let secret = totp::generate_secret();
    db::set_totp_pending(&conn, id, &secret).unwrap();
    let (codes, stored) = totp::generate_recovery_codes();
    db::enable_totp(&conn, id, &stored).unwrap();
    (secret, codes)
}

async fn mfa_token(h: &Harness, peer: &str) -> String {
    let r = try_login(h, peer, "admin", "admin-password-1").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()["mfa_token"].as_str().unwrap().to_string()
}

async fn try_code(h: &Harness, peer: &str, token: &str, code: &str) -> Response {
    send(
        h,
        peer,
        api("POST", "/auth/login/mfa"),
        json_body(&json!({"mfa_token": token, "code": code})),
    )
    .await
}

// ---------- What a failed login reveals ----------

#[tokio::test]
async fn a_failed_login_does_not_reveal_whether_the_user_exists() {
    let h = super::super::tests::harness();
    let known = try_login(&h, "198.51.100.1", "admin", "wrong-password").await;
    let unknown = try_login(&h, "198.51.100.2", "no-such-user", "wrong-password").await;
    assert_eq!(known.status, StatusCode::UNAUTHORIZED);
    assert_eq!(known.status, unknown.status);
    assert_eq!(known.bytes, unknown.bytes);
    assert!(known.headers.get(header::SET_COOKIE).is_none());
}

/// A password is hashed for an unknown user too. Otherwise how long the answer takes gives away
/// which names exist. Compared as "same order of magnitude" so this doesn't flake on a busy box.
#[tokio::test]
async fn a_failed_login_takes_about_as_long_for_an_unknown_user() {
    let h = super::super::tests::harness();
    let time = |user: &'static str, peer: &'static str| {
        let h = &h;
        async move {
            let start = std::time::Instant::now();
            try_login(h, peer, user, "wrong-password").await;
            start.elapsed()
        }
    };
    // The first hash can be slower while the pool warms up.
    time("admin", "198.51.100.3").await;
    let known = time("admin", "198.51.100.4").await;
    let unknown = time("no-such-user", "198.51.100.5").await;
    let (slow, fast) = if known > unknown {
        (known, unknown)
    } else {
        (unknown, known)
    };
    assert!(slow < fast * 10, "known user {known:?}, unknown user {unknown:?}");
}

#[tokio::test]
async fn oversized_credentials_are_refused_before_hashing() {
    let h = super::super::tests::harness();
    assert_eq!(
        try_login(&h, "198.51.100.6", &"a".repeat(65), "x").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        try_login(&h, "198.51.100.6", "admin", &"a".repeat(257)).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn passwords_are_stored_with_argon2id_at_owasp_strength() {
    let h = hash_password("a-long-enough-password").unwrap();
    assert!(h.starts_with("$argon2id$"), "{h}");
    let params = h.split('$').nth(3).unwrap();
    let get = |k: &str| {
        params
            .split(',')
            .find_map(|p| p.strip_prefix(&format!("{k}=")))
            .unwrap()
            .parse::<u32>()
            .unwrap()
    };
    assert!(get("m") >= 19456, "memory cost too low: {params}");
    assert!(get("t") >= 2, "time cost too low: {params}");
    // Salted: the same password never hashes the same way twice.
    assert_ne!(h, hash_password("a-long-enough-password").unwrap());
}

#[tokio::test]
async fn weak_new_passwords_are_refused() {
    let h = super::super::tests::harness();
    let cookie = h.login("manager").await;
    for weak in ["", "short", "123456789"] {
        let (s, _, _) = h
            .call(
                "POST",
                "/auth/password",
                Some(&cookie),
                Some(json!({"current_password": "admin-password-1", "new_password": weak})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{weak:?}");
    }
    // The wrong current password doesn't change it either.
    assert_ne!(
        h.call(
            "POST",
            "/auth/password",
            Some(&cookie),
            Some(json!({"current_password": "wrong-password", "new_password": "A-Good-Long-Password"})),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        h.call("GET", "/auth/me", Some(&cookie), None, false).await.0,
        StatusCode::OK
    );
}

// ---------- Guessing limits (SEC-10) ----------

#[tokio::test]
async fn sec10_someones_own_login_does_not_reset_the_failures_against_another_account() {
    let h = super::super::tests::harness();
    let peer = "198.51.100.10";
    // An attacker with their own low-privilege account: guess at the admin, then sign in to clear
    // the count, as many times as they like.
    for _ in 0..4 {
        assert_eq!(
            try_login(&h, peer, "admin", "guess").await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        try_login(&h, peer, "manager", "admin-password-1").await.status,
        StatusCode::OK
    );
    let mut refused = false;
    for _ in 0..4 {
        refused |= try_login(&h, peer, "admin", "guess").await.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(
        refused,
        "signing in reset the count of failed guesses at another account"
    );
}

#[tokio::test]
async fn sec10_parallel_guesses_cannot_outrun_the_limit() {
    let h = super::super::tests::harness();
    let peer = "198.51.100.11";
    let guesses = (0..24).map(|_| try_login(&h, peer, "admin", "guess"));
    let results = futures_util::future::join_all(guesses).await;
    let tried = results.iter().filter(|r| r.status == StatusCode::UNAUTHORIZED).count();
    assert!(tried <= 5, "{tried} guesses at once were all checked, the limit is 5");
}

#[tokio::test]
async fn sec10_changing_address_inside_an_ipv6_network_does_not_get_more_guesses() {
    let h = super::super::tests::harness();
    let mut refused = false;
    for i in 1..=8 {
        let peer = format!("2001:db8:1:2::{i:x}");
        refused |= try_login(&h, &peer, "admin", "guess").await.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(refused, "each address in a /64 got its own 5 guesses");
}

#[tokio::test]
async fn an_ipv4_client_written_as_ipv6_shares_its_limit() {
    let h = super::super::tests::harness();
    for _ in 0..3 {
        try_login(&h, "198.51.100.12", "admin", "guess").await;
    }
    for _ in 0..2 {
        try_login(&h, "::ffff:198.51.100.12", "admin", "guess").await;
    }
    assert_eq!(
        try_login(&h, "198.51.100.12", "admin", "guess").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn sec10_guesses_from_many_addresses_at_one_account_are_limited() {
    let h = super::super::tests::harness();
    let mut refused = false;
    for i in 1..=40 {
        let peer = format!("203.0.113.{i}");
        // Cloudflare ranges don't include this, so each is a different client.
        refused |= try_login(&h, &peer, "admin", "guess").await.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(refused, "a botnet gets unlimited guesses at the admin password");
}

/// Refused by the account's limit, a guess still has to reach fail2ban's log, or spreading guesses
/// over many addresses would keep every one of them from being banned.
#[tokio::test]
async fn guesses_refused_for_the_account_still_reach_fail2ban() {
    let h = super::super::tests::harness();
    for i in 1..=30 {
        try_login(&h, &format!("203.0.113.{i}"), "admin", "guess").await;
    }
    let log = std::fs::read_to_string(&h.auth_log).unwrap();
    assert!(log.contains("from 203.0.113.30 "), "{log}");
}

/// The way back in when someone's locking the admin out from elsewhere is an SSH tunnel.
#[tokio::test]
async fn an_account_locked_from_outside_can_still_sign_in_from_this_machine() {
    let h = super::super::tests::harness();
    for i in 1..=40 {
        try_login(&h, &format!("203.0.113.{i}"), "admin", "guess").await;
    }
    assert_eq!(
        try_login(&h, "127.0.0.1", "admin", "admin-password-1").await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_correct_password_is_still_refused_while_locked_out() {
    let h = super::super::tests::harness();
    let peer = "198.51.100.13";
    for _ in 0..5 {
        try_login(&h, peer, "admin", "guess").await;
    }
    let r = try_login(&h, peer, "admin", "admin-password-1").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers.get(header::SET_COOKIE).is_none());
}

/// A forwarded-address header is the classic way round a per-address limit.
#[tokio::test]
async fn forwarding_headers_do_not_get_more_guesses() {
    let h = super::super::tests::harness();
    let mut refused = false;
    for i in 1..=8 {
        let req = login_req()
            .header("x-forwarded-for", format!("10.0.0.{i}"))
            .header("x-real-ip", format!("10.0.0.{i}"))
            .header("cf-connecting-ip", format!("10.0.0.{i}"))
            .header("forwarded", format!("for=10.0.0.{i}"));
        let r = send(
            &h,
            "198.51.100.14",
            req,
            json_body(&json!({"username": "admin", "password": "guess"})),
        )
        .await;
        refused |= r.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(refused);
}

// ---------- The second factor ----------

#[tokio::test]
async fn a_password_alone_does_not_start_a_session_when_2fa_is_on() {
    let h = super::super::tests::harness();
    enable_2fa(&h);
    let r = try_login(&h, "198.51.100.20", "admin", "admin-password-1").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["mfa_required"], true);
    assert!(r.headers.get(header::SET_COOKIE).is_none());
    assert!(r.json().get("role").is_none(), "{}", r.text());
}

#[tokio::test]
async fn the_second_step_needs_the_right_kind_of_token() {
    let h = super::super::tests::harness();
    let (secret, _) = enable_2fa(&h);
    let code = totp::current_code(&secret, "admin");
    let id = user_id(&h, "admin");
    let session = crate::auth::create_jwt(id, "admin", 0, SECRET).unwrap();
    assert_eq!(
        try_code(&h, "198.51.100.21", &session, &code).await.status,
        StatusCode::UNAUTHORIZED,
        "a session token isn't proof of the password step"
    );
    assert_eq!(
        try_code(&h, "198.51.100.21", "garbage", &code).await.status,
        StatusCode::UNAUTHORIZED
    );
    let forged = crate::auth::create_mfa_token(id, "admin", 0, b"not-the-secret-not-the-secret-not-the").unwrap();
    assert_eq!(
        try_code(&h, "198.51.100.21", &forged, &code).await.status,
        StatusCode::UNAUTHORIZED
    );
    let token = mfa_token(&h, "198.51.100.21").await;
    assert_eq!(
        try_code(&h, "198.51.100.21", &token, &code).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn resetting_the_password_invalidates_a_pending_second_step() {
    let h = super::super::tests::harness();
    let (secret, _) = enable_2fa(&h);
    let token = mfa_token(&h, "198.51.100.22").await;
    db::bump_token_version(&h.pool.get().unwrap(), user_id(&h, "admin")).unwrap();
    let code = totp::current_code(&secret, "admin");
    assert_eq!(
        try_code(&h, "198.51.100.22", &token, &code).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_recovery_code_works_once() {
    let h = super::super::tests::harness();
    let (_, codes) = enable_2fa(&h);
    let token = mfa_token(&h, "198.51.100.23").await;
    assert_eq!(
        try_code(&h, "198.51.100.23", &token, &codes[0]).await.status,
        StatusCode::OK
    );
    let token = mfa_token(&h, "198.51.100.23").await;
    assert_eq!(
        try_code(&h, "198.51.100.23", &token, &codes[0]).await.status,
        StatusCode::UNAUTHORIZED
    );
}

/// Someone holding the password can reach this step from as many addresses as they have.
#[tokio::test]
async fn sec10_guessing_the_code_from_many_addresses_is_limited() {
    let h = super::super::tests::harness();
    let (secret, _) = enable_2fa(&h);
    let token = mfa_token(&h, "198.51.100.24").await;
    let mut refused_at = None;
    for i in 1..=12 {
        let peer = format!("203.0.113.{i}");
        if try_code(&h, &peer, &token, "000000").await.status == StatusCode::TOO_MANY_REQUESTS {
            refused_at = Some(i);
            break;
        }
    }
    assert!(refused_at.is_some(), "a TOTP code can be guessed without limit");
    // Stays that way for the right code, or the limit tells an attacker when they've got it.
    let good = totp::current_code(&secret, "admin");
    assert_eq!(
        try_code(&h, "198.51.100.200", &token, &good).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[test]
fn codes_that_could_never_be_right_are_refused() {
    let secret = totp::generate_secret();
    for bad in ["", "abcdef", "12345", "1234567", "' OR 1=1 --", "\0\0\0\0\0\0"] {
        assert!(!totp::verify(&secret, "admin", bad), "{bad:?}");
    }
    assert!(totp::verify(&secret, "admin", &totp::current_code(&secret, "admin")));
}

#[tokio::test]
async fn a_very_long_code_is_refused_before_it_is_looked_at() {
    let h = super::super::tests::harness();
    enable_2fa(&h);
    let token = mfa_token(&h, "198.51.100.25").await;
    assert_eq!(
        try_code(&h, "198.51.100.25", &token, &"9".repeat(33)).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn sql_in_a_username_is_only_a_wrong_username() {
    let h = super::super::tests::harness();
    for (i, name) in [
        "admin' --",
        "admin' OR '1'='1",
        "\" OR \"\"=\"",
        "'; DROP TABLE users; --",
    ]
    .iter()
    .enumerate()
    {
        let peer = format!("198.51.100.{}", 30 + i);
        assert_eq!(
            try_login(&h, &peer, name, "x").await.status,
            StatusCode::UNAUTHORIZED,
            "{name}"
        );
    }
    assert!(db::find_user_by_username(&h.pool.get().unwrap(), "admin")
        .unwrap()
        .is_some());
}
