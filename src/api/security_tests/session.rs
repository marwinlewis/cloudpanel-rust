//! Sessions after sign-in: cookie settings, and when one stops working.

use super::*;
use crate::auth::{create_jwt, session_cookie};
use serde_json::json;

async fn me(h: &Harness, cookie: &str) -> StatusCode {
    h.call("GET", "/auth/me", Some(cookie), None, false).await.0
}

#[test]
fn the_session_cookie_cannot_be_read_by_scripts_or_sent_cross_site() {
    let c = session_cookie(Some("t"), true);
    assert!(c.contains("HttpOnly"), "{c}");
    assert!(c.contains("SameSite=Strict"), "{c}");
    assert!(c.contains("; Secure"), "{c}");
    assert!(c.contains("Path=/"), "{c}");
    assert!(!session_cookie(Some("t"), false).contains("Secure"));
    let gone = session_cookie(None, true);
    assert!(gone.contains("Max-Age=0"), "{gone}");
}

#[tokio::test]
async fn a_login_sets_the_cookie_with_every_protection() {
    let h = super::super::tests::harness();
    let r = send(
        &h,
        "127.0.0.1",
        api("POST", "/auth/login"),
        json_body(&json!({"username": "admin", "password": "admin-password-1"})),
    )
    .await;
    let cookie = r.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    // The token only goes in the cookie, where scripts can't get it.
    assert!(!r.text().contains("eyJ"), "{}", r.text());
}

#[tokio::test]
async fn a_new_password_ends_every_other_session() {
    let h = super::super::tests::harness();
    let old = h.login("manager").await;
    let (s, _, _) = h
        .call(
            "POST",
            "/auth/password",
            Some(&old),
            Some(json!({"current_password": "admin-password-1", "new_password": "A-New-Long-Password-1"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me(&h, &old).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_admins_password_reset_ends_the_users_sessions() {
    let h = super::super::tests::harness();
    let session = h.login("manager").await;
    let admin = h.login("admin").await;
    let id = user_id(&h, "manager");
    let (s, _, _) = h
        .call(
            "POST",
            &format!("/users/{id}/password"),
            Some(&admin),
            Some(json!({"password": "A-New-Long-Password-1"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me(&h, &session).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_deleted_user_loses_access_at_once() {
    let h = super::super::tests::harness();
    let session = h.login("manager").await;
    db::delete_user(&h.pool.get().unwrap(), user_id(&h, "manager")).unwrap();
    assert_eq!(me(&h, &session).await, StatusCode::UNAUTHORIZED);
}

/// The role comes from the database on each request, not from the token.
#[tokio::test]
async fn a_demoted_admin_loses_admin_rights_at_once() {
    let h = super::super::tests::harness();
    let extra = {
        let conn = h.pool.get().unwrap();
        let hash = crate::auth::hash_password("admin-password-1").unwrap();
        db::create_user(&conn, "second", &hash, "s@example.com", "admin").unwrap()
    };
    let session = h.login("second").await;
    assert_eq!(
        h.call("GET", "/users", Some(&session), None, false).await.0,
        StatusCode::OK
    );
    db::update_user(&h.pool.get().unwrap(), extra, "s@example.com", "site_manager").unwrap();
    // A role change also ends their sessions, which is stricter than refusing this one request.
    let got = h.call("GET", "/users", Some(&session), None, false).await.0;
    assert!(got == StatusCode::FORBIDDEN || got == StatusCode::UNAUTHORIZED, "{got}");
}

/// A bad token in the header must not fall back to the cookie. That would let the CSRF check,
/// which is skipped for bearer tokens, be skipped on the strength of any made-up header.
#[tokio::test]
async fn a_bad_bearer_token_never_falls_back_to_the_cookie() {
    let h = super::super::tests::harness();
    let cookie = h.login("admin").await;
    let r = send(
        &h,
        "127.0.0.1",
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/auth/logout-all")
            .header(header::COOKIE, &cookie)
            .header(header::AUTHORIZATION, "Bearer made-up"),
        Body::empty(),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me(&h, &cookie).await, StatusCode::OK, "the request took effect");
}

#[tokio::test]
async fn a_good_bearer_token_works_and_does_not_need_the_csrf_header() {
    let h = super::super::tests::harness();
    let token = create_jwt(user_id(&h, "admin"), "admin", 0, SECRET).unwrap();
    let r = send(
        &h,
        "127.0.0.1",
        axum::http::Request::builder()
            .uri("/api/auth/me")
            .header(header::AUTHORIZATION, format!("Bearer {token}")),
        Body::empty(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[test]
fn tokens_are_signed_with_the_one_algorithm_expected() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    let c = Claims {
        sub: "admin".into(),
        uid: 1,
        ver: 0,
        iat: 0,
        exp: (chrono::Utc::now().timestamp() + 3600) as usize,
        purpose: None,
        jti: String::new(),
    };
    // Same key, stronger-looking algorithm. Still not what the panel issues.
    let hs512 = jsonwebtoken::encode(&Header::new(Algorithm::HS512), &c, &EncodingKey::from_secret(SECRET)).unwrap();
    assert!(crate::auth::verify_jwt(&hs512, SECRET).is_err());
}

#[test]
fn a_token_cannot_be_used_after_the_session_length_even_if_valid_otherwise() {
    let t = create_jwt(1, "admin", 0, SECRET).unwrap();
    let c = crate::auth::verify_jwt(&t, SECRET).unwrap();
    let hours = (c.exp - c.iat) / 3600;
    assert!(hours <= 12, "sessions last {hours} hours");
}

/// Signing out must end the session where it's checked, on the server. Clearing the cookie only
/// helps the browser it's in, not whoever copied the token.
#[tokio::test]
async fn sec13_signing_out_ends_the_session_on_the_server() {
    let h = super::super::tests::harness();
    let cookie = h.login("manager").await;
    let other = h.login("manager").await;
    let (s, _, _) = h.call("POST", "/auth/logout", Some(&cookie), None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me(&h, &cookie).await, StatusCode::UNAUTHORIZED);
    // Only that session: signing out of one browser leaves the others.
    assert_eq!(me(&h, &other).await, StatusCode::OK);
}

#[tokio::test]
async fn sec13_signing_out_a_bearer_token_ends_it_too() {
    let h = super::super::tests::harness();
    let token = create_jwt(user_id(&h, "manager"), "manager", 0, SECRET).unwrap();
    let with = |method: &str, path: &str| {
        axum::http::Request::builder()
            .method(method)
            .uri(format!("/api{path}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
    };
    assert_eq!(
        send(&h, "127.0.0.1", with("POST", "/auth/logout"), Body::empty())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(&h, "127.0.0.1", with("GET", "/auth/me"), Body::empty())
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

/// Without a session, or with a made-up one, there's nothing to end, and that isn't an error.
#[tokio::test]
async fn signing_out_without_a_session_still_succeeds() {
    let h = super::super::tests::harness();
    for cookie in [None, Some("cp_session=made-up")] {
        let (s, _, set) = h.call("POST", "/auth/logout", cookie, None, true).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(set.as_deref(), Some("cp_session="));
    }
}

#[test]
fn signed_out_tokens_are_forgotten_once_they_would_have_expired() {
    let h = super::super::tests::harness();
    let conn = h.pool.get().unwrap();
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    db::revoke_token(&conn, "old", past).unwrap();
    db::revoke_token(&conn, "new", future).unwrap();
    assert_eq!(db::prune_revoked_tokens(&conn, chrono::Utc::now()).unwrap(), 1);
    assert!(!db::is_token_revoked(&conn, "old").unwrap());
    assert!(db::is_token_revoked(&conn, "new").unwrap());
}
