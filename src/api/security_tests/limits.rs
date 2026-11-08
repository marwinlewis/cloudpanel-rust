//! Malformed and oversized requests, what stays out of errors, and what gets written down.

use super::*;
use serde_json::json;

fn assert_refused(r: &Response, why: &str) {
    assert!(
        r.status.is_client_error(),
        "{why}: {} {}",
        r.status,
        r.text().chars().take(200).collect::<String>()
    );
}

#[tokio::test]
async fn the_default_body_limit_applies_before_any_parsing() {
    let h = super::super::tests::harness();
    let big = format!(r#"{{"username":"{}","password":"x"}}"#, "a".repeat(300 * 1024));
    let r = send(&h, "127.0.0.1", api("POST", "/auth/login"), Body::from(big)).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_file_editor_has_its_own_smaller_limit() {
    let h = super::super::tests::harness();
    let (id, _) = managed_site_with_home(&h, "big.example.com");
    let cookie = h.login("manager").await;
    let huge = "x".repeat(4 * 1024 * 1024);
    let r = send(
        &h,
        "127.0.0.1",
        api("PUT", &format!("/sites/{id}/files/content")).header(header::COOKIE, &cookie),
        json_body(&json!({"path": "x.txt", "content": huge})),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Under the transport limit but over the editor's.
    let large = "x".repeat(2 * 1024 * 1024 + 1);
    let r = send(
        &h,
        "127.0.0.1",
        api("PUT", &format!("/sites/{id}/files/content")).header(header::COOKIE, &cookie),
        json_body(&json!({"path": "x.txt", "content": large})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

/// Nothing here may panic. In release builds a panic ends the whole panel (`panic = "abort"`).
#[tokio::test]
async fn malformed_bodies_get_an_error_not_a_crash() {
    let h = super::super::tests::harness();
    let deep = "[".repeat(100_000);
    let bodies: Vec<Vec<u8>> = vec![
        vec![],
        b"{".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"\"x\"".to_vec(),
        vec![0xff, 0xfe, 0x00],
        deep.into_bytes(),
        br#"{"username":1,"password":2}"#.to_vec(),
        br#"{"username":null,"password":null}"#.to_vec(),
        br#"{"username":"a","username":"b","password":"c"}"#.to_vec(),
    ];
    for (i, b) in bodies.into_iter().enumerate() {
        let r = send(&h, "127.0.0.1", api("POST", "/auth/login"), Body::from(b)).await;
        assert_refused(&r, &format!("body {i}"));
    }
}

#[tokio::test]
async fn malformed_paths_get_an_error_not_a_crash() {
    let h = super::super::tests::harness();
    let cookie = h.login("admin").await;
    for path in [
        "/sites/abc",
        "/sites/-1",
        "/sites/99999999999999999999999",
        "/sites/1%00",
        "/databases/0/export",
        "/jobs/9223372036854775807",
        "/sites/1/files/content",
        "/sites/1/files?path=%ff%fe",
        "/sites/9223372036854775807/files?path=x",
    ] {
        let r = send(
            &h,
            "127.0.0.1",
            api("GET", path).header(header::COOKIE, &cookie),
            Body::empty(),
        )
        .await;
        assert_refused(&r, path);
    }
}

#[tokio::test]
async fn malformed_uploads_get_an_error_not_a_crash() {
    let h = super::super::tests::harness();
    let (id, _) = managed_site_with_home(&h, "up.example.com");
    let cookie = h.login("manager").await;
    let url = format!("/sites/{id}/files/upload");
    for (kind, body) in [
        ("multipart/form-data", "x"),
        ("multipart/form-data; boundary=x", ""),
        ("multipart/form-data; boundary=x", "--x\r\nbroken"),
        ("multipart/form-data; boundary=x", "--x--\r\n"),
        ("application/json", "{}"),
    ] {
        let r = send(
            &h,
            "127.0.0.1",
            api_untyped("POST", &url)
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, kind),
            Body::from(body),
        )
        .await;
        assert_refused(&r, kind);
    }
}

fn upload_body(name: &str, content: &str) -> String {
    format!("--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\r\n{content}\r\n--x--\r\n")
}

/// The name a browser sends is the client's choice.
#[tokio::test]
async fn an_upload_cannot_choose_where_it_lands_by_its_name() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "upname.example.com");
    let cookie = h.login("manager").await;
    let url = format!("/sites/{id}/files/upload");
    for name in [
        "../outside.txt",
        "..\\outside.txt",
        "/tmp/cp-outside.txt",
        "a/../../outside.txt",
    ] {
        send(
            &h,
            "127.0.0.1",
            api_untyped("POST", &url)
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "multipart/form-data; boundary=x"),
            Body::from(upload_body(name, "pwned")),
        )
        .await;
        assert!(
            !home.parent().unwrap().join("outside.txt").exists(),
            "{name} landed outside the home"
        );
    }
    assert!(!std::path::Path::new("/tmp/cp-outside.txt").exists());
}

#[tokio::test]
async fn no_upload_temp_file_is_left_behind() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "uptemp.example.com");
    let cookie = h.login("manager").await;
    let r = send(
        &h,
        "127.0.0.1",
        api_untyped("POST", &format!("/sites/{id}/files/upload"))
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "multipart/form-data; boundary=x"),
        Body::from(upload_body("good.txt", "hello")),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(std::fs::read_to_string(home.join("good.txt")).unwrap(), "hello");
    let leftovers: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".upload"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// Anonymous clients don't get to make the panel store a large file before being turned away.
#[tokio::test]
async fn an_upload_is_refused_before_it_is_read_if_not_signed_in() {
    let h = super::super::tests::harness();
    let (id, home) = managed_site_with_home(&h, "anonup.example.com");
    let r = send(
        &h,
        "127.0.0.1",
        api_untyped("POST", &format!("/sites/{id}/files/upload"))
            .header(header::CONTENT_TYPE, "multipart/form-data; boundary=x"),
        Body::from(upload_body("x.txt", "x")),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 2, "only what was there");
}

// ---------- Errors ----------

#[test]
fn internal_errors_do_not_describe_the_server() {
    use axum::response::IntoResponse;
    let res = crate::api::error::ApiError::internal("disk full at /var/lib/cloudpanel/secret.key").into_response();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let debug = format!("{:?}", res.headers());
    assert!(!debug.contains("secret.key"));
}

// ---------- Audit log ----------

fn all_events() -> db::EventFilter {
    db::EventFilter {
        username: None,
        action: None,
        since: None,
        until: None,
        before_id: None,
        limit: 50,
    }
}

fn last_failure(h: &Harness) -> Option<db::models::Event> {
    let conn = h.pool.get().unwrap();
    db::list_events(&conn, &all_events())
        .unwrap()
        .into_iter()
        .find(|e| e.action == "auth.login_failed")
}

#[tokio::test]
async fn failed_logins_are_recorded() {
    let h = super::super::tests::harness();
    send(
        &h,
        "198.51.100.40",
        api("POST", "/auth/login"),
        json_body(&json!({"username": "admin", "password": "wrong"})),
    )
    .await;
    let e = last_failure(&h).expect("no audit entry");
    assert_eq!(e.ip.as_deref(), Some("198.51.100.40"));
    assert_eq!(e.username.as_deref(), Some("admin"));
    assert!(std::fs::read_to_string(&h.auth_log)
        .unwrap()
        .contains("from 198.51.100.40"));
}

/// fail2ban reads this file. A forged line in it could get someone else banned.
#[tokio::test]
async fn a_username_cannot_forge_a_line_in_the_auth_log() {
    let h = super::super::tests::harness();
    let forged = "x\n1 cloudpanel auth failure from 203.0.113.99 user=admin";
    send(
        &h,
        "198.51.100.41",
        api("POST", "/auth/login"),
        json_body(&json!({"username": forged, "password": "wrong"})),
    )
    .await;
    let log = std::fs::read_to_string(&h.auth_log).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.contains("from 198.51.100.41"), "{log}");
    let after_from = log.split("from ").nth(2);
    assert!(after_from.is_none(), "a second address got in: {log}");
}

#[tokio::test]
async fn account_changes_are_recorded_without_the_password() {
    let h = super::super::tests::harness();
    let admin = h.login("admin").await;
    let (s, _, _) = h
        .call(
            "POST",
            "/users",
            Some(&admin),
            Some(json!({"username": "newbie", "password": "The-Secret-Password-1", "email": "n@example.com", "role": "site_manager"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let events = db::list_events(&h.pool.get().unwrap(), &all_events()).unwrap();
    assert!(events.iter().any(|e| e.action.starts_with("user.")), "{events:?}");
    let text = format!("{events:?}");
    assert!(!text.contains("The-Secret-Password-1"), "{text}");
}

#[tokio::test]
async fn only_admins_can_read_the_audit_log() {
    let h = super::super::tests::harness();
    let cookie = h.login("manager").await;
    assert_eq!(
        h.call("GET", "/events", Some(&cookie), None, false).await.0,
        StatusCode::FORBIDDEN
    );
}

// ---------- The whole request path ----------

/// Bans are checked before anything else, so a banned client can't even load the page.
#[tokio::test]
async fn a_banned_client_is_refused_for_everything() {
    let h = super::super::tests::harness();
    h.ban("198.51.100.50");
    for (method, path) in [("GET", "/"), ("GET", "/api/auth/me"), ("POST", "/api/auth/login")] {
        assert_eq!(
            h.from("198.51.100.50", method, path, &[]).await,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
}

/// The router only hands out what's built into the binary.
#[tokio::test]
async fn static_files_cannot_be_used_to_read_from_disk() {
    let h = super::super::tests::harness();
    for path in [
        "/../Cargo.toml",
        "/..%2f..%2fCargo.toml",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/js/../../Cargo.toml",
        "/etc/passwd",
    ] {
        let r = send(&h, "127.0.0.1", axum::http::Request::builder().uri(path), Body::empty()).await;
        let text = r.text();
        assert!(!text.contains("[package]") && !text.contains("root:"), "{path}: {text}");
    }
}
