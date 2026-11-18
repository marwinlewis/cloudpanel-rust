//! The Email page's API: admin-only, CRUD round trips, secrets shown once, audit entries.

use crate::api::tests::{harness, Harness};
use axum::http::StatusCode;
use serde_json::{json, Value};

async fn call(h: &Harness, cookie: &str, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let (s, v, _) = h.call(method, path, Some(cookie), body, true).await;
    (s, v)
}

fn audited(h: &Harness, action: &str) -> bool {
    let conn = h.pool.get().unwrap();
    conn.query_row("SELECT COUNT(*) FROM events WHERE action = ?1", [action], |r| {
        r.get::<_, i64>(0)
    })
    .unwrap()
        > 0
}

#[tokio::test]
async fn managers_cannot_use_any_mail_route() {
    let h = harness();
    let c = h.login("manager").await;
    for (m, p) in [
        ("GET", "/mail"),
        ("GET", "/mail/status"),
        ("POST", "/mail/domains"),
        ("POST", "/mail/forwards"),
        ("POST", "/mail/keys"),
        ("DELETE", "/mail/keys/abc"),
        ("GET", "/mail/log"),
    ] {
        let (s, _) = call(&h, &c, m, p, Some(json!({}))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {p}");
    }
}

#[tokio::test]
async fn domains_forwards_keys_and_webhooks_round_trip() {
    let h = harness();
    let c = h.login("admin").await;

    let (s, v) = call(&h, &c, "GET", "/mail", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["installed"], true);
    assert_eq!(v["domains"].as_array().unwrap().len(), 0);
    assert!(v["event_types"].as_array().unwrap().len() >= 4);

    // Domain, with its DNS records.
    let (s, v) = call(&h, &c, "POST", "/mail/domains", Some(json!({"domain": "Example.com"}))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["name"], "example.com");
    assert_eq!(v["records"].as_array().unwrap().len(), 4);
    assert!(audited(&h, "mail.domain_add"));
    let (s, _) = call(&h, &c, "POST", "/mail/domains", Some(json!({"domain": "example.com"}))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = call(&h, &c, "POST", "/mail/domains", Some(json!({"domain": "not a domain"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = call(&h, &c, "GET", "/mail/domains/example.com/dns", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["records"][0]["required"], true);
    let (s, _) = call(&h, &c, "GET", "/mail/domains/nope.com/dns", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, v) = call(
        &h,
        &c,
        "POST",
        "/mail/domains/example.com/verify",
        Some(json!({"force": true})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["verified"], true);

    // Forwarding address.
    let (s, v) = call(
        &h,
        &c,
        "POST",
        "/mail/forwards",
        Some(json!({"address": "hi@example.com", "to": "me@gmail.com"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["forward_to"], "me@gmail.com");
    let (s, _) = call(
        &h,
        &c,
        "POST",
        "/mail/forwards",
        Some(json!({"address": "hi@other.com", "to": "me@gmail.com"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Key: the secret comes back once and is never listed.
    let (s, v) = call(
        &h,
        &c,
        "POST",
        "/mail/keys",
        Some(json!({"name": "gmail", "domain": "example.com", "permission": "sending", "hourly_limit": 100})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let secret = v["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("cp_"));
    assert_eq!(v["smtp"]["username"], "cloudpanel");
    let key_id = v["key"]["id"].as_str().unwrap().to_string();
    assert!(v["key"].get("secret_hash").is_none());
    let (s, _) = call(
        &h,
        &c,
        "POST",
        "/mail/keys",
        Some(json!({"name": "x", "permission": "root"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Webhook: same for its signing secret.
    let (s, v) = call(
        &h,
        &c,
        "POST",
        "/mail/webhooks",
        Some(json!({"url": "https://hooks.example.org/x", "events": ["email.bounced"]})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let hook_secret = v["secret"].as_str().unwrap().to_string();
    let hook_id = v["webhook"]["id"].as_str().unwrap().to_string();
    let (s, _) = call(
        &h,
        &c,
        "POST",
        "/mail/webhooks",
        Some(json!({"url": "http://hooks.example.org/x"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (_, v) = call(&h, &c, "GET", "/mail", None).await;
    let text = v.to_string();
    assert!(!text.contains(&secret), "key secret listed");
    assert!(!text.contains(&hook_secret), "webhook secret listed");
    assert_eq!(v["domains"][0]["verified"], true);
    assert_eq!(v["forwards"].as_array().unwrap().len(), 1);
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    assert_eq!(v["webhooks"].as_array().unwrap().len(), 1);

    // Log (empty) and its filter.
    let (s, v) = call(&h, &c, "GET", "/mail/log?status=bounced", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["messages"].as_array().unwrap().len(), 0);
    let (s, _) = call(&h, &c, "GET", "/mail/log?status=nonsense", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(&h, &c, "GET", "/mail/log/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Removing.
    let (s, _) = call(&h, &c, "DELETE", &format!("/mail/webhooks/{hook_id}"), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&h, &c, "DELETE", "/mail/forwards/hi@example.com", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&h, &c, "DELETE", "/mail/forwards/hi@example.com", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Removing the domain also revokes the key limited to it.
    let (s, v) = call(&h, &c, "DELETE", "/mail/domains/example.com", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&h, &c, "DELETE", &format!("/mail/keys/{key_id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    for a in [
        "mail.domain_verify",
        "mail.forward_add",
        "mail.forward_remove",
        "mail.key_create",
        "mail.webhook_add",
        "mail.webhook_remove",
        "mail.domain_remove",
    ] {
        assert!(audited(&h, a), "{a} not audited");
    }
}
