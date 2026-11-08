//! End-to-end API tests: CSRF, role-based access and the two-step MFA login, run
//! against the real router with a temporary database.

use crate::auth::{hash_password, totp, LoginLimiter};
use crate::config::Config;
use crate::db::{self, NewSite};
use crate::services::MetricsCollector;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

pub(super) struct Harness {
    pub(super) app: Router,
    pub(super) _dir: tempfile::TempDir,
    pub(super) pool: db::DbPool,
    pub(super) bans: std::path::PathBuf,
    pub(super) auth_log: std::path::PathBuf,
}

pub(super) fn harness() -> Harness {
    harness_with(|_| {})
}

pub(super) fn harness_with(adjust: impl FnOnce(&mut Config)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::from_env();
    adjust(&mut config);
    let d = dir.path();
    config.data_dir = d.join("data");
    config.db_path = d.join("data/cp.db");
    config.etc_dir = d.join("etc");
    config.log_dir = d.join("log");
    config.ban_dir = d.join("bans");
    std::fs::create_dir_all(&config.ban_dir).unwrap();
    let bans = config.ban_dir.clone();
    let auth_log = config.log_dir.join("auth.log");
    config.nginx_sites_available = d.join("nginx/sites-available");
    config.nginx_sites_enabled = d.join("nginx/sites-enabled");
    config.cron_file = d.join("cron");
    let pool = db::init_db(&config.db_path).unwrap();
    {
        let conn = pool.get().unwrap();
        let hash = hash_password("admin-password-1").unwrap();
        db::create_user(&conn, "admin", &hash, "admin@example.com", "admin").unwrap();
        let mgr = db::create_user(&conn, "manager", &hash, "m@example.com", "site_manager").unwrap();
        let mk = |domain: &str| {
            db::create_site(
                &conn,
                &NewSite {
                    domain,
                    site_type: "nodejs",
                    target_port: Some(3000),
                    document_root: None,
                    system_user: "cloudpanel",
                    include_www: false,
                    www_redirect: false,
                    home_dir: None,
                    app_command: None,
                    app_manager: "systemd",
                    php_version: None,
                },
            )
            .unwrap()
        };
        let mine = mk("mine.example.com");
        mk("other.example.com");
        db::grant_site(&conn, mgr, mine).unwrap();
    }
    let state = Arc::new(AppState {
        pool: pool.clone(),
        config,
        jwt_secret: b"test-secret-test-secret-test-secret!!".to_vec(),
        proxy_secret: "test-proxy-secret".into(),
        direct_closed: false,
        cloudflare: std::sync::RwLock::new(crate::services::cloudflare::Ranges::built_in()),
        limiter: LoginLimiter::default(),
        metrics: Arc::new(Mutex::new(MetricsCollector::default())),
        tls: Mutex::new(None),
    });
    Harness {
        app: super::create_app(state),
        _dir: dir,
        pool,
        bans,
        auth_log,
    }
}

impl Harness {
    pub(super) fn ban(&self, ip: &str) {
        std::fs::write(self.bans.join(ip), "").unwrap();
    }

    fn unban(&self, ip: &str) {
        std::fs::remove_file(self.bans.join(ip)).unwrap();
    }

    /// The status of one request on a connection from `peer`.
    pub(super) async fn from(&self, peer: &str, method: &str, path: &str, headers: &[(&str, &str)]) -> StatusCode {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(super::CSRF_HEADER, super::CSRF_VALUE)
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let body = if method == "POST" {
            json!({"username": "admin", "password": "wrong"}).to_string()
        } else {
            String::new()
        };
        let mut req = req.body(Body::from(body)).unwrap();
        let ip: std::net::IpAddr = peer.parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, 5555)));
        self.app.clone().oneshot(req).await.unwrap().status()
    }

    pub(super) async fn call(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<Value>,
        csrf: bool,
    ) -> (StatusCode, Value, Option<String>) {
        let mut req = Request::builder().method(method).uri(format!("/api{path}"));
        if csrf {
            req = req.header(super::CSRF_HEADER, super::CSRF_VALUE);
        }
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        let mut req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        req.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>("127.0.0.1:5555".parse().unwrap()));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let set_cookie = res
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::to_string);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v, set_cookie)
    }

    pub(super) async fn login(&self, user: &str) -> String {
        let (s, _, c) = self
            .call(
                "POST",
                "/auth/login",
                None,
                Some(json!({"username": user, "password": "admin-password-1"})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        c.unwrap()
    }
}

#[tokio::test]
async fn csrf_header_is_required_for_mutations() {
    let h = harness();
    let (s, _, _) = h
        .call(
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "x"})),
            false,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// Browsers talk HTTP/2 to the panel: no Host header, the host is in the URI
/// authority. A same-origin login must still pass the CSRF check.
#[tokio::test]
async fn same_origin_login_over_http2_is_allowed() {
    let h = harness();
    let send = |origin: &'static str| {
        let mut req = Request::builder()
            .method("POST")
            .uri("https://203.0.113.5:8443/api/auth/login")
            .version(axum::http::Version::HTTP_2)
            .header(super::CSRF_HEADER, super::CSRF_VALUE)
            .header("sec-fetch-site", "same-origin")
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"username": "admin", "password": "admin-password-1"}).to_string(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>("127.0.0.1:5555".parse().unwrap()));
        h.app.clone().oneshot(req)
    };
    let res = send("https://203.0.113.5:8443").await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = send("https://evil.example.com").await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn site_managers_only_see_their_sites() {
    let h = harness();
    let cookie = h.login("manager").await;
    let (s, v, _) = h.call("GET", "/sites", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::OK);
    let domains: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["domain"].as_str().unwrap())
        .collect();
    assert_eq!(domains, vec!["mine.example.com"]);
    let other = db::list_sites(&h.pool.get().unwrap())
        .unwrap()
        .into_iter()
        .find(|s| s.domain == "other.example.com")
        .unwrap();
    let (s, _, _) = h
        .call("GET", &format!("/sites/{}", other.id), Some(&cookie), None, false)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for path in [
        "/firewall/rules",
        "/users",
        "/services",
        "/events",
        "/system/metrics",
        "/fail2ban",
    ] {
        let (s, _, _) = h.call("GET", path, Some(&cookie), None, false).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}");
    }
    let (s, _, _) = h
        .call(
            "POST",
            "/sites",
            Some(&cookie),
            Some(json!({"domain": "x.example.com", "site_type": "static"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Custom nginx directives are admin-only even on an assigned site.
    let mine = v[0]["id"].as_i64().unwrap();
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("/sites/{mine}/directives"),
            Some(&cookie),
            Some(json!({"custom_directives": ""})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn last_admin_cannot_be_demoted() {
    let h = harness();
    let cookie = h.login("admin").await;
    let (_, users, _) = h.call("GET", "/users", Some(&cookie), None, false).await;
    let admin_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "admin")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("/users/{admin_id}"),
            Some(&cookie),
            Some(json!({"email": "admin@example.com", "role": "site_manager"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn two_factor_login_flow() {
    let h = harness();
    let cookie = h.login("admin").await;
    let (s, setup, _) = h.call("POST", "/auth/2fa/setup", Some(&cookie), None, true).await;
    assert_eq!(s, StatusCode::OK);
    let secret = setup["secret"].as_str().unwrap().to_string();
    let (s, _, _) = h
        .call(
            "POST",
            "/auth/2fa/enable",
            Some(&cookie),
            Some(json!({"code": "000000x"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let code = totp::current_code(&secret, "admin");
    let (s, enabled, _) = h
        .call(
            "POST",
            "/auth/2fa/enable",
            Some(&cookie),
            Some(json!({"code": code})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let recovery = enabled["recovery_codes"][0].as_str().unwrap().to_string();

    // Password alone now yields an MFA token, not a session.
    let (s, step1, c) = h
        .call(
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "admin-password-1"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(c.is_none());
    assert_eq!(step1["mfa_required"], true);
    let mfa_token = step1["mfa_token"].as_str().unwrap().to_string();

    // The MFA token must not work as a session.
    let (s, _, _) = h
        .call("GET", "/auth/me", Some(&format!("cp_session={mfa_token}")), None, false)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _, _) = h
        .call(
            "POST",
            "/auth/login/mfa",
            None,
            Some(json!({"mfa_token": mfa_token, "code": "123456"})),
            true,
        )
        .await;
    assert!(s == StatusCode::UNAUTHORIZED || code == "123456");
    let (s, _, c) = h
        .call(
            "POST",
            "/auth/login/mfa",
            None,
            Some(json!({"mfa_token": mfa_token, "code": recovery})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let session = c.unwrap();
    let (s, me, _) = h.call("GET", "/auth/me", Some(&session), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["recovery_codes_left"], 9);
    // A recovery code works only once.
    let (s, _, _) = h
        .call(
            "POST",
            "/auth/login/mfa",
            None,
            Some(json!({"mfa_token": mfa_token, "code": recovery})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Regression tests: authentication, sessions, user management and router basics.
// ---------------------------------------------------------------------------

async fn try_login(h: &Harness, user: &str, pw: &str) -> (StatusCode, Value, Option<String>) {
    h.call(
        "POST",
        "/auth/login",
        None,
        Some(json!({"username": user, "password": pw})),
        true,
    )
    .await
}

#[tokio::test]
async fn protected_endpoints_require_a_session() {
    let h = harness();
    for path in ["/auth/me", "/sites", "/users", "/cron/jobs", "/jobs", "/events"] {
        let (s, _, _) = h.call("GET", path, None, None, false).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
    }
    let (s, _, _) = h
        .call("GET", "/auth/me", Some("cp_session=not-a-jwt"), None, false)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_endpoints_return_json_404_and_no_store() {
    let h = harness();
    let (s, v, _) = h.call("GET", "/does-not-exist", None, None, false).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(v["error"].is_string());

    let mut req = Request::builder().uri("/api/auth/me").body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo::<SocketAddr>("127.0.0.1:5555".parse().unwrap()));
    let res = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
}

#[tokio::test]
async fn cross_site_fetch_metadata_is_blocked() {
    let h = harness();
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(super::CSRF_HEADER, super::CSRF_VALUE)
        .header("sec-fetch-site", "cross-site")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"username": "admin", "password": "admin-password-1"}).to_string(),
        ))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo::<SocketAddr>("127.0.0.1:5555".parse().unwrap()));
    let res = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// An imported site's vhost can't be reproduced, so nothing may rewrite it. Each of these has to be
/// refused before doing anything: a Let's Encrypt request, for one, would run certbot, which edits
/// and reloads nginx, if it only failed at the end.
#[tokio::test]
async fn imported_sites_refuse_everything_that_would_touch_their_nginx_config() {
    let h = harness();
    let id = {
        let conn = h.pool.get().unwrap();
        conn.execute(
            "UPDATE sites SET vhost_managed = 0 WHERE domain = 'mine.example.com'",
            [],
        )
        .unwrap();
        db::list_sites(&conn)
            .unwrap()
            .into_iter()
            .find(|s| s.domain == "mine.example.com")
            .unwrap()
            .id
    };
    let cookie = h.login("admin").await;
    let attempts = [
        ("PATCH", format!("/sites/{id}"), json!({"max_body_mb": 99})),
        ("POST", format!("/sites/{id}/state"), json!({"active": false})),
        ("POST", format!("/sites/{id}/ssl"), json!({"email": "me@example.com"})),
        ("DELETE", format!("/sites/{id}/ssl"), json!({})),
        (
            "PUT",
            format!("/sites/{id}/directives"),
            json!({"custom_directives": ""}),
        ),
        (
            "PUT",
            format!("/sites/{id}/basic-auth"),
            json!({"enabled": false, "allow": []}),
        ),
        (
            "POST",
            format!("/sites/{id}/basic-auth/users"),
            json!({"username": "someone", "password": "long-enough-1"}),
        ),
    ];
    for (method, path, body) in attempts {
        let (s, v, _) = h.call(method, &path, Some(&cookie), Some(body), true).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{method} {path}: {v}");
        assert!(
            v["error"].as_str().unwrap().contains("imported from CloudPanel CE"),
            "{method} {path}: {v}"
        );
    }
    let conn = h.pool.get().unwrap();
    let site = db::find_site_by_id(&conn, id).unwrap().unwrap();
    assert!(site.is_active && !site.ssl_enabled, "nothing about the site changed");
    assert!(db::list_basic_auth_users(&conn, id).unwrap().is_empty());
}

#[tokio::test]
async fn php_sites_need_php_to_be_enabled_when_installing() {
    let h = harness_with(|c| c.php_enabled = false);
    let cookie = h.login("admin").await;
    let (s, v, _) = h
        .call(
            "POST",
            "/sites",
            Some(&cookie),
            Some(json!({"domain": "blog.example.com", "site_type": "php"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("--with-php"), "{v}");
    let (s, v, _) = h.call("GET", "/sites/options", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["php_enabled"], false);
    let conn = h.pool.get().unwrap();
    assert!(!db::list_sites(&conn)
        .unwrap()
        .iter()
        .any(|s| s.domain == "blog.example.com"));
}

#[tokio::test]
async fn login_rejects_bad_credentials_and_reports_identity() {
    let h = harness();
    for (user, pw) in [("admin", "wrong-password"), ("nobody", "admin-password-1")] {
        let (s, v, c) = try_login(&h, user, pw).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{user}");
        assert!(c.is_none());
        // Same message for unknown users and wrong passwords (no user enumeration).
        assert_eq!(v["error"], "Invalid username or password");
    }
    let cookie = h.login("admin").await;
    assert!(cookie.starts_with("cp_session="));
    let (s, me, _) = h.call("GET", "/auth/me", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["username"], "admin");
    assert_eq!(me["role"], "admin");
}

#[tokio::test]
async fn repeated_failed_logins_are_rate_limited() {
    let h = harness();
    let mut last = StatusCode::OK;
    for _ in 0..6 {
        last = try_login(&h, "admin", "wrong-password").await.0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // Even the right password is refused while locked out.
    let (s, _, _) = try_login(&h, "admin", "admin-password-1").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn logout_clears_cookie_and_logout_all_revokes_sessions() {
    let h = harness();
    let (s, _, c) = h.call("POST", "/auth/logout", None, None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(c.as_deref().map(|c| c.trim_end_matches('=')), Some("cp_session"));

    let first = h.login("admin").await;
    let second = h.login("admin").await;
    let (s, _, _) = h.call("POST", "/auth/logout-all", Some(&first), None, true).await;
    assert_eq!(s, StatusCode::OK);
    for cookie in [&first, &second] {
        let (s, _, _) = h.call("GET", "/auth/me", Some(cookie), None, false).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn change_password_flow() {
    let h = harness();
    let old = h.login("admin").await;
    let change = |cur: &str, new: &str| Some(json!({"current_password": cur, "new_password": new}));

    for (body, why) in [
        (change("admin-password-1", "short"), "too short"),
        (change("admin-password-1", "admin-password-1"), "unchanged"),
        (change("wrong-password", "brand-new-pass-2"), "wrong current"),
    ] {
        let (s, _, _) = h.call("POST", "/auth/password", Some(&old), body, true).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{why}");
    }

    let (s, _, fresh) = h
        .call(
            "POST",
            "/auth/password",
            Some(&old),
            change("admin-password-1", "brand-new-pass-2"),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let fresh = fresh.unwrap();
    // The old session is revoked, the returned one works.
    let (s, _, _) = h.call("GET", "/auth/me", Some(&old), None, false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = h.call("GET", "/auth/me", Some(&fresh), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        try_login(&h, "admin", "admin-password-1").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(try_login(&h, "admin", "brand-new-pass-2").await.0, StatusCode::OK);
}

#[tokio::test]
async fn change_email_validates_and_rejects_duplicates() {
    let h = harness();
    let cookie = h.login("admin").await;
    for (email, want) in [
        ("not-an-email", StatusCode::BAD_REQUEST),
        ("m@example.com", StatusCode::CONFLICT),
        ("root@example.org", StatusCode::OK),
    ] {
        let (s, _, _) = h
            .call(
                "POST",
                "/auth/email",
                Some(&cookie),
                Some(json!({"email": email})),
                true,
            )
            .await;
        assert_eq!(s, want, "{email}");
    }
}

#[tokio::test]
async fn admin_user_management_lifecycle() {
    let h = harness();
    let admin = h.login("admin").await;
    let new_user = |name: &str, email: &str, pw: &str, role: &str| json!({"username": name, "email": email, "password": pw, "role": role});

    for (body, want) in [
        (
            new_user("x", "x@example.com", "long-enough-pw", "admin"),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_user("valid", "bad", "long-enough-pw", "admin"),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_user("valid", "v@example.com", "short", "admin"),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_user("valid", "v@example.com", "long-enough-pw", "root"),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_user("manager", "z@example.com", "long-enough-pw", "admin"),
            StatusCode::CONFLICT,
        ),
    ] {
        let (s, _, _) = h.call("POST", "/users", Some(&admin), Some(body.clone()), true).await;
        assert_eq!(s, want, "{body}");
    }

    let (s, created, _) = h
        .call(
            "POST",
            "/users",
            Some(&admin),
            Some(new_user(
                "second.admin",
                "second@example.com",
                "long-enough-pw",
                "admin",
            )),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap();

    let (_, users, _) = h.call("GET", "/users", Some(&admin), None, false).await;
    let list = users.as_array().unwrap();
    assert!(list.iter().any(|u| u["username"] == "second.admin"));
    // Password hashes must never leak through the API.
    assert!(!users.to_string().contains("argon2"));
    let my_id = list.iter().find(|u| u["username"] == "admin").unwrap()["id"]
        .as_i64()
        .unwrap();

    // Reset their password, then they can log in with it.
    let (s, _, _) = h
        .call(
            "POST",
            &format!("/users/{id}/password"),
            Some(&admin),
            Some(json!({"password": "reset-password-9"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        try_login(&h, "second.admin", "reset-password-9").await.0,
        StatusCode::OK
    );

    // With two admins, demotion is allowed.
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("/users/{id}"),
            Some(&admin),
            Some(json!({"email": "second@example.com", "role": "site_manager"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // Admins cannot delete themselves.
    let (s, _, _) = h
        .call("DELETE", &format!("/users/{my_id}"), Some(&admin), None, true)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _, _) = h
        .call("DELETE", &format!("/users/{id}"), Some(&admin), None, true)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = h
        .call("DELETE", &format!("/users/{id}"), Some(&admin), None, true)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn site_managers_cannot_manage_users() {
    let h = harness();
    let cookie = h.login("manager").await;
    let body = json!({"username": "evil", "email": "e@example.com", "password": "long-enough-pw", "role": "admin"});
    let (s, _, _) = h.call("POST", "/users", Some(&cookie), Some(body), true).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = h
        .call(
            "POST",
            "/users/1/password",
            Some(&cookie),
            Some(json!({"password": "takeover-pass-1"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = h.call("DELETE", "/users/1", Some(&cookie), None, true).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_sees_all_sites_and_missing_sites_are_404() {
    let h = harness();
    let cookie = h.login("admin").await;
    let (s, v, _) = h.call("GET", "/sites", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 2);
    let (s, _, _) = h.call("GET", "/sites/999999", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for path in ["/events", "/jobs"] {
        let (s, _, _) = h.call("GET", path, Some(&cookie), None, false).await;
        assert_eq!(s, StatusCode::OK, "{path}");
    }
}

#[test]
fn a_forwarded_address_needs_loopback_and_the_secret() {
    use axum::http::HeaderMap;
    let cf = crate::services::cloudflare::Ranges::built_in();
    let secret = "test-proxy-secret";
    let headers = |s: &str, ip: &str| {
        let mut h = HeaderMap::new();
        h.insert("x-cloudpanel-proxy", s.parse().unwrap());
        h.insert("x-real-ip", ip.parse().unwrap());
        h
    };
    let local = "127.0.0.1".parse().unwrap();
    let client: std::net::IpAddr = "203.0.113.9".parse().unwrap();

    let good = headers(secret, "203.0.113.9");
    assert_eq!(super::forwarded_client(local, &good, secret, &cf), Some(client));
    assert_eq!(
        super::forwarded_client("::1".parse().unwrap(), &good, secret, &cf),
        Some(client)
    );
    // From the outside, even the right secret proves nothing.
    assert_eq!(super::forwarded_client(client, &good, secret, &cf), None);
    // Local processes such as site users' apps don't have the secret.
    assert_eq!(
        super::forwarded_client(local, &headers("guess", "203.0.113.9"), secret, &cf),
        None
    );
    assert_eq!(
        super::forwarded_client(local, &headers("", "203.0.113.9"), "", &cf),
        None
    );
    let mut no_secret = HeaderMap::new();
    no_secret.insert("x-real-ip", "203.0.113.9".parse().unwrap());
    assert_eq!(super::forwarded_client(local, &no_secret, secret, &cf), None);
    // A bad address falls back to the connection's own.
    assert_eq!(
        super::forwarded_client(local, &headers(secret, "not-an-ip"), secret, &cf),
        None
    );
}

#[test]
fn only_cloudflare_can_name_the_visitor_with_its_header() {
    use axum::http::HeaderMap;
    let cf = crate::services::cloudflare::Ranges::built_in();
    let secret = "test-proxy-secret";
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    let from = |peer: &str, header: &str| {
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", header.parse().unwrap());
        super::forwarded_client(ip(peer), &h, secret, &cf)
    };

    // Through a Cloudflare address, over either family, about a visitor on either family.
    assert_eq!(from("173.245.48.1", "203.0.113.9"), Some(ip("203.0.113.9")));
    assert_eq!(from("::ffff:173.245.48.1", "203.0.113.9"), Some(ip("203.0.113.9")));
    assert_eq!(from("2606:4700::1", "2001:db8::5"), Some(ip("2001:db8::5")));
    // Anyone else can send the same header and it means nothing, even from this machine.
    assert_eq!(from("198.51.100.7", "203.0.113.9"), None);
    assert_eq!(from("2001:db8::1", "203.0.113.9"), None);
    assert_eq!(from("127.0.0.1", "203.0.113.9"), None);
    assert_eq!(from("::1", "203.0.113.9"), None);
    // A bad value leaves the connection's own address.
    assert_eq!(from("173.245.48.1", "not-an-ip"), None);
    // Cloudflare passes X-Real-IP along from the visitor, so from there it means nothing.
    let mut real_ip = HeaderMap::new();
    real_ip.insert("x-real-ip", "203.0.113.9".parse().unwrap());
    real_ip.insert("x-cloudpanel-proxy", secret.parse().unwrap());
    assert_eq!(super::forwarded_client(ip("173.245.48.1"), &real_ip, secret, &cf), None);
    // nginx has already dealt with Cloudflare by the time it connects: only X-Real-IP counts,
    // so a forged header sent through it changes nothing.
    real_ip.insert("cf-connecting-ip", "192.0.2.1".parse().unwrap());
    assert_eq!(
        super::forwarded_client(ip("127.0.0.1"), &real_ip, secret, &cf),
        Some(ip("203.0.113.9"))
    );
}

const BANNED: &str = "203.0.113.9";
const EDGE: &str = "173.245.48.1";
const NGINX: [(&str, &str); 1] = [("x-cloudpanel-proxy", "test-proxy-secret")];

#[tokio::test]
async fn a_banned_client_is_refused_however_it_connects() {
    let h = harness();
    let me = "/api/auth/me";

    // Everyone gets the usual answer before the ban.
    assert_eq!(h.from(BANNED, "GET", me, &[]).await, StatusCode::UNAUTHORIZED);
    h.ban(BANNED);

    let cases: [(&str, &[(&str, &str)]); 9] = [
        // Connecting directly to the panel's port.
        (BANNED, &[]),
        // Through nginx on 443, directly and through Cloudflare, where nginx has resolved it.
        ("127.0.0.1", &[NGINX[0], ("x-real-ip", BANNED)]),
        // Cloudflare proxying the panel's port, over either family.
        (EDGE, &[("cf-connecting-ip", BANNED)]),
        ("::ffff:173.245.48.1", &[("cf-connecting-ip", BANNED)]),
        ("2606:4700::1", &[("cf-connecting-ip", BANNED)]),
        // Its own connection, with headers claiming to be someone else.
        (BANNED, &[("cf-connecting-ip", "198.51.100.1")]),
        (BANNED, &[("x-real-ip", "198.51.100.1")]),
        (BANNED, &[("x-real-ip", "198.51.100.1"), NGINX[0]]),
        // A listener on [::] sees its own connection in this form.
        ("::ffff:203.0.113.9", &[]),
    ];
    for (peer, headers) in cases {
        for (method, path) in [
            ("GET", me),
            ("POST", "/api/auth/login"),
            ("GET", "/"),
            ("GET", "/js/app.js"),
        ] {
            assert_eq!(
                h.from(peer, method, path, headers).await,
                StatusCode::FORBIDDEN,
                "{method} {path} from {peer} with {headers:?}"
            );
        }
    }

    // Nobody else is affected.
    let other = [("x-real-ip", "198.51.100.1"), NGINX[0]];
    assert_eq!(h.from("198.51.100.1", "GET", me, &[]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(h.from("127.0.0.1", "GET", me, &other).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.from(EDGE, "GET", me, &[("cf-connecting-ip", "198.51.100.1")]).await,
        StatusCode::UNAUTHORIZED
    );

    // A forged address can't get someone else refused.
    let forged = [("x-real-ip", BANNED)];
    assert_eq!(
        h.from("198.51.100.1", "GET", me, &forged).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.from("127.0.0.1", "GET", me, &forged).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.from("198.51.100.1", "GET", me, &[("cf-connecting-ip", BANNED)]).await,
        StatusCode::UNAUTHORIZED
    );

    h.unban(BANNED);
    assert_eq!(h.from(BANNED, "GET", me, &[]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.from(EDGE, "GET", me, &[("cf-connecting-ip", BANNED)]).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_ban_never_blocks_cloudflare_or_this_machine() {
    let h = harness();
    let me = "/api/auth/me";
    for ip in [EDGE, "127.0.0.1"] {
        h.ban(ip);
    }
    // A request through that edge, whoever it names or if it names nobody, and through nginx.
    assert_eq!(
        h.from(EDGE, "GET", me, &[("cf-connecting-ip", "198.51.100.1")]).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.from(EDGE, "GET", me, &[]).await, StatusCode::UNAUTHORIZED);
    let via_nginx = [("x-real-ip", EDGE), NGINX[0]];
    assert_eq!(
        h.from("127.0.0.1", "GET", me, &via_nginx).await,
        StatusCode::UNAUTHORIZED
    );
    // An SSH tunnel to the panel's port stays a way back in.
    assert_eq!(h.from("127.0.0.1", "GET", me, &[]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(h.from("::1", "GET", me, &[]).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn fail2ban_never_sees_a_failure_from_a_cloudflare_address() {
    let h = harness();
    let login = "/api/auth/login";
    assert_eq!(h.from(EDGE, "POST", login, &[]).await, StatusCode::UNAUTHORIZED);
    let via_nginx = [("x-real-ip", EDGE), NGINX[0]];
    assert_eq!(
        h.from("127.0.0.1", "POST", login, &via_nginx).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(!h.auth_log.exists());

    // The visitor behind it is who fail2ban gets told about.
    let visitor = [("cf-connecting-ip", "198.51.100.1")];
    assert_eq!(h.from(EDGE, "POST", login, &visitor).await, StatusCode::UNAUTHORIZED);
    let log = std::fs::read_to_string(&h.auth_log).unwrap();
    assert!(log.contains("auth failure from 198.51.100.1 "), "{log}");
    assert!(!log.contains(EDGE), "{log}");
}

#[tokio::test]
async fn the_panel_jail_refuses_a_manual_ban_of_a_cloudflare_address() {
    let h = harness();
    let cookie = h.login("admin").await;
    for ip in [EDGE, "2606:4700::1"] {
        let (s, v, _) = h
            .call(
                "POST",
                "/fail2ban/ban",
                Some(&cookie),
                Some(json!({"jail": "cloudpanel", "ip": ip})),
                true,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{ip}");
        assert!(v["error"].as_str().unwrap().contains("Cloudflare"), "{v}");
    }
}

/// Answers every request with this status and body, as GitHub's release API would.
async fn release_api(status: u16, body: &'static str) -> String {
    let answer = move || async move { (StatusCode::from_u16(status).unwrap(), body) };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, Router::new().fallback(answer)).await });
    format!("http://{addr}/releases/latest")
}

const NEWER_RELEASE: &str = r#"{"tag_name":"v999.0.0","html_url":"https://github.com/o/r/releases/tag/v999.0.0","published_at":"2026-11-06T17:58:29Z"}"#;

#[tokio::test]
async fn a_manual_check_finds_a_new_panel_version_and_it_is_remembered() {
    let url = release_api(200, NEWER_RELEASE).await;
    let h = harness_with(|c| c.panel_release_url = url);
    let cookie = h.login("admin").await;

    let (s, before, _) = h.call("GET", "/system/panel-update", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(before["update_available"], false);
    assert!(before["checked_at"].is_null());
    assert_eq!(before["current"], env!("CARGO_PKG_VERSION"));

    let (s, found, _) = h
        .call("POST", "/system/panel-update/check", Some(&cookie), None, true)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(found["update_available"], true);
    assert_eq!(found["latest"], "999.0.0");
    assert_eq!(found["release_url"], "https://github.com/o/r/releases/tag/v999.0.0");
    assert!(found["upgrade_command"].as_str().unwrap().contains("install.sh"));
    assert!(found["error"].is_null());

    let (_, later, _) = h.call("GET", "/system/panel-update", Some(&cookie), None, false).await;
    assert_eq!(later, found);

    let (s, info, _) = h.call("GET", "/system/info", Some(&cookie), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(info["panel_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(info["panel_latest"], "999.0.0");
    assert_eq!(info["panel_update_available"], true);
}

#[tokio::test]
async fn a_panel_with_the_latest_version_is_up_to_date() {
    // The tag of whatever is running, as it would be right after updating.
    let body: &'static str = Box::leak(format!(r#"{{"tag_name":"v{}"}}"#, env!("CARGO_PKG_VERSION")).into_boxed_str());
    let url = release_api(200, body).await;
    let h = harness_with(|c| c.panel_release_url = url);
    let cookie = h.login("admin").await;
    let (_, v, _) = h
        .call("POST", "/system/panel-update/check", Some(&cookie), None, true)
        .await;
    assert_eq!(v["update_available"], false);
    assert_eq!(v["latest"], env!("CARGO_PKG_VERSION"));
    assert!(!v["checked_at"].is_null());
}

#[tokio::test]
async fn no_published_release_is_not_a_failed_check() {
    let url = release_api(404, r#"{"message":"Not Found"}"#).await;
    let h = harness_with(|c| c.panel_release_url = url);
    let cookie = h.login("admin").await;
    let (s, v, _) = h
        .call("POST", "/system/panel-update/check", Some(&cookie), None, true)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["update_available"], false);
    assert!(v["latest"].is_null());
    assert!(v["error"].is_null());
    assert!(!v["checked_at"].is_null());
}

#[tokio::test]
async fn a_failed_panel_update_check_says_so_and_keeps_the_last_answer() {
    let good = release_api(200, NEWER_RELEASE).await;
    let h = harness_with(|c| c.panel_release_url = good);
    let cookie = h.login("admin").await;
    let (_, found, _) = h
        .call("POST", "/system/panel-update/check", Some(&cookie), None, true)
        .await;

    // The same database, now with GitHub limiting this server's requests.
    let limited = release_api(403, r#"{"message":"API rate limit exceeded"}"#).await;
    let conn = h.pool.clone();
    let mut config = Config::from_env();
    config.panel_release_url = limited;
    let state = Arc::new(AppState {
        pool: conn,
        config,
        jwt_secret: b"test-secret-test-secret-test-secret!!".to_vec(),
        proxy_secret: "test-proxy-secret".into(),
        direct_closed: false,
        cloudflare: std::sync::RwLock::new(crate::services::cloudflare::Ranges::built_in()),
        limiter: LoginLimiter::default(),
        metrics: Arc::new(Mutex::new(MetricsCollector::default())),
        tls: Mutex::new(None),
    });
    let v = crate::services::panel_update::check(&state).await.unwrap();
    assert!(v["error"].as_str().unwrap().contains("403"), "{v}");
    assert!(!v["failed_at"].is_null());
    assert_eq!(v["latest"], "999.0.0");
    assert_eq!(v["update_available"], true);
    assert_eq!(v["checked_at"], found["checked_at"]);
}

#[tokio::test]
async fn only_admins_can_see_or_check_the_panel_version() {
    let url = release_api(200, NEWER_RELEASE).await;
    let h = harness_with(|c| c.panel_release_url = url);
    let manager = h.login("manager").await;
    let (s, _, _) = h.call("GET", "/system/panel-update", Some(&manager), None, false).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = h
        .call("POST", "/system/panel-update/check", Some(&manager), None, true)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = h.call("GET", "/system/panel-update", None, None, false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // A check changes stored state, so it needs the CSRF header like any other write.
    let admin = h.login("admin").await;
    let (s, _, _) = h
        .call("POST", "/system/panel-update/check", Some(&admin), None, false)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}
