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

struct Harness {
    app: Router,
    _dir: tempfile::TempDir,
    pool: db::DbPool,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::from_env();
    let d = dir.path();
    config.data_dir = d.join("data");
    config.db_path = d.join("data/cp.db");
    config.etc_dir = d.join("etc");
    config.log_dir = d.join("log");
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
                    home_dir: None,
                    app_command: None,
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
        limiter: LoginLimiter::default(),
        metrics: Arc::new(Mutex::new(MetricsCollector::default())),
        tls: Mutex::new(None),
    });
    Harness {
        app: super::create_api_router(state),
        _dir: dir,
        pool,
    }
}

impl Harness {
    async fn call(
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

    async fn login(&self, user: &str) -> String {
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
