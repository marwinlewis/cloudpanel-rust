//! Every route, tried by everyone who shouldn't get through.
//!
//! Handlers check who is asking through their extractors, so a new handler without one is public
//! and nothing else would notice. [`every_route_in_the_router_is_classified`] reads the router's
//! source and fails for a route missing from this table, which forces a decision about each one.
//!
//! Denied requests are all that's tried. Letting the allowed ones through would reboot the machine
//! the tests run on, so those are covered by the feature tests.

use super::*;
use crate::auth::{create_jwt, create_mfa_token};
use crate::db::CronInput;
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Guard {
    /// Anyone may call it.
    Public,
    /// Any signed-in user. What they get is scoped, which the idor tests check.
    Session,
    /// A signed-in user assigned to the site in the path.
    Site,
    /// A signed-in user assigned to the site owning the database, backup, cron job or job.
    Owned,
    /// Administrators only.
    Admin,
}
use Guard::*;

/// `:id` means whatever fits the path: a site, or the record the path names.
const ROUTES: &[(&str, &str, Guard)] = &[
    ("POST", "/auth/login", Public),
    ("POST", "/auth/login/mfa", Public),
    ("POST", "/auth/logout", Public),
    ("GET", "/auth/me", Session),
    ("POST", "/auth/logout-all", Session),
    ("POST", "/auth/password", Session),
    ("POST", "/auth/email", Session),
    ("POST", "/auth/2fa/setup", Session),
    ("POST", "/auth/2fa/enable", Session),
    ("POST", "/auth/2fa/disable", Session),
    ("POST", "/auth/2fa/recovery-codes", Session),
    ("GET", "/users", Admin),
    ("POST", "/users", Admin),
    ("PUT", "/users/:id", Admin),
    ("DELETE", "/users/:id", Admin),
    ("POST", "/users/:id/password", Admin),
    ("DELETE", "/users/:id/2fa", Admin),
    ("GET", "/jobs", Admin),
    ("GET", "/jobs/:id", Owned),
    ("GET", "/events", Admin),
    ("GET", "/system/metrics", Admin),
    ("GET", "/sites", Session),
    ("POST", "/sites", Admin),
    ("GET", "/sites/options", Session),
    ("GET", "/sites/:id", Site),
    ("PATCH", "/sites/:id", Site),
    ("DELETE", "/sites/:id", Admin),
    ("POST", "/sites/:id/ssl", Site),
    ("DELETE", "/sites/:id/ssl", Site),
    ("POST", "/sites/:id/ssl/renew", Site),
    ("POST", "/sites/:id/ssl/takeover", Site),
    ("POST", "/sites/:id/state", Site),
    ("GET", "/sites/:id/logs", Site),
    ("GET", "/sites/:id/vhost", Site),
    ("PUT", "/sites/:id/directives", Admin),
    ("PUT", "/sites/:id/basic-auth", Site),
    ("POST", "/sites/:id/basic-auth/users", Site),
    ("DELETE", "/sites/:id/basic-auth/users/:uid", Site),
    ("PUT", "/sites/:id/app", Site),
    ("GET", "/sites/:id/app/env", Site),
    ("GET", "/sites/:id/app/logs", Site),
    ("POST", "/sites/:id/app/install", Site),
    ("POST", "/sites/:id/app/build", Site),
    ("POST", "/sites/:id/app/deploy", Site),
    ("POST", "/sites/:id/app/:action", Site),
    ("GET", "/sites/:id/ssh-users", Site),
    ("POST", "/sites/:id/ssh-users", Site),
    ("PATCH", "/sites/:id/ssh-users/:uid", Site),
    ("DELETE", "/sites/:id/ssh-users/:uid", Site),
    ("POST", "/sites/:id/ssh-users/:uid/password", Site),
    ("POST", "/sites/:id/ssh-users/:uid/keys", Site),
    ("DELETE", "/sites/:id/ssh-users/:uid/keys/:kid", Site),
    ("GET", "/databases/engines", Session),
    ("GET", "/sites/:id/databases", Site),
    ("POST", "/sites/:id/databases", Site),
    ("DELETE", "/databases/:id", Owned),
    ("POST", "/databases/:id/users", Owned),
    ("DELETE", "/databases/:id/users/:username", Owned),
    ("POST", "/databases/:id/users/:username/password", Owned),
    ("GET", "/databases/:id/export", Owned),
    ("POST", "/databases/:id/import", Owned),
    ("GET", "/sites/:id/files", Site),
    ("GET", "/sites/:id/files/content", Site),
    ("PUT", "/sites/:id/files/content", Site),
    ("POST", "/sites/:id/files/op", Site),
    ("GET", "/sites/:id/files/download", Site),
    ("POST", "/sites/:id/files/upload", Site),
    ("GET", "/sites/:id/backups", Site),
    ("POST", "/sites/:id/backups", Site),
    ("PUT", "/sites/:id/backups/policy", Site),
    ("DELETE", "/backups/:id", Owned),
    ("GET", "/backups/:id/download", Owned),
    ("POST", "/backups/:id/restore", Owned),
    ("GET", "/backups/panel", Admin),
    ("POST", "/backups/panel", Admin),
    ("GET", "/backups/remote", Admin),
    ("PUT", "/backups/remote", Admin),
    ("DELETE", "/backups/remote", Admin),
    ("GET", "/services", Admin),
    ("GET", "/services/:name/logs", Admin),
    ("POST", "/services/:name/:action", Admin),
    ("GET", "/system/info", Admin),
    ("GET", "/system/updates", Admin),
    ("POST", "/system/updates/refresh", Admin),
    ("POST", "/system/updates/upgrade", Admin),
    ("GET", "/system/panel-update", Admin),
    ("POST", "/system/panel-update/check", Admin),
    ("POST", "/system/reboot", Admin),
    ("GET", "/docker/status", Admin),
    ("GET", "/docker/containers", Admin),
    ("POST", "/docker/containers", Admin),
    ("GET", "/docker/stats", Admin),
    ("DELETE", "/docker/containers/:id", Admin),
    ("POST", "/docker/containers/:id/start", Admin),
    ("POST", "/docker/containers/:id/stop", Admin),
    ("POST", "/docker/containers/:id/restart", Admin),
    ("GET", "/docker/containers/:id/logs", Admin),
    ("POST", "/docker/containers/:id/proxy-site", Admin),
    ("GET", "/docker/images", Admin),
    ("POST", "/docker/images", Admin),
    ("POST", "/docker/images/prune", Admin),
    ("DELETE", "/docker/images/*id", Admin),
    ("GET", "/docker/stacks", Admin),
    ("GET", "/docker/stacks/:name", Admin),
    ("PUT", "/docker/stacks/:name", Admin),
    ("GET", "/docker/stacks/:name/logs", Admin),
    ("POST", "/docker/stacks/:name/:action", Admin),
    ("GET", "/alerts", Admin),
    ("PUT", "/alerts/rules", Admin),
    ("POST", "/alerts/channels", Admin),
    ("DELETE", "/alerts/channels/:id", Admin),
    ("PATCH", "/alerts/channels/:id", Admin),
    ("POST", "/alerts/channels/:id/test", Admin),
    ("PUT", "/settings/panel-access", Admin),
    ("GET", "/settings/panel-cert", Admin),
    ("POST", "/settings/panel-cert", Admin),
    ("DELETE", "/settings/panel-cert", Admin),
    ("GET", "/firewall/rules", Admin),
    ("POST", "/firewall/rules", Admin),
    ("DELETE", "/firewall/rules/:id", Admin),
    ("GET", "/firewall/status", Admin),
    ("GET", "/fail2ban", Admin),
    ("PUT", "/fail2ban", Admin),
    ("POST", "/fail2ban/ban", Admin),
    ("POST", "/fail2ban/unban", Admin),
    ("GET", "/wireguard", Admin),
    ("PUT", "/wireguard", Admin),
    ("POST", "/wireguard/install", Admin),
    ("POST", "/wireguard/clients", Admin),
    ("PATCH", "/wireguard/clients/:id", Admin),
    ("DELETE", "/wireguard/clients/:id", Admin),
    ("GET", "/wireguard/clients/:id/config", Admin),
    ("GET", "/wireguard/clients/:id/download", Admin),
    ("GET", "/storage", Admin),
    ("POST", "/storage/install", Admin),
    ("PUT", "/storage/endpoint", Admin),
    ("DELETE", "/storage/endpoint", Admin),
    ("POST", "/storage/buckets", Admin),
    ("PUT", "/storage/buckets/:id", Admin),
    ("DELETE", "/storage/buckets/:id", Admin),
    ("PUT", "/storage/buckets/:id/keys/:key_id", Admin),
    ("DELETE", "/storage/buckets/:id/keys/:key_id", Admin),
    ("POST", "/storage/keys", Admin),
    ("PUT", "/storage/keys/:id", Admin),
    ("DELETE", "/storage/keys/:id", Admin),
    ("GET", "/sites/:id/storage", Site),
    ("POST", "/sites/:id/storage/buckets", Site),
    ("DELETE", "/sites/:id/storage/buckets/:bid", Site),
    ("PUT", "/sites/:id/storage/buckets/:bid/keys/:kid", Site),
    ("DELETE", "/sites/:id/storage/buckets/:bid/keys/:kid", Site),
    ("POST", "/sites/:id/storage/keys", Site),
    ("DELETE", "/sites/:id/storage/keys/:kid", Site),
    ("GET", "/cron/jobs", Session),
    ("POST", "/cron/jobs", Session),
    ("PUT", "/cron/jobs/:id", Owned),
    ("DELETE", "/cron/jobs/:id", Owned),
    ("POST", "/cron/jobs/:id/run", Owned),
    ("GET", "/cron/jobs/:id/runs", Owned),
];

/// The routes the router really has, read from its source. `.route("/path", get(a).post(b))`,
/// so each call is the path followed by method names up to the call's closing parenthesis.
fn routes_in_source() -> BTreeSet<(String, String)> {
    let src = include_str!("../mod.rs");
    let mut out = BTreeSet::new();
    for chunk in src.split(".route(").skip(1) {
        let start = chunk.find('"').unwrap() + 1;
        let end = start + chunk[start..].find('"').unwrap();
        let path = &chunk[start..end];
        // Up to the parenthesis that closes `.route(`.
        let mut depth = 1;
        let mut stop = chunk.len();
        for (i, c) in chunk.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        stop = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let args = &chunk[end..stop];
        for (word, method) in [
            ("get(", "GET"),
            ("post(", "POST"),
            ("put(", "PUT"),
            ("patch(", "PATCH"),
            ("delete(", "DELETE"),
        ] {
            let found = args.match_indices(word).any(|(i, _)| {
                // `get(` itself, not the end of a longer name like `budget(`.
                !args[..i].ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == ':')
            });
            if found {
                out.insert((method.to_string(), path.to_string()));
            }
        }
    }
    out
}

#[test]
fn every_route_in_the_router_is_classified() {
    let table: BTreeSet<(String, String)> = ROUTES.iter().map(|(m, p, _)| (m.to_string(), p.to_string())).collect();
    let real = routes_in_source();
    assert!(real.len() > 100, "the router's source could not be read: {real:?}");
    let missing: Vec<_> = real.difference(&table).collect();
    let stale: Vec<_> = table.difference(&real).collect();
    assert!(
        missing.is_empty(),
        "routes with no security classification (add them to ROUTES): {missing:?}"
    );
    assert!(stale.is_empty(), "routes in ROUTES that no longer exist: {stale:?}");
}

/// Records on `other.example.com`, which `manager` has no access to.
struct Others {
    site: i64,
    user: i64,
    database: i64,
    backup: i64,
    cron: i64,
    job: i64,
}

fn seed(h: &Harness) -> Others {
    let site = site_id(h, "other.example.com");
    let conn = h.pool.get().unwrap();
    let database = db::create_database(&conn, site, "sqlite", "otherdb").unwrap();
    db::add_database_user(&conn, database, "otheruser").unwrap();
    let backup = db::create_backup(&conn, Some(site), "other.example.com", "/nonexistent/backup.tar.gz").unwrap();
    let cron = db::create_cron_job(
        &conn,
        &CronInput {
            site_id: Some(site),
            name: None,
            schedule: "* * * * *",
            command: "true",
            user: "nobody",
            is_active: false,
        },
    )
    .unwrap();
    let admin = db::find_user_by_username(&conn, "admin").unwrap().unwrap().id;
    let job = db::create_job(&conn, "test", None, Some(admin)).unwrap();
    Others {
        site,
        user: admin,
        database,
        backup,
        cron,
        job,
    }
}

/// A path template with its placeholders filled in with `others`' records.
fn concrete(path: &str, o: &Others) -> String {
    let id = if path.starts_with("/databases/") {
        o.database
    } else if path.starts_with("/backups/") {
        o.backup
    } else if path.starts_with("/cron/") {
        o.cron
    } else if path.starts_with("/jobs/") {
        o.job
    } else if path.starts_with("/users/") {
        o.user
    } else {
        o.site
    };
    path.replace("/:id", &format!("/{id}"))
        .replace("/*id", "/image")
        .replace(":uid", "1")
        .replace(":kid", "1")
        .replace(":bid", "1")
        .replace(":key_id", "1")
        .replace(":username", "otheruser")
        .replace(":name", "nginx")
        .replace(":action", "restart")
}

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test";

/// Enough fields to get past every handler's body parsing, so that what stops the request is the
/// access check after it and not a 422 that proves nothing.
fn plausible_body() -> Value {
    json!({
        "path": "x.txt", "to": "y.txt", "content": "x", "op": "mkdir", "names": [], "mode": "0644",
        "engine": "sqlite", "name": "somename", "username": "someuser", "password": "Some-Password-123",
        "new_password": "Some-Password-123", "current_password": "Some-Password-123",
        "frequency": "daily", "hour": 1, "retention": 1, "retention_days": 1, "keep": 1, "remote": false,
        "enabled": true, "active": true, "is_active": true, "state": "active",
        "schedule": "* * * * *", "command": "true", "site_id": null,
        "email": "x@example.com", "role": "site_manager", "code": "000000", "mfa_token": "x",
        "domain": "new.example.com", "site_type": "static", "sftp_only": true,
        "key": KEY, "public_key": KEY, "directives": "", "custom_directives": "", "allow": [], "users": [],
        "force": false, "auto_renew": true, "open": true,
    })
}

async fn attempt(h: &Harness, method: &str, path: &str, token: Option<&str>) -> Response {
    let mut req = api_untyped(method, path);
    if let Some(t) = token {
        req = req.header(header::COOKIE, format!("cp_session={t}"));
    }
    let multipart = path.ends_with("/import") || path.ends_with("/upload");
    if multipart {
        req = req.header(header::CONTENT_TYPE, "multipart/form-data; boundary=x");
        return send(h, "127.0.0.1", req, Body::from("--x--\r\n")).await;
    }
    let req = req.header(header::CONTENT_TYPE, "application/json");
    let body = if method == "GET" {
        Body::empty()
    } else {
        json_body(&plausible_body())
    };
    send(h, "127.0.0.1", req, body).await
}

fn claims(uid: i64, name: &str, ver: i64, exp_from_now: i64, purpose: Option<&str>) -> Claims {
    let now = chrono::Utc::now().timestamp();
    Claims {
        sub: name.into(),
        uid,
        ver,
        iat: (now - 7200) as usize,
        exp: (now + exp_from_now) as usize,
        purpose: purpose.map(str::to_string),
        jti: String::new(),
    }
}

#[tokio::test]
async fn nobody_without_a_valid_session_gets_past_any_guarded_route() {
    let h = super::super::tests::harness();
    let others = seed(&h);
    let admin = user_id(&h, "admin");

    let wrong_secret = sign(
        &claims(admin, "admin", 0, 3600, None),
        b"not-the-secret-not-the-secret-not-the",
    );
    let expired = sign(&claims(admin, "admin", 0, -3600, None), SECRET);
    let stale = sign(&claims(admin, "admin", 7, 3600, None), SECRET);
    let no_such_user = sign(&claims(987_654, "ghost", 0, 3600, None), SECRET);
    let mfa_pending = create_mfa_token(admin, "admin", 0, SECRET).unwrap();
    let other_purpose = sign(&claims(admin, "admin", 0, 3600, Some("anything")), SECRET);
    // Not the last character: it carries two padding bits, so changing it can leave the signature
    // the same.
    let tampered = {
        let mut t: Vec<char> = create_jwt(admin, "admin", 0, SECRET).unwrap().chars().collect();
        let i = t.len() - 10;
        t[i] = if t[i] == 'A' { 'B' } else { 'A' };
        t.into_iter().collect::<String>()
    };
    let b64 = {
        use base64::Engine;
        |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    };
    let unsigned = {
        let head = b64(r#"{"alg":"none","typ":"JWT"}"#);
        let body = b64(&serde_json::to_string(&claims(admin, "admin", 0, 3600, None)).unwrap());
        format!("{head}.{body}.")
    };
    // A real manager's token, with its claims edited to the admin's and the signature left as it was.
    let promoted = {
        let mgr = user_id(&h, "manager");
        let real = create_jwt(mgr, "manager", 0, SECRET).unwrap();
        let parts: Vec<&str> = real.split('.').collect();
        let body = b64(&serde_json::to_string(&claims(admin, "admin", 0, 3600, None)).unwrap());
        format!("{}.{body}.{}", parts[0], parts[2])
    };

    let tokens: [(&str, Option<&str>); 10] = [
        ("anonymous", None),
        ("garbage", Some("garbage")),
        ("signed with another secret", Some(&wrong_secret)),
        ("expired", Some(&expired)),
        ("old token version", Some(&stale)),
        ("user that doesn't exist", Some(&no_such_user)),
        ("password step only", Some(&mfa_pending)),
        ("limited-purpose token", Some(&other_purpose)),
        ("bad signature", Some(&tampered)),
        ("edited claims", Some(&promoted)),
    ];
    // Without this, a broken harness would pass as "everything is refused".
    let valid = create_jwt(admin, "admin", 0, SECRET).unwrap();
    assert_eq!(
        attempt(&h, "GET", "/auth/me", Some(&valid)).await.status,
        StatusCode::OK
    );

    let mut leaks = Vec::new();
    for (method, path, guard) in ROUTES {
        if *guard == Public {
            continue;
        }
        let url = concrete(path, &others);
        for (who, token) in tokens.iter().chain([&("alg none", Some(unsigned.as_str()))]) {
            let got = attempt(&h, method, &url, *token).await.status;
            if got != StatusCode::UNAUTHORIZED {
                leaks.push(format!("{method} {path} as {who}: {got}"));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "reached a route without a valid session:\n{}",
        leaks.join("\n")
    );
}

#[tokio::test]
async fn a_site_manager_is_refused_everything_outside_their_sites() {
    let h = super::super::tests::harness();
    let others = seed(&h);
    let cookie = h.login("manager").await;
    let token = cookie.strip_prefix("cp_session=").unwrap().to_string();

    let mut leaks = Vec::new();
    for (method, path, guard) in ROUTES {
        let want = match guard {
            Public | Session => continue,
            Admin => StatusCode::FORBIDDEN,
            // Other people's records look missing, so they can't be probed for.
            Site | Owned => StatusCode::NOT_FOUND,
        };
        let got = attempt(&h, method, &concrete(path, &others), Some(&token)).await.status;
        if got != want {
            leaks.push(format!("{method} {path}: {got}, expected {want}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "a site manager got further than they should:\n{}",
        leaks.join("\n")
    );
}

/// Being denied mustn't have done the thing anyway.
#[tokio::test]
async fn refused_requests_change_nothing() {
    let h = super::super::tests::harness();
    let others = seed(&h);
    let cookie = h.login("manager").await;
    let token = cookie.strip_prefix("cp_session=").unwrap().to_string();
    let snapshot = |h: &Harness| {
        let conn = h.pool.get().unwrap();
        (
            db::list_sites(&conn).unwrap().len(),
            db::list_cron_jobs(&conn).unwrap().len(),
            db::list_databases(&conn, None).unwrap().len(),
            db::list_backups(&conn, None).unwrap().len(),
            db::list_users(&conn).unwrap().len(),
        )
    };
    let before = snapshot(&h);
    for (method, path, guard) in ROUTES {
        if matches!(guard, Site | Owned | Admin) && *method != "GET" {
            attempt(&h, method, &concrete(path, &others), Some(&token)).await;
            attempt(&h, method, &concrete(path, &others), None).await;
        }
    }
    assert_eq!(snapshot(&h), before);
}
