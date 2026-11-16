//! GitHub Actions runners: who sees which, stored tokens, and the deploy hook.

use crate::api::tests::{harness, Harness};
use crate::db::{self, NewRunner};
use crate::services::runners;
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;

fn site(h: &Harness, domain: &str) -> i64 {
    let conn = h.pool.get().unwrap();
    db::list_sites(&conn)
        .unwrap()
        .into_iter()
        .find(|s| s.domain == domain)
        .unwrap()
        .id
}

/// A runner on `domain`'s site, with a deploy token. Returns its id and token.
fn runner_on(h: &Harness, domain: Option<&str>, name: &str) -> (i64, String) {
    let site_id = domain.map(|d| site(h, d));
    let (token, hash) = runners::new_deploy_token();
    let conn = h.pool.get().unwrap();
    let id = db::create_runner(
        &conn,
        &NewRunner {
            site_id,
            name,
            github_url: "https://github.com/acme/app",
            labels: "",
            runner_group: "",
            system_user: "cloudpanel",
            dir: &format!("/home/cloudpanel/actions-runner/{name}"),
            credential_id: None,
            deploy_token_hash: Some(&hash),
            adopted: false,
        },
    )
    .unwrap();
    (id, token)
}

#[tokio::test]
async fn managers_only_see_runners_of_their_sites() {
    let h = harness();
    runner_on(&h, Some("mine.example.com"), "mine-1");
    runner_on(&h, Some("other.example.com"), "other-1");
    runner_on(&h, None, "adopted-1");

    let admin = h.login("admin").await;
    let (s, v, _) = h.call("GET", "/runners", Some(&admin), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["runners"].as_array().unwrap().len(), 3);
    assert_eq!(v["is_admin"], true);

    let mgr = h.login("manager").await;
    let (s, v, _) = h.call("GET", "/runners", Some(&mgr), None, false).await;
    assert_eq!(s, StatusCode::OK);
    let names: Vec<&str> = v["runners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["mine-1"]);
    assert!(v["credentials"].as_array().unwrap().is_empty());
    assert!(!v.to_string().contains("deploy_token_hash"));
}

#[tokio::test]
async fn creating_a_runner_is_checked_before_anything_runs() {
    let h = harness();
    let mine = site(&h, "mine.example.com");
    let other = site(&h, "other.example.com");
    let mgr = h.login("manager").await;
    let body = |site_id: i64, extra: Value| {
        let mut b =
            json!({"site_id": site_id, "url": "https://github.com/acme/app", "token": "AABBCCDDEEFF0011223344"});
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    let cases = [
        (body(other, json!({})), StatusCode::NOT_FOUND),
        (
            body(mine, json!({"url": "https://gitlab.com/acme/app"})),
            StatusCode::BAD_REQUEST,
        ),
        (body(mine, json!({"token": null})), StatusCode::BAD_REQUEST),
        (body(mine, json!({"token": "bad token!"})), StatusCode::BAD_REQUEST),
        (body(mine, json!({"labels": "ok,not ok"})), StatusCode::BAD_REQUEST),
        (body(mine, json!({"name": "../escape"})), StatusCode::BAD_REQUEST),
        // Stored tokens are the administrators'.
        (
            body(mine, json!({"token": null, "credential_id": 1})),
            StatusCode::FORBIDDEN,
        ),
        // The test sites run as `cloudpanel` with no home of their own.
        (body(mine, json!({})), StatusCode::BAD_REQUEST),
    ];
    for (b, want) in cases {
        let (s, v, _) = h.call("POST", "/runners", Some(&mgr), Some(b.clone()), true).await;
        assert_eq!(s, want, "{b} -> {v}");
    }
}

#[tokio::test]
async fn stored_github_tokens_are_encrypted_and_never_shown() {
    let h = harness();
    let admin = h.login("admin").await;
    let secret = "github_pat_11AAAAAAA0123456789abcdefghijklmnop";
    let (s, _, _) = h
        .call(
            "POST",
            "/github-credentials",
            Some(&admin),
            Some(json!({"name": "acme", "token": secret})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, _) = h
        .call(
            "POST",
            "/github-credentials",
            Some(&admin),
            Some(json!({"name": "ACME", "token": secret})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (_, list, _) = h.call("GET", "/github-credentials", Some(&admin), None, false).await;
    let (_, overview, _) = h.call("GET", "/runners", Some(&admin), None, false).await;
    assert_eq!(list["credentials"][0]["name"], "acme");
    for v in [&list, &overview] {
        assert!(!v.to_string().contains(secret), "{v}");
        assert!(!v.to_string().contains("token_sealed"), "{v}");
    }
    let conn = h.pool.get().unwrap();
    let stored = &db::list_github_credentials(&conn).unwrap()[0].token_sealed;
    assert!(stored.starts_with("v1:") && !stored.contains(secret));

    let mgr = h.login("manager").await;
    let (s, _, _) = h.call("GET", "/github-credentials", Some(&mgr), None, false).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

async fn hook(h: &Harness, auth: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/runner-hook/deploy")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, format!("Bearer {a}"));
    }
    let mut req = req.body(Body::from(body.to_string())).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo::<SocketAddr>("127.0.0.1:5555".parse().unwrap()));
    let res = h.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_deploy_hook_only_deploys_the_runners_own_site() {
    let h = harness();
    {
        let conn = h.pool.get().unwrap();
        conn.execute(
            "UPDATE sites SET home_dir = '/home/cloudpanel' WHERE domain = 'mine.example.com'",
            [],
        )
        .unwrap();
    }
    let (_, token) = runner_on(&h, Some("mine.example.com"), "mine-1");
    let (_, unlinked) = runner_on(&h, None, "adopted-1");
    let admin = h.login("admin").await;
    let session = admin.strip_prefix("cp_session=").unwrap();

    let restart = json!({"action": "restart"});
    // Without a bearer token the CSRF guard stops it first.
    assert_eq!(hook(&h, None, restart.clone()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        hook(&h, Some("cpr_nope"), restart.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hook(&h, Some(&unlinked), restart.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    // A panel session isn't a deploy token.
    assert_eq!(
        hook(&h, Some(session), restart.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hook(&h, Some(&token), json!({"action": "rm -rf"})).await.0,
        StatusCode::BAD_REQUEST
    );

    let (s, v) = hook(&h, Some(&token), restart.clone()).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let job = v["job_id"].as_i64().unwrap();
    {
        let conn = h.pool.get().unwrap();
        let j = db::find_job(&conn, job).unwrap().unwrap();
        assert_eq!(j.target.as_deref(), Some("mine.example.com"));
        assert_eq!(j.kind, "runner.restart");
    }
    // Once every few seconds.
    assert_eq!(hook(&h, Some(&token), restart).await.0, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn rotating_the_deploy_token_retires_the_old_one() {
    let h = harness();
    let (id, old) = runner_on(&h, Some("mine.example.com"), "mine-1");
    let mgr = h.login("manager").await;
    let (s, v, _) = h
        .call("POST", &format!("/runners/{id}/deploy-token"), Some(&mgr), None, true)
        .await;
    // Writing the unit fails without a real runner directory; the token is replaced first.
    assert!(
        s == StatusCode::NO_CONTENT || s == StatusCode::UNPROCESSABLE_ENTITY,
        "{s} {v}"
    );
    assert_eq!(hook(&h, Some(&old), json!({})).await.0, StatusCode::UNAUTHORIZED);
}

/// GitHub's runner API, answering for `acme/app` to one token.
async fn fake_github() -> String {
    fn ok(h: &HeaderMap) -> bool {
        h.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer good-pat")
    }
    let app = Router::new()
        .route(
            "/repos/acme/app/actions/runners/registration-token",
            post(|h: HeaderMap| async move {
                if ok(&h) {
                    (StatusCode::CREATED, Json(json!({"token": "REGTOKEN123", "expires_at": "2026-11-16T12:00:00Z"})))
                } else {
                    (StatusCode::UNAUTHORIZED, Json(json!({"message": "Bad credentials"})))
                }
            }),
        )
        .route(
            "/orgs/acme/actions/runners/remove-token",
            post(|h: HeaderMap| async move {
                if ok(&h) {
                    (StatusCode::CREATED, Json(json!({"token": "REMOVE456"})))
                } else {
                    (StatusCode::FORBIDDEN, Json(json!({})))
                }
            }),
        )
        .route(
            "/repos/acme/app/actions/runners",
            get(|| async {
                Json(json!({"total_count": 1, "runners": [{"id": 1, "name": "mine-1", "os": "Linux", "status": "online", "busy": true, "labels": []}]}))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

#[tokio::test]
async fn tokens_come_from_githubs_runner_api() {
    let api = fake_github().await;
    assert_eq!(
        runners::registration_token(&api, "good-pat", "https://github.com/acme/app")
            .await
            .unwrap(),
        "REGTOKEN123"
    );
    assert_eq!(
        runners::removal_token(&api, "good-pat", "https://github.com/acme")
            .await
            .unwrap(),
        "REMOVE456"
    );
    let e = runners::registration_token(&api, "bad", "https://github.com/acme/app")
        .await
        .unwrap_err();
    assert!(e.contains("401"), "{e}");
    let list = runners::list_remote(&api, "good-pat", "https://github.com/acme/app")
        .await
        .unwrap();
    assert_eq!(list[0].name, "mine-1");
    assert_eq!(list[0].status, "online");
    assert!(list[0].busy);
}
