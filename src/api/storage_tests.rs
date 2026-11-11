//! Object storage API against a stand-in for Garage's admin API.

use crate::api::tests::{harness_with, Harness};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const TOKEN: &str = "test-admin-token";

/// A bucket: alias, object count, quotas, and grants by access key.
type FakeBucket = (String, u64, Value, HashMap<String, Value>);

#[derive(Default)]
struct Fake {
    buckets: HashMap<String, FakeBucket>,
    /// Access key ID to name.
    keys: HashMap<String, String>,
    next: u32,
}
type Shared = Arc<Mutex<Fake>>;
type Q = Query<HashMap<String, String>>;
type R = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn authed(h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    if h.get("authorization").and_then(|v| v.to_str().ok()) == Some(format!("Bearer {TOKEN}").as_str()) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"code": "Forbidden", "message": "bad token"})),
        ))
    }
}

fn info(f: &Fake, id: &str) -> Value {
    let (alias, objects, quotas, grants) = &f.buckets[id];
    json!({
        "id": id, "created": "2026-01-01T00:00:00Z", "globalAliases": [alias], "websiteAccess": false,
        "objects": objects, "bytes": objects * 100, "unfinishedUploads": 0, "unfinishedMultipartUploads": 0,
        "unfinishedMultipartUploadParts": 0, "unfinishedMultipartUploadBytes": 0, "quotas": quotas,
        "keys": grants.iter().map(|(k, p)| json!({
            "accessKeyId": k, "name": f.keys.get(k).cloned().unwrap_or_default(),
            "permissions": p, "bucketLocalAliases": []
        })).collect::<Vec<_>>(),
    })
}

fn change_grant(f: &mut Fake, b: &Value, to: bool) {
    let bucket = f.buckets.get_mut(b["bucketId"].as_str().unwrap()).unwrap();
    let p = bucket
        .3
        .entry(b["accessKeyId"].as_str().unwrap().to_string())
        .or_insert(json!({"read": false, "write": false, "owner": false}));
    for k in ["read", "write", "owner"] {
        if b["permissions"][k] == true {
            p[k] = json!(to);
        }
    }
}

async fn health(h: HeaderMap) -> R {
    authed(&h)?;
    Ok(Json(
        json!({"status": "healthy", "knownNodes": 1, "connectedNodes": 1, "storageNodes": 1,
        "storageNodesUp": 1, "partitions": 256, "partitionsQuorum": 256, "partitionsAllOk": 256}),
    ))
}

async fn statistics(h: HeaderMap) -> R {
    authed(&h)?;
    Ok(Json(json!({"freeform": "", "dataAvail": 1_000_000})))
}

async fn status(h: HeaderMap) -> R {
    authed(&h)?;
    Ok(Json(json!({"layoutVersion": 1, "nodes": [
        {"id": "n1", "isUp": true, "draining": false, "garageVersion": "v2.5.0"}
    ]})))
}

async fn list_buckets(State(s): State<Shared>, h: HeaderMap) -> R {
    authed(&h)?;
    let f = s.lock().unwrap();
    let list: Vec<Value> = f
        .buckets
        .iter()
        .map(|(id, b)| json!({"id": id, "created": "x", "globalAliases": [b.0], "localAliases": []}))
        .collect();
    Ok(Json(json!(list)))
}

async fn bucket_info(State(s): State<Shared>, h: HeaderMap, Query(q): Q) -> R {
    authed(&h)?;
    let f = s.lock().unwrap();
    let id = q.get("id").cloned().unwrap_or_default();
    if !f.buckets.contains_key(&id) {
        return Err((StatusCode::NOT_FOUND, Json(json!({"message": "no such bucket"}))));
    }
    Ok(Json(info(&f, &id)))
}

async fn create_bucket(State(s): State<Shared>, h: HeaderMap, Json(b): Json<Value>) -> R {
    authed(&h)?;
    let mut f = s.lock().unwrap();
    let alias = b["globalAlias"].as_str().unwrap().to_string();
    if f.buckets.values().any(|x| x.0 == alias) {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"message": format!("Bucket {alias} already exists")})),
        ));
    }
    f.next += 1;
    let id = format!("b{:063}", f.next);
    f.buckets.insert(
        id.clone(),
        (alias, 0, json!({"maxSize": null, "maxObjects": null}), HashMap::new()),
    );
    Ok(Json(info(&f, &id)))
}

async fn update_bucket(State(s): State<Shared>, h: HeaderMap, Query(q): Q, Json(b): Json<Value>) -> R {
    authed(&h)?;
    let mut f = s.lock().unwrap();
    let id = q["id"].clone();
    f.buckets.get_mut(&id).unwrap().2 = b["quotas"].clone();
    Ok(Json(info(&f, &id)))
}

async fn delete_bucket(State(s): State<Shared>, h: HeaderMap, Query(q): Q) -> R {
    authed(&h)?;
    let mut f = s.lock().unwrap();
    if f.buckets[&q["id"]].1 > 0 {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"message": "Bucket not empty"}))));
    }
    f.buckets.remove(&q["id"]);
    Ok(Json(Value::Null))
}

async fn list_keys(State(s): State<Shared>, h: HeaderMap) -> R {
    authed(&h)?;
    let f = s.lock().unwrap();
    let list: Vec<Value> = f
        .keys
        .iter()
        .map(|(id, n)| json!({"id": id, "name": n, "expired": false}))
        .collect();
    Ok(Json(json!(list)))
}

async fn create_key(State(s): State<Shared>, h: HeaderMap, Json(b): Json<Value>) -> R {
    authed(&h)?;
    let mut f = s.lock().unwrap();
    assert_eq!(b["deny"]["createBucket"], true, "keys never get to create buckets");
    f.next += 1;
    let id = format!("GK{:024x}", f.next);
    f.keys.insert(id.clone(), b["name"].as_str().unwrap().to_string());
    Ok(Json(
        json!({"accessKeyId": id, "name": b["name"], "expired": false, "secretAccessKey": "s3cr3t",
        "permissions": {"createBucket": false}, "buckets": []}),
    ))
}

async fn delete_key(State(s): State<Shared>, h: HeaderMap, Query(q): Q) -> R {
    authed(&h)?;
    let mut f = s.lock().unwrap();
    let id = q["id"].clone();
    f.keys.remove(&id);
    for b in f.buckets.values_mut() {
        b.3.remove(&id);
    }
    Ok(Json(Value::Null))
}

async fn allow(State(s): State<Shared>, h: HeaderMap, Json(b): Json<Value>) -> R {
    authed(&h)?;
    change_grant(&mut s.lock().unwrap(), &b, true);
    Ok(Json(json!({})))
}

async fn deny(State(s): State<Shared>, h: HeaderMap, Json(b): Json<Value>) -> R {
    authed(&h)?;
    change_grant(&mut s.lock().unwrap(), &b, false);
    Ok(Json(json!({})))
}

fn fake_garage(state: Shared) -> Router {
    Router::new()
        .route("/v2/GetClusterHealth", get(health))
        .route("/v2/GetClusterStatistics", get(statistics))
        .route("/v2/GetClusterStatus", get(status))
        .route("/v2/ListBuckets", get(list_buckets))
        .route("/v2/GetBucketInfo", get(bucket_info))
        .route("/v2/CreateBucket", post(create_bucket))
        .route("/v2/UpdateBucket", post(update_bucket))
        .route("/v2/DeleteBucket", post(delete_bucket))
        .route("/v2/ListKeys", get(list_keys))
        .route("/v2/CreateKey", post(create_key))
        .route("/v2/DeleteKey", post(delete_key))
        .route("/v2/AllowBucketKey", post(allow))
        .route("/v2/DenyBucketKey", post(deny))
        .with_state(state)
}

async fn setup() -> (Harness, Shared, tempfile::TempDir) {
    let fake: Shared = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = fake_garage(fake.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("admin.token"), format!("{TOKEN}\n")).unwrap();
    let garage_dir = dir.path().to_path_buf();
    let h = harness_with(move |c| {
        c.garage_dir = garage_dir;
        c.garage_admin_url = format!("http://{addr}");
    });
    (h, fake, dir)
}

fn site(h: &Harness, domain: &str) -> i64 {
    let conn = h.pool.get().unwrap();
    crate::db::list_sites(&conn)
        .unwrap()
        .into_iter()
        .find(|s| s.domain == domain)
        .unwrap()
        .id
}

fn names(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn admins_and_site_managers_manage_buckets_keys_and_grants() {
    let (h, fake, _dir) = setup().await;
    let admin = h.login("admin").await;
    let mgr = h.login("manager").await;
    let mine = site(&h, "mine.example.com");
    let other = site(&h, "other.example.com");

    let (s, overview, _) = h.call("GET", "/storage", Some(&admin), None, false).await;
    assert_eq!(s, StatusCode::OK, "{overview}");
    assert_eq!(overview["running"], true);
    assert_eq!(overview["version"], "v2.5.0");
    assert_eq!(overview["endpoint"]["local"], "http://127.0.0.1:3900");
    assert_eq!(overview["endpoint"]["region"], "us-east-1");

    // A manager makes a bucket and a key for their site; the secret is shown once.
    let buckets = format!("/sites/{mine}/storage/buckets");
    let (s, bucket, _) = h
        .call("POST", &buckets, Some(&mgr), Some(json!({"name": "mine-media"})), true)
        .await;
    assert_eq!(s, StatusCode::CREATED, "{bucket}");
    assert_eq!(bucket["site_id"], mine);
    let (s, bad, _) = h
        .call("POST", &buckets, Some(&mgr), Some(json!({"name": "Bad_Name"})), true)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    let (s, key, _) = h
        .call(
            "POST",
            &format!("/sites/{mine}/storage/keys"),
            Some(&mgr),
            Some(json!({"name": "app"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{key}");
    assert_eq!(key["secret_access_key"], "s3cr3t");
    assert!(key["access_key_id"].as_str().unwrap().starts_with("GK"));
    let (bid, kid) = (bucket["id"].as_i64().unwrap(), key["id"].as_i64().unwrap());

    let grant = format!("/sites/{mine}/storage/buckets/{bid}/keys/{kid}");
    let (s, _, _) = h
        .call(
            "PUT",
            &grant,
            Some(&mgr),
            Some(json!({"read": true, "write": true})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = h
        .call(
            "PUT",
            &grant,
            Some(&mgr),
            Some(json!({"read": true, "owner": true})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "owner rights stay with admins");

    let site_view = format!("/sites/{mine}/storage");
    let (s, view, _) = h.call("GET", &site_view, Some(&mgr), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(names(&view["buckets"]), ["mine-media"]);
    assert_eq!(
        view["buckets"][0]["grants"][0]["permissions"],
        json!({"read": true, "write": true, "owner": false})
    );
    assert!(
        !view.to_string().contains("s3cr3t"),
        "secrets are never stored or listed"
    );

    // Lowering a grant takes away what isn't asked for.
    let (s, _, _) = h
        .call("PUT", &grant, Some(&mgr), Some(json!({"read": true})), true)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, view, _) = h.call("GET", &site_view, Some(&mgr), None, false).await;
    assert_eq!(
        view["buckets"][0]["grants"][0]["permissions"],
        json!({"read": true, "write": false, "owner": false})
    );

    // An admin's bucket on another site, an unlinked key, and a bucket made outside the panel.
    let (s, theirs, _) = h
        .call(
            "POST",
            "/storage/buckets",
            Some(&admin),
            Some(json!({"name": "other-media", "site_id": other, "max_size_mb": 10})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{theirs}");
    let tid = theirs["id"].as_i64().unwrap();
    {
        let f = fake.lock().unwrap();
        let q = &f.buckets.values().find(|b| b.0 == "other-media").unwrap().2;
        assert_eq!(q["maxSize"], 10 * 1024 * 1024);
    }
    let (s, loose, _) = h
        .call(
            "POST",
            "/storage/keys",
            Some(&admin),
            Some(json!({"name": "ops"})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let lid = loose["id"].as_i64().unwrap();
    fake.lock()
        .unwrap()
        .buckets
        .insert("z".repeat(64), ("made-by-cli".into(), 0, json!({}), HashMap::new()));

    // The manager can't reach any of them, even through their own site's paths.
    for (m, path) in [
        ("DELETE", format!("/sites/{mine}/storage/buckets/{tid}")),
        ("PUT", format!("/sites/{mine}/storage/buckets/{tid}/keys/{kid}")),
        ("PUT", format!("/sites/{mine}/storage/buckets/{bid}/keys/{lid}")),
        ("DELETE", format!("/sites/{mine}/storage/keys/{lid}")),
        ("GET", format!("/sites/{other}/storage")),
    ] {
        let body = (m != "GET").then(|| json!({"read": true}));
        let (s, _, _) = h.call(m, &path, Some(&mgr), body, m != "GET").await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m} {path}");
    }
    let (_, view, _) = h.call("GET", &site_view, Some(&mgr), None, false).await;
    assert_eq!(names(&view["buckets"]), ["mine-media"]);

    // A site's key only gets access to that site's buckets, even when an admin grants it.
    let (s, msg, _) = h
        .call(
            "PUT",
            &format!("/storage/buckets/{tid}/keys/{kid}"),
            Some(&admin),
            Some(json!({"read": true})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{msg}");

    // The admin sees everything, including the adopted bucket. The admin's grant on the site's
    // bucket is counted for the manager, not shown.
    let (s, _, _) = h
        .call(
            "PUT",
            &format!("/storage/buckets/{bid}/keys/{lid}"),
            Some(&admin),
            Some(json!({"read": true})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, overview, _) = h.call("GET", "/storage", Some(&admin), None, false).await;
    assert_eq!(
        names(&overview["buckets"]),
        ["made-by-cli", "mine-media", "other-media"]
    );
    assert_eq!(overview["keys"].as_array().unwrap().len(), 2);
    let (_, view, _) = h.call("GET", &site_view, Some(&mgr), None, false).await;
    assert_eq!(view["buckets"][0]["grants"].as_array().unwrap().len(), 1);
    assert_eq!(view["buckets"][0]["other_grants"], 1);

    // A bucket with objects in it stays.
    let set_objects = |n: u64| {
        fake.lock()
            .unwrap()
            .buckets
            .values_mut()
            .find(|b| b.0 == "mine-media")
            .unwrap()
            .1 = n;
    };
    set_objects(3);
    let one = format!("/sites/{mine}/storage/buckets/{bid}");
    let (s, msg, _) = h.call("DELETE", &one, Some(&mgr), None, true).await;
    assert_eq!(s, StatusCode::CONFLICT, "{msg}");
    set_objects(0);
    let (s, _, _) = h.call("DELETE", &one, Some(&mgr), None, true).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = h
        .call(
            "DELETE",
            &format!("/sites/{mine}/storage/keys/{kid}"),
            Some(&mgr),
            None,
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    {
        let f = fake.lock().unwrap();
        assert!(!f.buckets.values().any(|b| b.0 == "mine-media"));
        assert_eq!(f.keys.len(), 1);
    }

    let conn = h.pool.get().unwrap();
    let all = crate::db::EventFilter {
        limit: 1000,
        ..Default::default()
    };
    let events = crate::db::list_events(&conn, &all).unwrap();
    for action in [
        "storage.bucket.create",
        "storage.key.create",
        "storage.grant",
        "storage.bucket.delete",
        "storage.key.delete",
    ] {
        assert!(events.iter().any(|e| e.action == action), "no audit entry for {action}");
    }
}

#[tokio::test]
async fn deleting_a_site_keeps_its_buckets_unlinked() {
    let (h, _fake, _dir) = setup().await;
    let admin = h.login("admin").await;
    let mine = site(&h, "mine.example.com");
    let (s, b, _) = h
        .call(
            "POST",
            "/storage/buckets",
            Some(&admin),
            Some(json!({"name": "keep-me", "site_id": mine})),
            true,
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let conn = h.pool.get().unwrap();
    crate::db::delete_site(&conn, mine).unwrap();
    let kept = crate::db::find_storage_bucket(&conn, b["id"].as_i64().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(kept.site_id, None);
}

#[tokio::test]
async fn a_wrong_token_is_reported_and_nothing_is_listed() {
    let (h, _fake, dir) = setup().await;
    std::fs::write(dir.path().join("admin.token"), "wrong").unwrap();
    let admin = h.login("admin").await;
    let (s, v, _) = h.call("GET", "/storage", Some(&admin), None, false).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["error"].as_str().unwrap().contains("403"), "{v}");
    assert_eq!(v["buckets"], json!([]));
}
