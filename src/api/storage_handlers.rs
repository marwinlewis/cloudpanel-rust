//! Object storage (Garage): buckets, access keys and their grants.
//!
//! Administrators manage everything under `/storage`. A bucket or key can belong to a site, and
//! the managers of that site manage it under `/sites/:id/storage`. A bucket or key of another
//! site, or of none, looks missing to them.

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::{AdminUser, AuthUser};
use crate::authz::require_site;
use crate::config::Config;
use crate::db::{
    self,
    models::{StorageBucket, StorageKey},
};
use crate::services::garage::{self, Admin, BucketInfo, Perm, Quotas, Settings};
use crate::services::nginx::NginxService;
use crate::services::panel_cert;
use crate::services::SslService;
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use futures_util::future::join_all;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};

/// Who is asking: an administrator (everything) or a manager working on one site.
#[derive(Clone, Copy)]
enum Scope {
    Admin,
    Site(i64),
}

impl Scope {
    fn site(self) -> Option<i64> {
        match self {
            Scope::Admin => None,
            Scope::Site(id) => Some(id),
        }
    }

    fn allows(self, owner: Option<i64>) -> bool {
        match self {
            Scope::Admin => true,
            Scope::Site(id) => owner == Some(id),
        }
    }
}

fn garage_error(e: String) -> ApiError {
    ApiError::Unprocessable(e)
}

fn admin_client(config: &Config) -> ApiResult<Admin> {
    if !garage::installed(config) && !cfg!(test) {
        return Err(ApiError::BadRequest(
            "Object storage is not installed. An administrator can install it on the Object Storage page.".into(),
        ));
    }
    Admin::from_config(config).map_err(garage_error)
}

/// Is Garage up for the panel to talk to? Tests run against a stand-in admin API instead.
fn live(config: &Config) -> bool {
    if cfg!(test) {
        return config.garage_dir.join("admin.token").is_file();
    }
    garage::installed(config) && garage::active()
}

fn load_settings(conn: &Connection) -> ApiResult<Settings> {
    Ok(db::get_json(conn, garage::SETTING)?)
}

/// Where apps reach the S3 API: the public hostname if there is one, and always loopback.
fn endpoints(settings: &Settings) -> Value {
    json!({
        "public": settings.hostname.as_ref().map(|h| format!("https://{h}")),
        "local": format!("http://{}", garage::S3_ADDR),
        "region": garage::REGION,
        "path_style": true,
    })
}

/// Make the panel's records match Garage's buckets and keys.
async fn sync(state: &SharedState, admin: &Admin) -> ApiResult<()> {
    let (buckets, keys) = tokio::try_join!(admin.list_buckets(), admin.list_keys()).map_err(garage_error)?;
    let buckets: Vec<(String, String)> = buckets
        .into_iter()
        .map(|b| {
            let name = b
                .global_aliases
                .first()
                .cloned()
                .unwrap_or_else(|| format!("({})", &b.id[..b.id.len().min(16)]));
            (b.id, name)
        })
        .collect();
    let keys: Vec<(String, String)> = keys.into_iter().map(|k| (k.id, k.name)).collect();
    state.db(move |conn| Ok(db::sync_storage(conn, &buckets, &keys)?)).await
}

/// Buckets with Garage's live numbers and grants. For a site, only grants to its own keys are
/// listed; the others are counted.
async fn bucket_views(admin: &Admin, buckets: &[StorageBucket], keys: &[StorageKey], scope: Scope) -> Vec<Value> {
    let infos = join_all(buckets.iter().map(|b| admin.bucket(&b.garage_id))).await;
    buckets
        .iter()
        .zip(infos)
        .map(|(b, info)| {
            let mut v = serde_json::to_value(b).unwrap_or_default();
            match info {
                Ok(BucketInfo {
                    objects,
                    bytes,
                    quotas,
                    keys: grants,
                    ..
                }) => {
                    let mut listed = Vec::new();
                    let mut others = 0;
                    for g in grants.iter().filter(|g| g.permissions.any()) {
                        match keys.iter().find(|k| k.garage_key_id == g.access_key_id) {
                            Some(k) if scope.allows(k.site_id) => listed.push(json!({
                                "key_id": k.id,
                                "access_key_id": k.garage_key_id,
                                "name": k.name,
                                "permissions": g.permissions,
                            })),
                            _ => others += 1,
                        }
                    }
                    v["objects"] = json!(objects);
                    v["bytes"] = json!(bytes);
                    v["quotas"] = json!(quotas);
                    v["grants"] = json!(listed);
                    v["other_grants"] = json!(others);
                }
                Err(e) => v["error"] = json!(e),
            }
            v
        })
        .collect()
}

// ---------- Overview ----------

pub async fn get_storage(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let (installed, can_install, running) =
        blocking(move || Ok((garage::installed(&config), garage::can_install(&config), live(&config)))).await?;
    let (settings, sites) = state
        .db(|conn| Ok((load_settings(conn)?, db::list_sites(conn)?)))
        .await?;
    let sites: Vec<Value> = sites
        .iter()
        .map(|s| json!({ "id": s.id, "domain": s.domain }))
        .collect();
    let mut out = json!({
        "installed": installed,
        "can_install": can_install,
        "running": running,
        "version": null,
        "latest_version": garage::VERSION,
        "endpoint": endpoints(&settings),
        "hostname": settings.hostname,
        "sites": sites,
        "buckets": [],
        "keys": [],
    });
    if !running {
        return Ok(Json(out));
    }
    let admin = Admin::from_config(&state.config).map_err(garage_error)?;
    let (health, stats, version) = tokio::join!(admin.health(), admin.statistics(), admin.version());
    out["health"] = json!(health.as_ref().ok());
    out["statistics"] = json!(stats.as_ref().ok());
    out["version"] = json!(version.ok().flatten());
    if let Err(e) = health {
        out["error"] = json!(e);
        return Ok(Json(out));
    }
    sync(&state, &admin).await?;
    let (buckets, keys) = state
        .db(|conn| {
            Ok((
                db::list_storage_buckets(conn, None)?,
                db::list_storage_keys(conn, None)?,
            ))
        })
        .await?;
    out["buckets"] = json!(bucket_views(&admin, &buckets, &keys, Scope::Admin).await);
    out["keys"] = json!(keys);
    Ok(Json(out))
}

pub async fn install(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    if !garage::can_install(&state.config) {
        return Err(ApiError::BadRequest(
            "This system can't install Garage from the panel. Run the CloudPanel installer with --with-garage.".into(),
        ));
    }
    let exe = std::env::current_exe().map_err(ApiError::internal)?;
    let actor = admin.0.clone();
    state
        .db(move |conn| {
            audit::record(conn, &actor, "storage.install", None, Some(garage::VERSION));
            Ok(())
        })
        .await?;
    let job_id = crate::jobs::spawn(&state.pool, "storage.install", None, Some(admin.0.id), move |log| {
        let exe = exe.to_string_lossy().into_owned();
        let r = crate::services::cmd::run_host_streaming(
            &exe,
            &["garage-install"],
            &crate::services::cmd::CmdOpts::default().timeout(20 * 60),
            &mut |l, _| log.line(l),
        );
        if r.success() {
            Ok(())
        } else {
            Err(format!("Installing Garage failed (exit code {})", r.code.unwrap_or(-1)))
        }
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- Public endpoint ----------

#[derive(Deserialize)]
pub struct EndpointRequest {
    pub hostname: String,
    pub email: String,
    /// Skip the DNS check (servers behind NAT where the public IP isn't on an interface).
    #[serde(default)]
    pub skip_dns_check: bool,
}

pub async fn set_endpoint(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<EndpointRequest>,
) -> ApiResult<impl IntoResponse> {
    if !garage::installed(&state.config) && !cfg!(test) {
        return Err(ApiError::BadRequest("Install object storage first".into()));
    }
    let host = validate::domain(&p.hostname).map_err(ApiError::BadRequest)?;
    let email = validate::email(&p.email).map_err(ApiError::BadRequest)?;
    let h = host.clone();
    state
        .db(move |conn| {
            if let Some(site) = panel_cert::site_on_hostname(&db::list_sites(conn)?, &h) {
                return Err(ApiError::Conflict(format!(
                    "The site {site} already answers on {h}. Use a different hostname for object storage."
                )));
            }
            if panel_cert::load(conn).is_some_and(|t| t.hostname.eq_ignore_ascii_case(&h)) {
                return Err(ApiError::Conflict(format!("{h} is the panel's own hostname")));
            }
            Ok(())
        })
        .await?;
    if !p.skip_dns_check {
        panel_cert::resolves_here(&host).await.map_err(ApiError::BadRequest)?;
    }
    let h = host.clone();
    let config = state.config.clone();
    let (cert, key) = blocking(move || {
        let (cert, key) =
            SslService::issue_letsencrypt(std::slice::from_ref(&h), &email).map_err(ApiError::Unprocessable)?;
        NginxService::apply_s3_vhost(&config, &h, &cert, &key, garage::S3_ADDR).map_err(ApiError::Unprocessable)?;
        Ok((cert, key))
    })
    .await?;
    let name = host.clone();
    state
        .db(move |conn| {
            let mut s = load_settings(conn)?;
            s.hostname = Some(name.clone());
            s.cert = Some(cert);
            s.key = Some(key);
            db::set_json(conn, garage::SETTING, &s)?;
            audit::record(conn, &admin.0, "storage.endpoint.set", Some(&name), None);
            Ok(())
        })
        .await?;
    Ok(Json(
        json!({ "message": format!("Object storage is now at https://{host}") }),
    ))
}

pub async fn remove_endpoint(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    blocking(move || NginxService::remove_s3_vhost(&config).map_err(ApiError::Unprocessable)).await?;
    state
        .db(move |conn| {
            let mut s = load_settings(conn)?;
            let old = s.hostname.take();
            s.cert = None;
            s.key = None;
            db::set_json(conn, garage::SETTING, &s)?;
            audit::record(conn, &admin.0, "storage.endpoint.remove", old.as_deref(), None);
            Ok(())
        })
        .await?;
    Ok(Json(
        json!({ "message": "Object storage is now reachable on this server only" }),
    ))
}

// ---------- Buckets ----------

#[derive(Deserialize)]
pub struct CreateBucketRequest {
    pub name: String,
    #[serde(default)]
    pub site_id: Option<i64>,
    #[serde(default)]
    pub max_size_mb: Option<u64>,
    #[serde(default)]
    pub max_objects: Option<u64>,
}

fn quotas(max_size_mb: Option<u64>, max_objects: Option<u64>) -> ApiResult<Quotas> {
    let max_size = match max_size_mb.filter(|m| *m > 0) {
        Some(mb) => Some(
            mb.checked_mul(1024 * 1024)
                .ok_or_else(|| ApiError::BadRequest("That size limit is too large".into()))?,
        ),
        None => None,
    };
    Ok(Quotas {
        max_size,
        max_objects: max_objects.filter(|m| *m > 0),
    })
}

async fn check_site(state: &SharedState, site_id: Option<i64>) -> ApiResult<()> {
    if let Some(id) = site_id {
        state
            .db(move |conn| {
                db::find_site_by_id(conn, id)?.ok_or(ApiError::NotFound("Site"))?;
                Ok(())
            })
            .await?;
    }
    Ok(())
}

async fn create_bucket_in(
    state: &SharedState,
    actor: AuthUser,
    name: &str,
    site_id: Option<i64>,
    q: Quotas,
) -> ApiResult<StorageBucket> {
    let name = garage::bucket_name(name).map_err(ApiError::BadRequest)?;
    let admin = admin_client(&state.config)?;
    let created = admin.create_bucket(&name).await.map_err(garage_error)?;
    if q != Quotas::default() {
        if let Err(e) = admin.set_quotas(&created.id, &q).await {
            let _ = admin.delete_bucket(&created.id).await;
            return Err(garage_error(e));
        }
    }
    let gid = created.id.clone();
    let saved = state
        .db(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let id = db::create_storage_bucket(&tx, &gid, &name, site_id)?;
            let detail = site_id.map(|s| format!("site {s}"));
            audit::record(&tx, &actor, "storage.bucket.create", Some(&name), detail.as_deref());
            let b = db::find_storage_bucket(&tx, id)?.ok_or(ApiError::NotFound("Bucket"))?;
            tx.commit()?;
            Ok(b)
        })
        .await;
    if saved.is_err() {
        let _ = admin.delete_bucket(&created.id).await;
    }
    saved
}

pub async fn create_bucket(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateBucketRequest>,
) -> ApiResult<impl IntoResponse> {
    let q = quotas(p.max_size_mb, p.max_objects)?;
    check_site(&state, p.site_id).await?;
    let b = create_bucket_in(&state, admin.0, &p.name, p.site_id, q).await?;
    Ok((StatusCode::CREATED, Json(b)))
}

#[derive(Deserialize)]
pub struct UpdateBucketRequest {
    #[serde(default)]
    pub site_id: Option<i64>,
    #[serde(default)]
    pub max_size_mb: Option<u64>,
    #[serde(default)]
    pub max_objects: Option<u64>,
}

/// Replace a bucket's site link and quotas (administrators only).
pub async fn update_bucket(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<UpdateBucketRequest>,
) -> ApiResult<impl IntoResponse> {
    let q = quotas(p.max_size_mb, p.max_objects)?;
    check_site(&state, p.site_id).await?;
    let b = state
        .db(move |conn| db::find_storage_bucket(conn, id)?.ok_or(ApiError::NotFound("Bucket")))
        .await?;
    let client = admin_client(&state.config)?;
    client.set_quotas(&b.garage_id, &q).await.map_err(garage_error)?;
    let site_id = p.site_id;
    let updated = state
        .db(move |conn| {
            let tx = conn.unchecked_transaction()?;
            db::set_storage_bucket_site(&tx, id, site_id)?;
            let detail = format!(
                "site {}, max size {}, max objects {}",
                site_id.map_or("none".into(), |s| s.to_string()),
                q.max_size.map_or("none".into(), |s| format!("{s} bytes")),
                q.max_objects.map_or("none".into(), |s| s.to_string()),
            );
            audit::record(&tx, &admin.0, "storage.bucket.update", Some(&b.name), Some(&detail));
            let b = db::find_storage_bucket(&tx, id)?.ok_or(ApiError::NotFound("Bucket"))?;
            tx.commit()?;
            Ok(b)
        })
        .await?;
    Ok(Json(updated))
}

async fn find_bucket(state: &SharedState, scope: Scope, id: i64) -> ApiResult<StorageBucket> {
    state
        .db(move |conn| {
            db::find_storage_bucket(conn, id)?
                .filter(|b| scope.allows(b.site_id))
                .ok_or(ApiError::NotFound("Bucket"))
        })
        .await
}

async fn find_key(state: &SharedState, scope: Scope, id: i64) -> ApiResult<StorageKey> {
    state
        .db(move |conn| {
            db::find_storage_key(conn, id)?
                .filter(|k| scope.allows(k.site_id))
                .ok_or(ApiError::NotFound("Access key"))
        })
        .await
}

async fn delete_bucket_in(state: &SharedState, actor: AuthUser, scope: Scope, id: i64) -> ApiResult<()> {
    let b = find_bucket(state, scope, id).await?;
    let admin = admin_client(&state.config)?;
    let info = admin.bucket(&b.garage_id).await.map_err(garage_error)?;
    if info.objects > 0 || info.bytes > 0 {
        return Err(ApiError::Conflict(format!(
            "Bucket {} still holds {} object{}. Empty it first.",
            b.name,
            info.objects,
            if info.objects == 1 { "" } else { "s" }
        )));
    }
    admin.delete_bucket(&b.garage_id).await.map_err(garage_error)?;
    state
        .db(move |conn| {
            db::delete_storage_bucket(conn, id)?;
            audit::record(conn, &actor, "storage.bucket.delete", Some(&b.name), None);
            Ok(())
        })
        .await
}

pub async fn delete_bucket(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    delete_bucket_in(&state, admin.0, Scope::Admin, id).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------- Access keys ----------

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    #[serde(default)]
    pub site_id: Option<i64>,
}

async fn create_key_in(state: &SharedState, actor: AuthUser, name: &str, site_id: Option<i64>) -> ApiResult<Value> {
    let name = garage::key_name(name).map_err(ApiError::BadRequest)?;
    let admin = admin_client(&state.config)?;
    let created = admin.create_key(&name).await.map_err(garage_error)?;
    let Some(secret) = created.secret_access_key.clone() else {
        let _ = admin.delete_key(&created.access_key_id).await;
        return Err(ApiError::internal("Garage did not return the new key's secret"));
    };
    let kid = created.access_key_id.clone();
    let saved = state
        .db(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let id = db::create_storage_key(&tx, &kid, &name, site_id)?;
            let detail = site_id.map(|s| format!("site {s}"));
            audit::record(&tx, &actor, "storage.key.create", Some(&kid), detail.as_deref());
            let k = db::find_storage_key(&tx, id)?.ok_or(ApiError::NotFound("Access key"))?;
            tx.commit()?;
            Ok(k)
        })
        .await;
    let k = match saved {
        Ok(k) => k,
        Err(e) => {
            let _ = admin.delete_key(&created.access_key_id).await;
            return Err(e);
        }
    };
    // The secret is shown this once and never stored by the panel.
    let mut v = serde_json::to_value(&k).unwrap_or_default();
    v["secret_access_key"] = json!(secret);
    Ok(v)
}

pub async fn create_key(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateKeyRequest>,
) -> ApiResult<impl IntoResponse> {
    check_site(&state, p.site_id).await?;
    let v = create_key_in(&state, admin.0, &p.name, p.site_id).await?;
    Ok((StatusCode::CREATED, Json(v)))
}

#[derive(Deserialize)]
pub struct UpdateKeyRequest {
    #[serde(default)]
    pub site_id: Option<i64>,
}

/// Link a key to a site, or unlink it (administrators only).
pub async fn update_key(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<UpdateKeyRequest>,
) -> ApiResult<impl IntoResponse> {
    check_site(&state, p.site_id).await?;
    let updated = state
        .db(move |conn| {
            let k = db::find_storage_key(conn, id)?.ok_or(ApiError::NotFound("Access key"))?;
            let tx = conn.unchecked_transaction()?;
            db::set_storage_key_site(&tx, id, p.site_id)?;
            let detail = format!("site {}", p.site_id.map_or("none".into(), |s| s.to_string()));
            audit::record(
                &tx,
                &admin.0,
                "storage.key.update",
                Some(&k.garage_key_id),
                Some(&detail),
            );
            let k = db::find_storage_key(&tx, id)?.ok_or(ApiError::NotFound("Access key"))?;
            tx.commit()?;
            Ok(k)
        })
        .await?;
    Ok(Json(updated))
}

async fn delete_key_in(state: &SharedState, actor: AuthUser, scope: Scope, id: i64) -> ApiResult<()> {
    let k = find_key(state, scope, id).await?;
    let admin = admin_client(&state.config)?;
    admin.delete_key(&k.garage_key_id).await.map_err(garage_error)?;
    state
        .db(move |conn| {
            db::delete_storage_key(conn, id)?;
            audit::record(
                conn,
                &actor,
                "storage.key.delete",
                Some(&k.garage_key_id),
                Some(&k.name),
            );
            Ok(())
        })
        .await
}

pub async fn delete_key(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    delete_key_in(&state, admin.0, Scope::Admin, id).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------- Grants ----------

#[derive(Deserialize, Default)]
pub struct GrantRequest {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub owner: bool,
}

async fn set_grant_in(
    state: &SharedState,
    actor: AuthUser,
    scope: Scope,
    bucket_id: i64,
    key_id: i64,
    perm: Perm,
) -> ApiResult<()> {
    let b = find_bucket(state, scope, bucket_id).await?;
    let k = find_key(state, scope, key_id).await?;
    // A site's key only ever gets access to that site's buckets, whoever grants it.
    if let (Some(ks), bs) = (k.site_id, b.site_id) {
        if bs != Some(ks) {
            return Err(ApiError::BadRequest(format!(
                "Key {} belongs to {}, and bucket {} doesn't. Link both to the same site, or unlink the key.",
                k.name,
                k.site_domain.as_deref().unwrap_or("another site"),
                b.name
            )));
        }
    }
    let admin = admin_client(&state.config)?;
    admin
        .set_grant(&b.garage_id, &k.garage_key_id, perm)
        .await
        .map_err(garage_error)?;
    let detail = format!(
        "{}: {}",
        k.garage_key_id,
        [("read", perm.read), ("write", perm.write), ("owner", perm.owner)]
            .iter()
            .filter(|(_, on)| *on)
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join("+")
    );
    let detail = if perm.any() {
        detail
    } else {
        format!("{}: none", k.garage_key_id)
    };
    state
        .db(move |conn| {
            audit::record(conn, &actor, "storage.grant", Some(&b.name), Some(&detail));
            Ok(())
        })
        .await
}

pub async fn set_grant(
    Path((bucket_id, key_id)): Path<(i64, i64)>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<GrantRequest>,
) -> ApiResult<impl IntoResponse> {
    let perm = Perm {
        read: p.read,
        write: p.write,
        owner: p.owner,
    };
    set_grant_in(&state, admin.0, Scope::Admin, bucket_id, key_id, perm).await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn revoke_grant(
    Path((bucket_id, key_id)): Path<(i64, i64)>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    set_grant_in(&state, admin.0, Scope::Admin, bucket_id, key_id, Perm::default()).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------- A site's own buckets and keys ----------

async fn site_scope(state: &SharedState, user: &AuthUser, site_id: i64) -> ApiResult<Scope> {
    let u = user.clone();
    state
        .db(move |conn| {
            require_site(conn, &u, site_id)?;
            Ok(())
        })
        .await?;
    Ok(Scope::Site(site_id))
}

pub async fn get_site_storage(
    Path(site_id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let scope = site_scope(&state, &user, site_id).await?;
    let config = state.config.clone();
    let (installed, running) = blocking(move || Ok((garage::installed(&config), live(&config)))).await?;
    let settings = state.db(load_settings).await?;
    let mut out = json!({
        "installed": installed,
        "running": running,
        "endpoint": endpoints(&settings),
        "buckets": [],
        "keys": [],
    });
    if !running {
        return Ok(Json(out));
    }
    let admin = Admin::from_config(&state.config).map_err(garage_error)?;
    if let Err(e) = sync(&state, &admin).await {
        out["error"] = json!(match e {
            ApiError::Unprocessable(m) => m,
            _ => "Object storage is not answering".into(),
        });
        return Ok(Json(out));
    }
    let (buckets, keys) = state
        .db(move |conn| {
            Ok((
                db::list_storage_buckets(conn, scope.site())?,
                db::list_storage_keys(conn, scope.site())?,
            ))
        })
        .await?;
    out["buckets"] = json!(bucket_views(&admin, &buckets, &keys, scope).await);
    out["keys"] = json!(keys);
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct NameRequest {
    pub name: String,
}

pub async fn create_site_bucket(
    Path(site_id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<NameRequest>,
) -> ApiResult<impl IntoResponse> {
    site_scope(&state, &user, site_id).await?;
    let b = create_bucket_in(&state, user, &p.name, Some(site_id), Quotas::default()).await?;
    Ok((StatusCode::CREATED, Json(b)))
}

pub async fn delete_site_bucket(
    Path((site_id, id)): Path<(i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let scope = site_scope(&state, &user, site_id).await?;
    delete_bucket_in(&state, user, scope, id).await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn create_site_key(
    Path(site_id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<NameRequest>,
) -> ApiResult<impl IntoResponse> {
    site_scope(&state, &user, site_id).await?;
    let v = create_key_in(&state, user, &p.name, Some(site_id)).await?;
    Ok((StatusCode::CREATED, Json(v)))
}

pub async fn delete_site_key(
    Path((site_id, id)): Path<(i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let scope = site_scope(&state, &user, site_id).await?;
    delete_key_in(&state, user, scope, id).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Read and write only: owner rights (bucket settings, deleting it over S3) stay with admins.
pub async fn set_site_grant(
    Path((site_id, bucket_id, key_id)): Path<(i64, i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<GrantRequest>,
) -> ApiResult<impl IntoResponse> {
    let scope = site_scope(&state, &user, site_id).await?;
    if p.owner && !user.is_admin() {
        return Err(ApiError::Forbidden);
    }
    let perm = Perm {
        read: p.read,
        write: p.write,
        owner: p.owner,
    };
    set_grant_in(&state, user, scope, bucket_id, key_id, perm).await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn revoke_site_grant(
    Path((site_id, bucket_id, key_id)): Path<(i64, i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let scope = site_scope(&state, &user, site_id).await?;
    set_grant_in(&state, user, scope, bucket_id, key_id, Perm::default()).await?;
    Ok(Json(json!({ "ok": true })))
}
