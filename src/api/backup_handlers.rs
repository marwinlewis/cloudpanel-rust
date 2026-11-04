use crate::api::download::file_response;
use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::{AdminUser, AuthUser};
use crate::authz::require_site;
use crate::db::{self, models::BackupPolicy};
use crate::services::backups;
use crate::services::s3::{self, S3Config};
use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

pub async fn list_site_backups(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            require_site(conn, &user, id)?;
            Ok(json!({
                "backups": db::list_backups(conn, Some(id))?,
                "policy": db::get_backup_policy(conn, id)?,
                "remote_configured": backups::remote_config(&config, conn).is_some(),
            }))
        })
        .await?;
    Ok(Json(out))
}

pub async fn create_site_backup(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let actor = user.clone();
    let site = state
        .db(move |conn| {
            let site = require_site(conn, &actor, id)?;
            audit::record(conn, &actor, "backup.create", Some(&site.domain), None);
            Ok(site)
        })
        .await?;
    if site.home_dir.is_none() {
        return Err(ApiError::BadRequest(
            "This site has no home directory to back up".into(),
        ));
    }
    let (config, pool) = (state.config.clone(), state.pool.clone());
    let job_id = crate::jobs::spawn(
        &state.pool,
        "backup.create",
        Some(&site.domain),
        Some(user.id),
        move |log| backups::backup_site(&config, &pool, id, log).map(|_| ()),
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

#[derive(Deserialize)]
pub struct PolicyRequest {
    pub frequency: String,
    pub hour: i64,
    pub retention: i64,
    #[serde(default)]
    pub remote_enabled: bool,
}

pub async fn set_backup_policy(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<PolicyRequest>,
) -> ApiResult<impl IntoResponse> {
    if !matches!(p.frequency.as_str(), "off" | "daily" | "weekly") {
        return Err(ApiError::BadRequest("Frequency must be off, daily or weekly".into()));
    }
    if !(0..=23).contains(&p.hour) || !(1..=365).contains(&p.retention) {
        return Err(ApiError::BadRequest("Hour must be 0-23 and retention 1-365".into()));
    }
    let config = state.config.clone();
    let policy = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            if p.remote_enabled && backups::remote_config(&config, conn).is_none() {
                return Err(ApiError::BadRequest(
                    "Configure remote storage in Settings first".into(),
                ));
            }
            let mut policy = db::get_backup_policy(conn, id)?;
            policy = BackupPolicy {
                frequency: p.frequency,
                hour: p.hour,
                retention: p.retention,
                remote_enabled: p.remote_enabled,
                ..policy
            };
            db::save_backup_policy(conn, &policy)?;
            audit::record(
                conn,
                &user,
                "backup.policy",
                Some(&site.domain),
                Some(&policy.frequency),
            );
            Ok(policy)
        })
        .await?;
    Ok(Json(policy))
}

/// Load a backup the user may access (panel backups are admin-only).
fn load_backup(conn: &rusqlite::Connection, user: &AuthUser, id: i64) -> ApiResult<crate::db::models::Backup> {
    let b = db::find_backup(conn, id)?.ok_or(ApiError::NotFound("Backup"))?;
    match b.site_id {
        Some(sid) => {
            require_site(conn, user, sid).map_err(|_| ApiError::NotFound("Backup"))?;
        }
        None if user.is_admin() => {}
        None => return Err(ApiError::NotFound("Backup")),
    }
    Ok(b)
}

pub async fn download_backup(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<axum::response::Response> {
    let config = state.config.clone();
    let b = state
        .db(move |conn| {
            let b = load_backup(conn, &user, id)?;
            audit::record(conn, &user, "backup.download", Some(&b.domain), Some(&b.file_name));
            Ok(b)
        })
        .await?;
    let path = std::path::PathBuf::from(&b.path);
    if !backups::is_backup_file(&config, &path) {
        return Err(ApiError::BadRequest(
            "The backup file is not on this server (it may only exist in remote storage)".into(),
        ));
    }
    file_response(path, &b.file_name).await
}

pub async fn delete_backup(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let b = load_backup(conn, &user, id)?;
            backups::delete(&config, conn, id).map_err(ApiError::Unprocessable)?;
            audit::record(conn, &user, "backup.delete", Some(&b.domain), Some(&b.file_name));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn restore_backup(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let actor = user.clone();
    let b = state
        .db(move |conn| {
            let b = load_backup(conn, &actor, id)?;
            if b.site_id.is_none() {
                return Err(ApiError::BadRequest(
                    "Panel backups are restored manually; see the README".into(),
                ));
            }
            if b.status != "ok" {
                return Err(ApiError::BadRequest("Only successful backups can be restored".into()));
            }
            audit::record(conn, &actor, "backup.restore", Some(&b.domain), Some(&b.file_name));
            Ok(b)
        })
        .await?;
    let (config, pool) = (state.config.clone(), state.pool.clone());
    let job_id = crate::jobs::spawn(
        &state.pool,
        "backup.restore",
        Some(&b.domain),
        Some(user.id),
        move |log| backups::restore(&config, &pool, id, log),
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- Panel backups & remote storage (admin) ----------

pub async fn list_panel_backups(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let list = state
        .db(|conn| {
            Ok(db::list_backups(conn, None)?
                .into_iter()
                .filter(|b| b.site_id.is_none() && b.domain == "_panel")
                .collect::<Vec<_>>())
        })
        .await?;
    Ok(Json(list))
}

pub async fn create_panel_backup(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let (config, pool) = (state.config.clone(), state.pool.clone());
    let actor = admin.0.clone();
    state
        .db(move |conn| {
            audit::record(conn, &actor, "backup.panel", None, None);
            Ok(())
        })
        .await?;
    let job_id = crate::jobs::spawn(&state.pool, "backup.panel", None, Some(admin.0.id), move |log| {
        backups::backup_panel(&config, &pool, log)
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn get_remote(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let cfg = state.db(move |conn| Ok(backups::remote_config(&config, conn))).await?;
    // Never return the secret key.
    Ok(Json(cfg.map(|c| {
        json!({
            "endpoint": c.endpoint, "region": c.region, "bucket": c.bucket, "access_key": c.access_key,
            "prefix": c.prefix, "path_style": c.path_style, "has_secret": !c.secret_key.is_empty(),
        })
    })))
}

#[derive(Deserialize)]
pub struct RemoteRequest {
    pub endpoint: String,
    #[serde(default)]
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    /// Empty keeps the stored secret.
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
}

pub async fn set_remote(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<RemoteRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let existing = {
        let c = config.clone();
        state.db(move |conn| Ok(backups::remote_config(&c, conn))).await?
    };
    let cfg = S3Config {
        endpoint: p.endpoint.trim().to_string(),
        region: p.region.trim().to_string(),
        bucket: p.bucket.trim().to_string(),
        access_key: p.access_key.trim().to_string(),
        secret_key: if p.secret_key.trim().is_empty() {
            existing.map(|e| e.secret_key).unwrap_or_default()
        } else {
            p.secret_key.trim().to_string()
        },
        prefix: p.prefix.trim().to_string(),
        path_style: p.path_style,
    };
    cfg.validate().map_err(ApiError::BadRequest)?;
    let test = cfg.clone();
    crate::state::blocking(move || {
        s3::test(&test).map_err(|e| ApiError::Unprocessable(format!("Connection test failed: {e}")))
    })
    .await?;
    let sealed = crate::secrets::seal(&config.etc_dir, &cfg).map_err(ApiError::internal)?;
    state
        .db(move |conn| {
            db::set_setting(conn, backups::S3_SETTING, &sealed)?;
            audit::record(conn, &admin.0, "backup.remote_configure", Some(&cfg.bucket), None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "message": "Remote storage saved and tested" })))
}

pub async fn delete_remote(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            db::delete_setting(conn, backups::S3_SETTING)?;
            conn.execute("UPDATE backup_policies SET remote_enabled = 0", [])?;
            audit::record(conn, &admin.0, "backup.remote_remove", None, None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}
