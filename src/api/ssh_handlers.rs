//! SSH / SFTP accounts per site and their authorized keys.

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AuthUser;
use crate::authz::require_site;
use crate::config::Config;
use crate::db::{self, models::SshUser};
use crate::services::sysusers;
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;

fn sync_keys(config: &Config, conn: &Connection, u: &SshUser) -> ApiResult<()> {
    let keys: Vec<String> = db::list_ssh_keys(conn, u.id)?
        .into_iter()
        .map(|k| k.public_key)
        .collect();
    sysusers::write_authorized_keys(config, &u.username, &keys).map_err(ApiError::internal)
}

fn check_password(pw: &str) -> ApiResult<()> {
    validate::password(pw).map_err(ApiError::BadRequest)?;
    if pw.contains([':', '\n', '\r']) {
        return Err(ApiError::BadRequest(
            "Password cannot contain ':' or line breaks".into(),
        ));
    }
    Ok(())
}

pub async fn list_ssh_users(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let out = state
        .db(move |conn| {
            require_site(conn, &user, id)?;
            let mut out = Vec::new();
            for u in db::list_ssh_users(conn, id)? {
                let keys = db::list_ssh_keys(conn, u.id)?;
                let mut v = serde_json::to_value(&u).map_err(ApiError::internal)?;
                v["keys"] = json!(keys
                    .iter()
                    .map(|k| json!({ "id": k.id, "name": k.name, "fingerprint": k.fingerprint, "created_at": k.created_at }))
                    .collect::<Vec<_>>());
                out.push(v);
            }
            Ok(out)
        })
        .await?;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct CreateSshUserRequest {
    pub username: String,
    pub password: Option<String>,
    #[serde(default)]
    pub sftp_only: bool,
}

pub async fn create_ssh_user(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateSshUserRequest>,
) -> ApiResult<impl IntoResponse> {
    let username = validate::system_user(&p.username).map_err(ApiError::BadRequest)?;
    if let Some(pw) = p.password.as_deref().filter(|s| !s.is_empty()) {
        check_password(pw)?;
    }
    let config = state.config.clone();
    let created = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let home = site
                .home_dir
                .clone()
                .ok_or_else(|| ApiError::BadRequest("This site has no Linux user to share files with".into()))?;
            if sysusers::name_in_use(&username) || db::list_ssh_users(conn, id)?.iter().any(|u| u.username == username)
            {
                return Err(ApiError::Conflict(format!("The user '{username}' already exists")));
            }
            sysusers::ensure_sshd_dropin(&config).map_err(ApiError::Unprocessable)?;
            sysusers::create_ssh_user(&site.system_user, &username, std::path::Path::new(&home), p.sftp_only)
                .map_err(ApiError::Unprocessable)?;
            if let Some(pw) = p.password.as_deref().filter(|s| !s.is_empty()) {
                if let Err(e) = sysusers::set_password(&username, pw) {
                    let _ = sysusers::delete_user(&username, false);
                    return Err(ApiError::Unprocessable(e));
                }
            }
            let uid = db::create_ssh_user(conn, id, &username, p.sftp_only, false).map_err(|e| {
                let _ = sysusers::delete_user(&username, false);
                ApiError::from(e)
            })?;
            audit::record(conn, &user, "ssh.user_create", Some(&site.domain), Some(&username));
            Ok(db::find_ssh_user(conn, id, uid)?)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Deserialize)]
pub struct UpdateSshUserRequest {
    pub sftp_only: bool,
}

pub async fn update_ssh_user(
    Path((id, uid)): Path<(i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<UpdateSshUserRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let u = db::find_ssh_user(conn, id, uid)?.ok_or(ApiError::NotFound("SSH user"))?;
            if u.is_owner && p.sftp_only {
                // The owner runs the app and cron jobs; it keeps a shell.
                return Err(ApiError::BadRequest(
                    "The site owner account cannot be SFTP-only".into(),
                ));
            }
            sysusers::ensure_sshd_dropin(&config).map_err(ApiError::Unprocessable)?;
            sysusers::set_sftp_only(&u.username, p.sftp_only).map_err(ApiError::Unprocessable)?;
            db::set_ssh_user_sftp_only(conn, uid, p.sftp_only)?;
            audit::record(conn, &user, "ssh.user_update", Some(&site.domain), Some(&u.username));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PasswordRequest {
    pub password: String,
}

pub async fn set_ssh_password(
    Path((id, uid)): Path<(i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<PasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    check_password(&p.password)?;
    state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let u = db::find_ssh_user(conn, id, uid)?.ok_or(ApiError::NotFound("SSH user"))?;
            sysusers::set_password(&u.username, &p.password).map_err(ApiError::Unprocessable)?;
            audit::record(conn, &user, "ssh.password", Some(&site.domain), Some(&u.username));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "message": "Password updated" })))
}

pub async fn delete_ssh_user(
    Path((id, uid)): Path<(i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let u = db::find_ssh_user(conn, id, uid)?.ok_or(ApiError::NotFound("SSH user"))?;
            if u.is_owner {
                return Err(ApiError::BadRequest(
                    "The site owner account is removed with the site".into(),
                ));
            }
            sysusers::delete_user(&u.username, false).map_err(ApiError::Unprocessable)?;
            sysusers::remove_authorized_keys(&config, &u.username);
            db::delete_ssh_user(conn, uid)?;
            audit::record(conn, &user, "ssh.user_delete", Some(&site.domain), Some(&u.username));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct AddKeyRequest {
    pub name: Option<String>,
    pub public_key: String,
}

pub async fn add_ssh_key(
    Path((id, uid)): Path<(i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<AddKeyRequest>,
) -> ApiResult<impl IntoResponse> {
    let (key, fingerprint) = validate::ssh_public_key(&p.public_key).map_err(ApiError::BadRequest)?;
    let name = validate::short_text(p.name.as_deref(), 60)
        .map_err(ApiError::BadRequest)?
        .unwrap_or_else(|| {
            key.split_whitespace()
                .nth(2)
                .unwrap_or("key")
                .chars()
                .take(60)
                .collect()
        });
    let config = state.config.clone();
    state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let u = db::find_ssh_user(conn, id, uid)?.ok_or(ApiError::NotFound("SSH user"))?;
            let existing = db::list_ssh_keys(conn, uid)?;
            if existing.iter().any(|k| k.fingerprint == fingerprint) {
                return Err(ApiError::Conflict("That key is already added".into()));
            }
            if existing.len() >= 50 {
                return Err(ApiError::BadRequest("At most 50 keys per user".into()));
            }
            sysusers::ensure_sshd_dropin(&config).map_err(ApiError::Unprocessable)?;
            db::add_ssh_key(conn, uid, &name, &key, &fingerprint)?;
            sync_keys(&config, conn, &u)?;
            audit::record(
                conn,
                &user,
                "ssh.key_add",
                Some(&site.domain),
                Some(&format!("{} {fingerprint}", u.username)),
            );
            Ok(())
        })
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "ok": true }))))
}

pub async fn delete_ssh_key(
    Path((id, uid, kid)): Path<(i64, i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let u = db::find_ssh_user(conn, id, uid)?.ok_or(ApiError::NotFound("SSH user"))?;
            if !db::delete_ssh_key(conn, uid, kid)? {
                return Err(ApiError::NotFound("Key"));
            }
            sync_keys(&config, conn, &u)?;
            audit::record(conn, &user, "ssh.key_delete", Some(&site.domain), Some(&u.username));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}
