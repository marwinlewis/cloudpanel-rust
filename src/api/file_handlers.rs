//! File manager endpoints, confined to the site's home directory.

use crate::api::download::{file_response, receive_upload};
use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AuthUser;
use crate::authz::require_site;
use crate::services::files::SiteFs;
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

pub const MAX_UPLOAD: u64 = 1024 * 1024 * 1024;

pub fn upload_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(MAX_UPLOAD as usize + 1024 * 1024)
}

pub fn edit_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(3 * 1024 * 1024)
}

fn ufs<T>(r: Result<T, String>) -> ApiResult<T> {
    r.map_err(ApiError::BadRequest)
}

/// Resolve the site and its file system root for the current user.
async fn site_fs(state: &SharedState, user: &AuthUser, id: i64) -> ApiResult<(crate::db::models::Site, SiteFs)> {
    let u = user.clone();
    let site = state.db(move |conn| require_site(conn, &u, id)).await?;
    let home = site
        .home_dir
        .clone()
        .ok_or_else(|| ApiError::BadRequest("This site has no home directory".into()))?;
    let sfs = ufs(SiteFs::new(&home, &site.system_user))?;
    Ok((site, sfs))
}

async fn audit_fs(state: &SharedState, user: AuthUser, action: &'static str, domain: String, path: String) {
    let _ = state
        .db(move |conn| {
            audit::record(conn, &user, action, Some(&domain), Some(&path));
            Ok(())
        })
        .await;
}

#[derive(Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    pub path: String,
}

pub async fn list(
    Path(id): Path<i64>,
    Query(q): Query<PathQuery>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let (site, sfs) = site_fs(&state, &user, id).await?;
    let path = q.path.clone();
    let entries = crate::state::blocking(move || ufs(sfs.list(&path))).await?;
    Ok(Json(
        json!({ "path": q.path.trim_matches('/'), "home": site.home_dir, "entries": entries }),
    ))
}

pub async fn read(
    Path(id): Path<i64>,
    Query(q): Query<PathQuery>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let (_, sfs) = site_fs(&state, &user, id).await?;
    let content = crate::state::blocking(move || ufs(sfs.read_text(&q.path))).await?;
    Ok(Json(json!({ "content": content })))
}

#[derive(Deserialize)]
pub struct WriteRequest {
    pub path: String,
    pub content: String,
}

pub async fn write(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<WriteRequest>,
) -> ApiResult<impl IntoResponse> {
    let (site, sfs) = site_fs(&state, &user, id).await?;
    let path = p.path.clone();
    crate::state::blocking(move || ufs(sfs.write_text(&p.path, &p.content))).await?;
    audit_fs(&state, user, "files.write", site.domain, path).await;
    Ok(Json(json!({ "message": "Saved" })))
}

#[derive(Deserialize)]
pub struct OpRequest {
    pub op: String,
    pub path: String,
    pub to: Option<String>,
    pub mode: Option<String>,
    #[serde(default)]
    pub names: Vec<String>,
    pub name: Option<String>,
}

/// mkdir, touch, rename, delete, chmod, extract, compress.
pub async fn op(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<OpRequest>,
) -> ApiResult<impl IntoResponse> {
    let (site, sfs) = site_fs(&state, &user, id).await?;
    let op = p.op.clone();
    let path = p.path.clone();
    let result = crate::state::blocking(move || {
        let r = (|| -> Result<Option<String>, String> {
            match p.op.as_str() {
                "mkdir" => sfs.mkdir(&p.path).map(|_| None),
                "touch" => sfs.create_file(&p.path).map(|_| None),
                "rename" => {
                    let to = p.to.as_deref().ok_or_else(|| "Missing destination".to_string())?;
                    sfs.rename(&p.path, to).map(|_| None)
                }
                "delete" => sfs.delete(&p.path).map(|_| None),
                "chmod" => {
                    let mode = validate::file_mode(p.mode.as_deref().unwrap_or(""))?;
                    sfs.chmod(&p.path, mode).map(|_| None)
                }
                "extract" => sfs.extract(&p.path).map(|_| None),
                "compress" => sfs
                    .compress(&p.path, &p.names, p.name.as_deref().unwrap_or("archive"))
                    .map(Some),
                _ => Err("Unknown operation".into()),
            }
        })();
        r.map_err(ApiError::BadRequest)
    })
    .await?;
    audit_fs(&state, user, "files.op", site.domain, format!("{op} {path}")).await;
    Ok(Json(json!({ "ok": true, "result": result })))
}

pub async fn download(
    Path(id): Path<i64>,
    Query(q): Query<PathQuery>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<axum::response::Response> {
    let (_, sfs) = site_fs(&state, &user, id).await?;
    let path = q.path.clone();
    let (file, _) = crate::state::blocking(move || ufs(sfs.download_path(&path))).await?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    file_response(file, &name).await
}

pub async fn upload(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    mp: Multipart,
) -> ApiResult<impl IntoResponse> {
    let (site, sfs) = site_fs(&state, &user, id).await?;
    // Stage inside the home so the final rename stays on one filesystem.
    let staging = std::path::PathBuf::from(site.home_dir.clone().unwrap_or_default());
    let up = receive_upload(mp, &staging, MAX_UPLOAD).await?;
    let dir = up.fields.get("path").cloned().unwrap_or_default();
    let overwrite = up.fields.get("overwrite").is_some_and(|v| v == "true");
    let name = up.file_name.clone();
    let tmp = up.temp_path.clone();
    let rel = crate::state::blocking(move || {
        let target = ufs(sfs.upload_target(&dir, &name, overwrite))?;
        std::fs::rename(&tmp, &target).map_err(ApiError::internal)?;
        ufs(sfs.finish_upload(&target))?;
        Ok(sfs.rel(&target))
    })
    .await;
    drop(up);
    let rel = rel?;
    audit_fs(&state, user, "files.upload", site.domain, rel.clone()).await;
    Ok(Json(json!({ "path": rel })))
}
