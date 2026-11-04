//! Application process (systemd unit) management for Node.js / Python / proxy sites.

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AuthUser;
use crate::authz::require_site;
use crate::db;
use crate::services::apps::{self, AppAction};
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Deserialize)]
pub struct AppConfigRequest {
    pub command: Option<String>,
    pub workdir: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub enabled: bool,
}

pub async fn update_app(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<AppConfigRequest>,
) -> ApiResult<impl IntoResponse> {
    let command = match p.command.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => Some(validate::app_command(c).map_err(ApiError::BadRequest)?),
        None => None,
    };
    if p.enabled && command.is_none() {
        return Err(ApiError::BadRequest(
            "Set a start command before enabling the app".into(),
        ));
    }
    if p.env.len() > 100 {
        return Err(ApiError::BadRequest("At most 100 environment variables".into()));
    }
    let mut env = BTreeMap::new();
    for (k, v) in &p.env {
        let k = validate::env_key(k).map_err(ApiError::BadRequest)?;
        if k == "PORT" {
            return Err(ApiError::BadRequest("PORT is set from the site's app port".into()));
        }
        env.insert(k, validate::env_value(v).map_err(ApiError::BadRequest)?);
    }
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            let mut site = require_site(conn, &user, id)?;
            if !site.kind().is_some_and(|k| k.has_app()) {
                return Err(ApiError::BadRequest("This site type has no managed app".into()));
            }
            let workdir = match p.workdir.as_deref().map(str::trim).filter(|w| !w.is_empty()) {
                Some(w) => {
                    let base = site
                        .home_dir
                        .clone()
                        .ok_or_else(|| ApiError::BadRequest("This site has no home directory".into()))?;
                    let path = validate::path_within(w, std::path::Path::new(&base)).map_err(ApiError::BadRequest)?;
                    Some(crate::services::sites::display_path(&path))
                }
                None => None,
            };
            if site.home_dir.is_none() && command.is_some() {
                return Err(ApiError::BadRequest(
                    "Sites created before v0.3 have no Linux user; recreate the site to manage its app".into(),
                ));
            }
            site.app_command = command;
            site.app_workdir = workdir;
            site.app_env = serde_json::to_string(&env).map_err(ApiError::internal)?;
            site.app_enabled = p.enabled;
            apps::apply(&config, &site).map_err(ApiError::Unprocessable)?;
            db::save_site(conn, &site)?;
            audit::record(conn, &user, "app.configure", Some(&site.domain), None);
            Ok(site)
        })
        .await?;
    Ok(Json(site))
}

pub async fn app_action(
    Path((id, action)): Path<(i64, String)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let act = match action.as_str() {
        "start" => AppAction::Start,
        "stop" => AppAction::Stop,
        "restart" => AppAction::Restart,
        _ => return Err(ApiError::NotFound("Action")),
    };
    let config = state.config.clone();
    let status = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            if site.app_command.is_none() {
                return Err(ApiError::BadRequest("Configure a start command first".into()));
            }
            if !site.is_active && !matches!(act, AppAction::Stop) {
                return Err(ApiError::BadRequest("Enable the site before starting its app".into()));
            }
            apps::act(&site.domain, act).map_err(ApiError::Unprocessable)?;
            audit::record(conn, &user, &format!("app.{action}"), Some(&site.domain), None);
            Ok(apps::status(&config, &site.domain))
        })
        .await?;
    Ok(Json(status))
}

#[derive(Deserialize)]
pub struct LinesQuery {
    pub lines: Option<usize>,
}

pub async fn app_logs(
    Path(id): Path<i64>,
    Query(q): Query<LinesQuery>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let lines = q.lines.unwrap_or(300).clamp(10, 5000);
    let logs = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            apps::journal(&apps::unit_name(&site.domain), lines).map_err(ApiError::Unprocessable)
        })
        .await?;
    Ok(Json(json!({ "logs": logs })))
}

pub async fn install_dependencies(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let actor = user.clone();
    let site = state
        .db(move |conn| {
            let site = require_site(conn, &actor, id)?;
            audit::record(conn, &actor, "app.install_dependencies", Some(&site.domain), None);
            Ok(site)
        })
        .await?;
    if site.home_dir.is_none() {
        return Err(ApiError::BadRequest("This site has no Linux user".into()));
    }
    let domain = site.domain.clone();
    let job_id = crate::jobs::spawn(&state.pool, "app.install", Some(&domain), Some(user.id), move |log| {
        apps::install_dependencies(&site, log)
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}
