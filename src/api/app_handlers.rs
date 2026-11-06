//! Application process management for Node.js / Python / proxy sites (systemd unit or PM2).

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AuthUser;
use crate::authz::require_site;
use crate::config::Config;
use crate::db;
use crate::db::models::{Pm2Options, Site, SiteType, MANAGER_PM2, MANAGER_SYSTEMD};
use crate::jobs::JobLog;
use crate::services::apps::{self, AppAction};
use crate::services::{dotenv, pm2, runtimes};
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct AppConfigRequest {
    pub command: Option<String>,
    pub workdir: Option<String>,
    /// New content for the site's `.env`. Left alone when omitted.
    pub env_text: Option<String>,
    pub enabled: bool,
    /// `systemd` or `pm2`. Keeps the current manager when omitted.
    pub manager: Option<String>,
    pub pm2: Option<Pm2Options>,
    /// Confirms taking over a PM2 daemon that was started by hand, which restarts its apps.
    #[serde(default)]
    pub adopt: bool,
}

/// Store new `.env` text. Sites without a home have no file, so theirs stays in the database.
fn save_env_text(site: &mut Site, text: &str) -> Result<Vec<String>, ApiError> {
    if text.len() as u64 > dotenv::MAX_ENV_BYTES {
        return Err(ApiError::BadRequest(format!(
            "Environment is too large (max {} KB)",
            dotenv::MAX_ENV_BYTES / 1024
        )));
    }
    let parsed = dotenv::parse(text);
    if site.home_dir.is_some() {
        let exists = dotenv::path_for(site).is_some_and(|p| p.symlink_metadata().is_ok());
        if exists || !text.trim().is_empty() {
            dotenv::write_site(site, text).map_err(ApiError::BadRequest)?;
        }
        // Whatever the database held is in the file now, or was deleted from the box.
        site.app_env = "{}".into();
    } else {
        site.app_env = serde_json::to_string(&parsed.vars).map_err(ApiError::internal)?;
    }
    Ok(parsed.warnings)
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
    let config = state.config.clone();
    let actor = user.clone();
    let (site, warnings, needs_pm2) = state
        .db(move |conn| {
            let previous = require_site(conn, &actor, id)?;
            let mut site = previous.clone();
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
            site.app_enabled = p.enabled;

            if let Some(m) = p.manager.as_deref() {
                match m {
                    MANAGER_SYSTEMD => {}
                    MANAGER_PM2 => {
                        if site.kind() != Some(SiteType::Nodejs) || site.home_dir.is_none() {
                            return Err(ApiError::BadRequest("PM2 is only available for Node.js sites".into()));
                        }
                    }
                    _ => return Err(ApiError::BadRequest("Process manager must be systemd or pm2".into())),
                }
                site.app_manager = m.to_string();
            }
            if site.uses_pm2() {
                let options = p.pm2.clone().unwrap_or_else(|| site.pm2_options());
                let options = pm2::validate_options(
                    &options,
                    site.app_command.as_deref(),
                    pm2::detect_ecosystem(&site).is_some(),
                )
                .map_err(ApiError::BadRequest)?;
                site.app_pm2 = serde_json::to_string(&options).map_err(ApiError::internal)?;
            }
            if p.enabled && !apps::has_start(&site) {
                return Err(ApiError::BadRequest(
                    "Set a start command before enabling the app".into(),
                ));
            }

            let needs_pm2 = site.uses_pm2() && !pm2::installed();
            // Refuse before anything changes, and let the UI ask.
            let foreign = site.uses_pm2() && !needs_pm2 && pm2::foreign_daemon(&config, &site);
            if foreign && !p.adopt {
                return Err(ApiError::Conflict(
                    "A PM2 daemon started by hand is running for this site. Taking it over restarts its apps.".into(),
                ));
            }

            let warnings = match p.env_text.as_deref() {
                Some(text) => save_env_text(&mut site, text)?,
                None => Vec::new(),
            };

            let switched = previous.app_manager != site.app_manager;
            if switched {
                apps::stop_unit(&site.domain);
            }
            let changed = switched
                || previous.app_command != site.app_command
                || previous.app_workdir != site.app_workdir
                || previous.app_pm2 != site.app_pm2;
            if needs_pm2 {
                // Installing takes a while, so a job does it and then applies the settings.
                db::save_site(conn, &site)?;
            } else {
                if foreign {
                    pm2::adopt(&site).map_err(ApiError::Unprocessable)?;
                }
                let applied = if changed {
                    apps::apply_fresh(&config, &site)
                } else {
                    apps::apply(&config, &site)
                };
                // The settings and `.env` are saved either way, so a failed start can be retried.
                db::save_site(conn, &site)?;
                applied.map_err(ApiError::Unprocessable)?;
            }
            audit::record(conn, &actor, "app.configure", Some(&site.domain), None);
            Ok((site, warnings, needs_pm2))
        })
        .await?;

    let mut job_id = None;
    if needs_pm2 {
        let config = state.config.clone();
        let s = site.clone();
        job_id = Some(
            crate::jobs::spawn(
                &state.pool,
                "runtime.pm2",
                Some(&site.domain),
                Some(user.id),
                move |log| {
                    runtimes::ensure_nodejs(&config, &|l| log.line(l))?;
                    pm2::ensure(&config, &|l| log.line(l))?;
                    apps::apply_fresh(&config, &s)
                },
            )
            .map_err(ApiError::internal)?,
        );
    }
    let mut v = serde_json::to_value(&site).map_err(ApiError::internal)?;
    v["env_warnings"] = json!(warnings);
    v["job_id"] = json!(job_id);
    Ok(Json(v))
}

/// The contents of the environment box: the `.env` file plus keys only the database has.
pub async fn get_env(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            if !site.kind().is_some_and(|k| k.has_app()) {
                return Err(ApiError::BadRequest("This site type has no managed app".into()));
            }
            let view = dotenv::view(&site).map_err(ApiError::BadRequest)?;
            let mut v = serde_json::to_value(&view).map_err(ApiError::internal)?;
            v["pending"] = json!(apps::env_pending(&config, &site));
            Ok(v)
        })
        .await?;
    Ok(Json(out))
}

pub async fn app_action(
    Path((id, action)): Path<(i64, String)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let act = match action.as_str() {
        "start" => Some(AppAction::Start),
        "stop" => Some(AppAction::Stop),
        "restart" => Some(AppAction::Restart),
        "reload" => Some(AppAction::Reload),
        "flush" => None,
        _ => return Err(ApiError::NotFound("Action")),
    };
    let config = state.config.clone();
    let status = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let Some(act) = act else {
                if !site.uses_pm2() {
                    return Err(ApiError::BadRequest(
                        "Only PM2 apps have log files to clear; systemd apps log to the journal".into(),
                    ));
                }
                pm2::flush_logs(&site).map_err(ApiError::Unprocessable)?;
                audit::record(conn, &user, "app.flush", Some(&site.domain), None);
                return Ok(apps::status(&config, &site));
            };
            if !apps::has_start(&site) {
                return Err(ApiError::BadRequest("Configure a start command first".into()));
            }
            if !site.is_active && !matches!(act, AppAction::Stop) {
                return Err(ApiError::BadRequest("Enable the site before starting its app".into()));
            }
            apps::act(&config, &site, act).map_err(ApiError::Unprocessable)?;
            audit::record(conn, &user, &format!("app.{action}"), Some(&site.domain), None);
            Ok(apps::status(&config, &site))
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
            apps::logs(&site, lines).map_err(ApiError::Unprocessable)
        })
        .await?;
    Ok(Json(json!({ "logs": logs })))
}

/// Start a background job on a site's app, after making sure Node.js is there.
async fn app_job<F>(state: SharedState, user: AuthUser, id: i64, kind: &'static str, work: F) -> ApiResult<i64>
where
    F: FnOnce(&Config, &Site, &JobLog) -> Result<(), String> + Send + 'static,
{
    let actor = user.clone();
    let site = state
        .db(move |conn| {
            let site = require_site(conn, &actor, id)?;
            audit::record(conn, &actor, kind, Some(&site.domain), None);
            Ok(site)
        })
        .await?;
    if site.home_dir.is_none() {
        return Err(ApiError::BadRequest("This site has no Linux user".into()));
    }
    let domain = site.domain.clone();
    let config = state.config.clone();
    crate::jobs::spawn(&state.pool, kind, Some(&domain), Some(user.id), move |log| {
        if site.kind() == Some(SiteType::Nodejs) {
            runtimes::ensure_nodejs(&config, &|l| log.line(l))?;
        }
        work(&config, &site, log)
    })
    .map_err(ApiError::internal)
}

#[derive(Deserialize)]
pub struct InstallQuery {
    /// Install even though the project looks like a prebuilt deploy.
    #[serde(default)]
    pub force: bool,
}

pub async fn install_dependencies(
    Path(id): Path<i64>,
    Query(q): Query<InstallQuery>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let job_id = app_job(state, user, id, "app.install", move |config, site, log| {
        apps::install_dependencies(site, log, q.force)?;
        apps::restart_if_down(config, site, log)
    })
    .await?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn build_app(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let job_id = app_job(state, user, id, "app.build", |_, site, log| apps::build(site, log)).await?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn deploy_app(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let job_id = app_job(state, user, id, "app.deploy", apps::deploy).await?;
    Ok(Json(json!({ "job_id": job_id })))
}
