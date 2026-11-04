//! Cron jobs. Admins manage every job; site managers manage jobs linked to their sites,
//! which always run as that site's user.

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AuthUser;
use crate::authz::require_site;
use crate::db::{self, CronInput};
use crate::services::cron::{execute, CronService};
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

#[derive(Deserialize)]
pub struct CronRequest {
    pub site_id: Option<i64>,
    pub name: Option<String>,
    pub schedule: String,
    pub command: String,
    pub user: Option<String>,
    #[serde(default = "yes")]
    pub is_active: bool,
}

fn yes() -> bool {
    true
}

/// (site_id, name, schedule, command, run-as user)
type Prepared = (Option<i64>, Option<String>, String, String, String);

/// Validate a request into stored values, enforcing site-manager rules.
fn prepare(
    conn: &Connection,
    user: &AuthUser,
    p: &CronRequest,
) -> ApiResult<Prepared> {
    let schedule = validate::cron_schedule(&p.schedule).map_err(ApiError::BadRequest)?;
    let command = validate::cron_command(&p.command).map_err(ApiError::BadRequest)?;
    let name = validate::short_text(p.name.as_deref(), 80).map_err(ApiError::BadRequest)?;
    let run_as = match p.site_id {
        Some(sid) => {
            let site = require_site(conn, user, sid)?;
            match p.user.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
                // Admins may pick another user for a site-linked job; site managers may not.
                Some(u) if user.is_admin() => u.to_string(),
                _ => site.system_user,
            }
        }
        None => {
            if !user.is_admin() {
                return Err(ApiError::BadRequest("Choose one of your sites for this job".into()));
            }
            p.user.clone().unwrap_or_else(|| "root".into())
        }
    };
    let run_as = validate::system_user(&run_as).map_err(ApiError::BadRequest)?;
    if !CronService::user_exists(&run_as) {
        return Err(ApiError::BadRequest(format!("System user '{run_as}' does not exist")));
    }
    Ok((p.site_id, name, schedule, command, run_as))
}

fn visible(conn: &Connection, user: &AuthUser) -> ApiResult<Vec<crate::db::models::CronJob>> {
    let all = db::list_cron_jobs(conn)?;
    if user.is_admin() {
        return Ok(all);
    }
    let mine = db::user_site_ids(conn, user.id)?;
    Ok(all
        .into_iter()
        .filter(|j| j.site_id.is_some_and(|s| mine.contains(&s)))
        .collect())
}

fn load(conn: &Connection, user: &AuthUser, id: i64) -> ApiResult<crate::db::models::CronJob> {
    visible(conn, user)?
        .into_iter()
        .find(|j| j.id == id)
        .ok_or(ApiError::NotFound("Cron job"))
}

pub async fn get_cron_jobs(user: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let out = state
        .db(move |conn| {
            let last = db::last_cron_runs(conn)?;
            let mut out = Vec::new();
            for j in visible(conn, &user)? {
                let mut v = serde_json::to_value(&j).map_err(ApiError::internal)?;
                if let Some((_, at, code)) = last.iter().find(|(id, _, _)| *id == j.id) {
                    v["last_run"] = json!({ "at": at, "exit_code": code });
                }
                out.push(v);
            }
            Ok(out)
        })
        .await?;
    Ok(Json(out))
}

pub async fn add_cron_job(
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<CronRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let id = state
        .db(move |conn| {
            let (site_id, name, schedule, command, run_as) = prepare(conn, &user, &p)?;
            let tx = conn.unchecked_transaction()?;
            let id = db::create_cron_job(
                &tx,
                &CronInput {
                    site_id,
                    name: name.as_deref(),
                    schedule: &schedule,
                    command: &command,
                    user: &run_as,
                    is_active: p.is_active,
                },
            )?;
            CronService::apply(&config, &db::list_cron_jobs(&tx)?).map_err(ApiError::internal)?;
            tx.commit()?;
            audit::record(
                conn,
                &user,
                "cron.create",
                None,
                Some(&format!("#{id} {schedule} as {run_as}")),
            );
            Ok(id)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

pub async fn update_cron_job(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<CronRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            load(conn, &user, id)?;
            let (site_id, name, schedule, command, run_as) = prepare(conn, &user, &p)?;
            let tx = conn.unchecked_transaction()?;
            db::update_cron_job(
                &tx,
                id,
                &CronInput {
                    site_id,
                    name: name.as_deref(),
                    schedule: &schedule,
                    command: &command,
                    user: &run_as,
                    is_active: p.is_active,
                },
            )?;
            CronService::apply(&config, &db::list_cron_jobs(&tx)?).map_err(ApiError::internal)?;
            tx.commit()?;
            audit::record(conn, &user, "cron.update", None, Some(&format!("#{id}")));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_cron_job(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            load(conn, &user, id)?;
            let tx = conn.unchecked_transaction()?;
            db::delete_cron_job(&tx, id)?;
            CronService::apply(&config, &db::list_cron_jobs(&tx)?).map_err(ApiError::internal)?;
            tx.commit()?;
            audit::record(conn, &user, "cron.delete", None, Some(&format!("#{id}")));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

/// Run a job immediately (5-minute limit) and return its output.
pub async fn run_cron_job(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let out = state
        .db(move |conn| {
            let job = load(conn, &user, id)?;
            audit::record(conn, &user, "cron.run", None, Some(&format!("#{id}")));
            let (code, output) = execute(conn, &job, Some(300));
            Ok(json!({ "exit_code": code, "output": output }))
        })
        .await?;
    Ok(Json(out))
}

pub async fn cron_runs(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let out = state
        .db(move |conn| {
            load(conn, &user, id)?;
            Ok(db::list_cron_runs(conn, id)?)
        })
        .await?;
    Ok(Json(out))
}
