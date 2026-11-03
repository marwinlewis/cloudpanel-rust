use crate::api::error::{ApiError, ApiResult};
use crate::auth::AdminUser;
use crate::db::{create_cron_job, delete_cron_job, find_site_by_id, list_cron_jobs};
use crate::services::CronService;
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateCronRequest {
    pub site_id: Option<i64>,
    pub schedule: String,
    pub command: String,
    pub user: Option<String>,
}

pub async fn get_cron_jobs(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    Ok(Json(state.db(|conn| Ok(list_cron_jobs(conn)?)).await?))
}

pub async fn add_cron_job(
    _admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateCronRequest>,
) -> ApiResult<impl IntoResponse> {
    let schedule = validate::cron_schedule(&p.schedule).map_err(ApiError::BadRequest)?;
    let command = validate::cron_command(&p.command).map_err(ApiError::BadRequest)?;
    let user = validate::system_user(p.user.as_deref().unwrap_or("root")).map_err(ApiError::BadRequest)?;
    if !CronService::user_exists(&user) {
        return Err(ApiError::BadRequest(format!("System user '{user}' does not exist")));
    }

    let cron_file = state.config.cron_file.clone();
    let id = state
        .db(move |conn| {
            if let Some(site_id) = p.site_id {
                find_site_by_id(conn, site_id)?.ok_or(ApiError::NotFound("Site"))?;
            }
            let tx = conn.unchecked_transaction()?;
            let id = create_cron_job(&tx, p.site_id, &schedule, &command, &user)?;
            CronService::apply(&cron_file, &list_cron_jobs(&tx)?).map_err(ApiError::internal)?;
            tx.commit()?;
            Ok(id)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

pub async fn remove_cron_job(
    Path(id): Path<i64>,
    _admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let cron_file = state.config.cron_file.clone();
    state
        .db(move |conn| {
            let tx = conn.unchecked_transaction()?;
            if !delete_cron_job(&tx, id)? {
                return Err(ApiError::NotFound("Cron job"));
            }
            CronService::apply(&cron_file, &list_cron_jobs(&tx)?).map_err(ApiError::internal)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
