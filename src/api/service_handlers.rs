//! Services, package updates, reboot and host info (admin only).

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AdminUser;
use crate::db;
use crate::services::apps;
use crate::services::system::{self, Action, Upgradable};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const UPDATES_SETTING: &str = "apt_upgradable";

#[derive(Serialize, Deserialize, Default)]
struct UpdateCache {
    checked_at: Option<chrono::DateTime<chrono::Utc>>,
    packages: Vec<Upgradable>,
}

pub async fn list_services(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let apps_units = state
        .db(|conn| {
            Ok(db::list_sites(conn)?
                .into_iter()
                .filter(|s| s.app_command.is_some())
                .map(|s| (apps::unit_name(&s.domain), s.domain))
                .collect::<Vec<_>>())
        })
        .await?;
    let list = blocking(move || Ok(system::list(&apps_units))).await?;
    Ok(Json(list))
}

pub async fn service_action(
    Path((name, action)): Path<(String, String)>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let name = validate::service_name(&name).map_err(ApiError::BadRequest)?;
    let act = Action::parse(&action).ok_or(ApiError::NotFound("Action"))?;
    let n = name.clone();
    blocking(move || system::act(&n, act).map_err(ApiError::Unprocessable)).await?;
    let status = {
        let n = name.clone();
        blocking(move || Ok(system::status(&n, ""))).await?
    };
    state
        .db(move |conn| {
            audit::record(conn, &admin.0, &format!("service.{}", act.as_str()), Some(&name), None);
            Ok(())
        })
        .await?;
    Ok(Json(status))
}

#[derive(Deserialize)]
pub struct LinesQuery {
    pub lines: Option<usize>,
}

pub async fn service_logs(
    Path(name): Path<String>,
    Query(q): Query<LinesQuery>,
    _admin: AdminUser,
) -> ApiResult<impl IntoResponse> {
    let name = validate::service_name(&name).map_err(ApiError::BadRequest)?;
    let lines = q.lines.unwrap_or(300).clamp(10, 5000);
    let logs = blocking(move || apps::journal(&name, lines).map_err(ApiError::Unprocessable)).await?;
    Ok(Json(json!({ "logs": logs })))
}

pub async fn get_updates(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let cache: UpdateCache = state.db(|conn| Ok(db::get_json(conn, UPDATES_SETTING)?)).await?;
    let reboot = blocking(|| Ok(system::reboot_required())).await?;
    Ok(Json(json!({
        "checked_at": cache.checked_at,
        "packages": cache.packages,
        "security_count": cache.packages.iter().filter(|p| p.security).count(),
        "reboot_required": reboot,
    })))
}

pub async fn refresh_updates(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let pool = state.pool.clone();
    let job_id = crate::jobs::spawn(&state.pool, "updates.refresh", None, Some(admin.0.id), move |log| {
        let packages = system::refresh_updates(log)?;
        let conn = pool.get().map_err(|e| e.to_string())?;
        db::set_json(
            &conn,
            UPDATES_SETTING,
            &UpdateCache {
                checked_at: Some(chrono::Utc::now()),
                packages,
            },
        )
        .map_err(|e| e.to_string())
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn upgrade_all(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let pool = state.pool.clone();
    let actor = admin.0.clone();
    state
        .db(move |conn| {
            audit::record(conn, &actor, "updates.upgrade", None, None);
            Ok(())
        })
        .await?;
    let job_id = crate::jobs::spawn(&state.pool, "updates.upgrade", None, Some(admin.0.id), move |log| {
        system::upgrade_all(log)?;
        let packages = system::list_upgradable().unwrap_or_default();
        if let Ok(conn) = pool.get() {
            let _ = db::set_json(
                &conn,
                UPDATES_SETTING,
                &UpdateCache {
                    checked_at: Some(chrono::Utc::now()),
                    packages,
                },
            );
        }
        if system::reboot_required() {
            log.line("A reboot is required to finish installing updates.");
        }
        Ok(())
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn reboot(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            audit::record(conn, &admin.0, "system.reboot", None, None);
            Ok(())
        })
        .await?;
    // Reply first, then reboot.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if let Err(e) = tokio::task::spawn_blocking(system::reboot).await.unwrap_or(Ok(())) {
            tracing::error!("reboot failed: {e}");
        }
    });
    Ok(Json(
        json!({ "message": "Rebooting. The panel will be back in a minute or two." }),
    ))
}

pub async fn system_info(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let cache: UpdateCache = state.db(|conn| Ok(db::get_json(conn, UPDATES_SETTING)?)).await?;
    let (v4, v6) = blocking(|| Ok(system::public_ips())).await?;
    let reboot = blocking(|| Ok(system::reboot_required())).await?;
    Ok(Json(json!({
        "public_ipv4": v4,
        "public_ipv6": v6,
        "pending_updates": cache.packages.len(),
        "security_updates": cache.packages.iter().filter(|p| p.security).count(),
        "updates_checked_at": cache.checked_at,
        "reboot_required": reboot,
        "panel_version": env!("CARGO_PKG_VERSION"),
    })))
}
