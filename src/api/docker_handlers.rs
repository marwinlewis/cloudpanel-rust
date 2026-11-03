use crate::api::error::{ApiError, ApiResult};
use crate::auth::AdminUser;
use crate::services::sites::{provision, SiteInput};
use crate::services::{ContainerAction, DockerService};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LogsQuery {
    pub tail: Option<usize>,
}

#[derive(Deserialize)]
pub struct DockerProxyRequest {
    pub domain: String,
    pub host_port: u16,
    #[serde(default)]
    pub include_www: bool,
}

fn container(id: &str) -> ApiResult<String> {
    validate::container_id(id).map_err(ApiError::BadRequest)
}

pub async fn get_docker_status(_admin: AdminUser) -> ApiResult<impl IntoResponse> {
    let available = blocking(|| Ok(DockerService::is_available())).await?;
    Ok(Json(serde_json::json!({ "available": available })))
}

pub async fn list_docker_containers(_admin: AdminUser) -> ApiResult<impl IntoResponse> {
    let containers = blocking(|| DockerService::list_containers().map_err(ApiError::Unprocessable)).await?;
    Ok(Json(containers))
}

async fn act(id: String, action: ContainerAction) -> ApiResult<impl IntoResponse> {
    let id = container(&id)?;
    blocking(move || DockerService::act(&id, action).map_err(ApiError::Unprocessable)).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn start_docker_container(Path(id): Path<String>, _admin: AdminUser) -> ApiResult<impl IntoResponse> {
    act(id, ContainerAction::Start).await
}

pub async fn stop_docker_container(Path(id): Path<String>, _admin: AdminUser) -> ApiResult<impl IntoResponse> {
    act(id, ContainerAction::Stop).await
}

pub async fn restart_docker_container(Path(id): Path<String>, _admin: AdminUser) -> ApiResult<impl IntoResponse> {
    act(id, ContainerAction::Restart).await
}

pub async fn get_docker_logs(
    Path(id): Path<String>,
    Query(query): Query<LogsQuery>,
    _admin: AdminUser,
) -> ApiResult<impl IntoResponse> {
    let id = container(&id)?;
    let tail = query.tail.unwrap_or(200).clamp(1, 5000);
    let logs = blocking(move || DockerService::logs(&id, tail).map_err(ApiError::Unprocessable)).await?;
    Ok(Json(serde_json::json!({ "logs": logs })))
}

/// Create an nginx reverse-proxy site in front of a container's published port.
pub async fn proxy_container_to_site(
    Path(id): Path<String>,
    _admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<DockerProxyRequest>,
) -> ApiResult<impl IntoResponse> {
    container(&id)?;
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            provision(
                &config,
                conn,
                SiteInput {
                    domain: p.domain,
                    site_type: "docker_proxy".into(),
                    target_port: Some(p.host_port),
                    document_root: None,
                    system_user: None,
                    include_www: p.include_www,
                },
            )
        })
        .await?;
    Ok((StatusCode::CREATED, Json(site)))
}
