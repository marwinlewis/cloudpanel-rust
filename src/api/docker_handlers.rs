use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AdminUser;
use crate::services::docker::{self as dk, ContainerAction, DockerService, RunSpec};
use crate::services::sites::{provision, www_choice, SiteInput};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct LogsQuery {
    pub tail: Option<usize>,
}

#[derive(Deserialize)]
pub struct DockerProxyRequest {
    pub domain: String,
    pub host_port: u16,
    pub include_www: Option<bool>,
    pub www_redirect: Option<bool>,
}

#[derive(Deserialize)]
pub struct ForceQuery {
    #[serde(default)]
    pub force: bool,
}

fn container(id: &str) -> ApiResult<String> {
    validate::container_id(id).map_err(ApiError::BadRequest)
}

async fn audit_admin(state: &SharedState, admin: &AdminUser, action: String, target: String) {
    let a = admin.0.clone();
    let _ = state
        .db(move |conn| {
            audit::record(conn, &a, &action, Some(&target), None);
            Ok(())
        })
        .await;
}

pub async fn get_docker_status(_admin: AdminUser) -> ApiResult<impl IntoResponse> {
    let available = blocking(|| Ok(DockerService::is_available())).await?;
    Ok(Json(json!({ "available": available })))
}

pub async fn list_docker_containers(_admin: AdminUser) -> ApiResult<impl IntoResponse> {
    let containers = blocking(|| DockerService::list_containers().map_err(ApiError::Unprocessable)).await?;
    Ok(Json(containers))
}

pub async fn docker_stats(_admin: AdminUser) -> ApiResult<impl IntoResponse> {
    let stats = blocking(|| DockerService::stats().map_err(ApiError::Unprocessable)).await?;
    Ok(Json(stats))
}

async fn act(
    state: SharedState,
    admin: AdminUser,
    id: String,
    action: ContainerAction,
) -> ApiResult<impl IntoResponse> {
    let id = container(&id)?;
    let cid = id.clone();
    blocking(move || DockerService::act(&cid, action).map_err(ApiError::Unprocessable)).await?;
    audit_admin(&state, &admin, format!("docker.{}", action.as_str()), id).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn start_docker_container(
    Path(id): Path<String>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    act(state, admin, id, ContainerAction::Start).await
}

pub async fn stop_docker_container(
    Path(id): Path<String>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    act(state, admin, id, ContainerAction::Stop).await
}

pub async fn restart_docker_container(
    Path(id): Path<String>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    act(state, admin, id, ContainerAction::Restart).await
}

pub async fn remove_docker_container(
    Path(id): Path<String>,
    Query(q): Query<ForceQuery>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let id = container(&id)?;
    let cid = id.clone();
    blocking(move || DockerService::remove_container(&cid, q.force).map_err(ApiError::Unprocessable)).await?;
    audit_admin(&state, &admin, "docker.remove".into(), id).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn get_docker_logs(
    Path(id): Path<String>,
    Query(query): Query<LogsQuery>,
    _admin: AdminUser,
) -> ApiResult<impl IntoResponse> {
    let id = container(&id)?;
    let tail = query.tail.unwrap_or(200).clamp(1, 5000);
    let logs = blocking(move || DockerService::logs(&id, tail).map_err(ApiError::Unprocessable)).await?;
    Ok(Json(json!({ "logs": logs })))
}

pub async fn create_container(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(spec): Json<RunSpec>,
) -> ApiResult<impl IntoResponse> {
    let roots = vec![state.config.home_dir.clone(), state.config.stacks_dir.clone()];
    let args = spec.to_args(&roots).map_err(ApiError::BadRequest)?;
    audit_admin(&state, &admin, "docker.create".into(), spec.name.clone()).await;
    let job_id = crate::jobs::spawn(
        &state.pool,
        "docker.run",
        Some(&spec.name),
        Some(admin.0.id),
        move |log| DockerService::run(&args, log),
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

/// Create an nginx reverse-proxy site in front of a container's published port.
pub async fn proxy_container_to_site(
    Path(id): Path<String>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<DockerProxyRequest>,
) -> ApiResult<impl IntoResponse> {
    container(&id)?;
    let config = state.config.clone();
    let (include_www, www_redirect) = www_choice(p.include_www, p.www_redirect);
    let site = state
        .db(move |conn| {
            let site = provision(
                &config,
                conn,
                SiteInput {
                    domain: p.domain,
                    site_type: "docker_proxy".into(),
                    target_port: Some(p.host_port),
                    document_root: None,
                    system_user: None,
                    include_www,
                    www_redirect,
                    app_command: None,
                    app_manager: None,
                    create_user: false,
                },
            )?;
            audit::record(conn, &admin.0, "site.create", Some(&site.domain), Some("docker_proxy"));
            Ok(site)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(site)))
}

// ---------- Images ----------

pub async fn list_images(_admin: AdminUser) -> ApiResult<impl IntoResponse> {
    Ok(Json(
        blocking(|| DockerService::images().map_err(ApiError::Unprocessable)).await?,
    ))
}

#[derive(Deserialize)]
pub struct PullRequest {
    pub image: String,
}

pub async fn pull_image(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<PullRequest>,
) -> ApiResult<impl IntoResponse> {
    let image = validate::image_ref(&p.image).map_err(ApiError::BadRequest)?;
    audit_admin(&state, &admin, "docker.pull".into(), image.clone()).await;
    let img = image.clone();
    let job_id = crate::jobs::spawn(&state.pool, "docker.pull", Some(&image), Some(admin.0.id), move |log| {
        DockerService::pull(&img, log)
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn remove_image(
    Path(id): Path<String>,
    Query(q): Query<ForceQuery>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let id = validate::image_ref(&id).map_err(ApiError::BadRequest)?;
    let iid = id.clone();
    blocking(move || DockerService::remove_image(&iid, q.force).map_err(ApiError::Unprocessable)).await?;
    audit_admin(&state, &admin, "docker.image_remove".into(), id).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn prune_images(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let out = blocking(|| DockerService::prune_images().map_err(ApiError::Unprocessable)).await?;
    audit_admin(&state, &admin, "docker.image_prune".into(), String::new()).await;
    Ok(Json(json!({ "output": out })))
}

// ---------- Compose stacks ----------

pub async fn list_stacks(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let root = state.config.stacks_dir.clone();
    Ok(Json(blocking(move || Ok(dk::list_stacks(&root))).await?))
}

pub async fn get_stack(
    Path(name): Path<String>,
    _admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let name = dk::stack_name(&name).map_err(ApiError::BadRequest)?;
    let root = state.config.stacks_dir.clone();
    let (compose, env) =
        blocking(move || dk::read_stack(&root, &name).map_err(|_| ApiError::NotFound("Stack"))).await?;
    Ok(Json(json!({ "compose": compose, "env": env })))
}

#[derive(Deserialize)]
pub struct StackRequest {
    pub compose: String,
    #[serde(default)]
    pub env: String,
}

pub async fn save_stack(
    Path(name): Path<String>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<StackRequest>,
) -> ApiResult<impl IntoResponse> {
    let name = dk::stack_name(&name).map_err(ApiError::BadRequest)?;
    let root = state.config.stacks_dir.clone();
    let n = name.clone();
    blocking(move || dk::save_stack(&root, &n, &p.compose, &p.env).map_err(ApiError::BadRequest)).await?;
    audit_admin(&state, &admin, "docker.stack_save".into(), name).await;
    Ok(Json(json!({ "message": "Stack saved" })))
}

pub async fn stack_action(
    Path((name, action)): Path<(String, String)>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let name = dk::stack_name(&name).map_err(ApiError::BadRequest)?;
    if !matches!(action.as_str(), "up" | "down" | "pull" | "restart" | "delete") {
        return Err(ApiError::NotFound("Action"));
    }
    let root = state.config.stacks_dir.clone();
    audit_admin(&state, &admin, format!("docker.stack_{action}"), name.clone()).await;
    let n = name.clone();
    let job_id = crate::jobs::spawn(&state.pool, "docker.stack", Some(&name), Some(admin.0.id), move |log| {
        if action == "delete" {
            dk::delete_stack(&root, &n, log)
        } else {
            dk::stack_action(&root, &n, &action, log)
        }
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn stack_logs(
    Path(name): Path<String>,
    Query(q): Query<LogsQuery>,
    _admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let name = dk::stack_name(&name).map_err(ApiError::BadRequest)?;
    let root = state.config.stacks_dir.clone();
    let tail = q.tail.unwrap_or(300).clamp(10, 5000);
    let logs = blocking(move || dk::stack_logs(&root, &name, tail).map_err(ApiError::Unprocessable)).await?;
    Ok(Json(json!({ "logs": logs })))
}
