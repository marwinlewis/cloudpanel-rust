pub mod auth_handlers;
pub mod cron_handlers;
pub mod docker_handlers;
pub mod error;
pub mod firewall_handlers;
pub mod site_handlers;
pub mod system_handlers;

use crate::state::SharedState;
use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, HeaderValue, Method},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Router,
};
use error::ApiError;
use tower_http::set_header::SetResponseHeaderLayer;

pub const CSRF_HEADER: &str = "x-requested-with";
pub const CSRF_VALUE: &str = "cloudpanel";

pub fn create_api_router(state: SharedState) -> Router {
    let api = Router::new()
        // Auth
        .route("/auth/login", post(auth_handlers::login))
        .route("/auth/me", get(auth_handlers::me))
        .route("/auth/logout", post(auth_handlers::logout))
        .route("/auth/logout-all", post(auth_handlers::logout_all))
        .route("/auth/password", post(auth_handlers::change_password))
        // System
        .route("/system/metrics", get(system_handlers::get_system_metrics))
        // Sites
        .route(
            "/sites",
            get(site_handlers::get_sites).post(site_handlers::create_new_site),
        )
        .route(
            "/sites/:id",
            get(site_handlers::get_site).delete(site_handlers::delete_existing_site),
        )
        .route("/sites/:id/ssl", post(site_handlers::setup_site_ssl))
        // Docker
        .route("/docker/status", get(docker_handlers::get_docker_status))
        .route("/docker/containers", get(docker_handlers::list_docker_containers))
        .route(
            "/docker/containers/:id/start",
            post(docker_handlers::start_docker_container),
        )
        .route(
            "/docker/containers/:id/stop",
            post(docker_handlers::stop_docker_container),
        )
        .route(
            "/docker/containers/:id/restart",
            post(docker_handlers::restart_docker_container),
        )
        .route("/docker/containers/:id/logs", get(docker_handlers::get_docker_logs))
        .route(
            "/docker/containers/:id/proxy-site",
            post(docker_handlers::proxy_container_to_site),
        )
        // Firewall
        .route(
            "/firewall/rules",
            get(firewall_handlers::get_rules).post(firewall_handlers::add_rule),
        )
        .route("/firewall/rules/:id", delete(firewall_handlers::delete_rule))
        // Cron
        .route(
            "/cron/jobs",
            get(cron_handlers::get_cron_jobs).post(cron_handlers::add_cron_job),
        )
        .route("/cron/jobs/:id", delete(cron_handlers::remove_cron_job))
        .fallback(|| async { ApiError::NotFound("Endpoint") })
        .layer(middleware::from_fn(csrf_guard))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state);

    Router::new().nest("/api", api)
}

/// CSRF protection for cookie-authenticated, state-changing requests. Browsers can't
/// send the custom header cross-origin without a CORS preflight (which we never allow),
/// and Origin / Sec-Fetch-Site are checked as a second layer.
async fn csrf_guard(req: Request, next: Next) -> Result<Response, ApiError> {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let h = req.headers();
    let bearer = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));

    if !safe && !bearer {
        let denied = || Err(ApiError::BadRequest("Cross-site request blocked".into()));
        if h.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some(CSRF_VALUE) {
            return denied();
        }
        if let Some(site) = h.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
            if site != "same-origin" && site != "none" {
                return denied();
            }
        }
        if let Some(origin) = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let host = h.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
            let origin_host = origin.split_once("://").map(|(_, rest)| rest).unwrap_or("");
            if host.is_empty() || origin_host != host {
                return denied();
            }
        }
    }
    Ok(next.run(req).await)
}
