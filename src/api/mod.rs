pub mod admin_handlers;
pub mod alert_handlers;
pub mod app_handlers;
pub mod auth_handlers;
pub mod backup_handlers;
pub mod cron_handlers;
pub mod database_handlers;
pub mod docker_handlers;
pub mod download;
pub mod error;
pub mod file_handlers;
pub mod firewall_handlers;
pub mod service_handlers;
pub mod site_handlers;
pub mod ssh_handlers;
pub mod system_handlers;
pub mod user_handlers;

#[cfg(test)]
mod tests;

use crate::state::SharedState;
use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, HeaderValue, Method},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, patch, post, put},
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
        .route("/auth/login/mfa", post(auth_handlers::login_mfa))
        .route("/auth/email", post(auth_handlers::change_email))
        .route("/auth/2fa/setup", post(auth_handlers::totp_setup))
        .route("/auth/2fa/enable", post(auth_handlers::totp_enable))
        .route("/auth/2fa/disable", post(auth_handlers::totp_disable))
        .route("/auth/2fa/recovery-codes", post(auth_handlers::totp_recovery_codes))
        // Users
        .route(
            "/users",
            get(user_handlers::list_users).post(user_handlers::create_user),
        )
        .route(
            "/users/:id",
            put(user_handlers::update_user).delete(user_handlers::delete_user),
        )
        .route("/users/:id/password", post(user_handlers::reset_password))
        .route("/users/:id/2fa", delete(user_handlers::reset_2fa))
        // Jobs & audit log
        .route("/jobs", get(admin_handlers::list_jobs))
        .route("/jobs/:id", get(admin_handlers::get_job))
        .route("/events", get(admin_handlers::list_events))
        // System
        .route("/system/metrics", get(system_handlers::get_system_metrics))
        // Sites
        .route(
            "/sites",
            get(site_handlers::get_sites).post(site_handlers::create_new_site),
        )
        .route(
            "/sites/:id",
            get(site_handlers::get_site)
                .patch(site_handlers::update_site)
                .delete(site_handlers::delete_existing_site),
        )
        .route(
            "/sites/:id/ssl",
            post(site_handlers::setup_site_ssl).delete(site_handlers::remove_site_ssl),
        )
        .route("/sites/:id/ssl/renew", post(site_handlers::renew_site_ssl))
        .route("/sites/:id/state", post(site_handlers::set_site_state))
        .route("/sites/:id/logs", get(site_handlers::get_site_logs))
        .route("/sites/:id/vhost", get(site_handlers::get_site_vhost))
        .route("/sites/:id/directives", put(site_handlers::set_site_directives))
        .route("/sites/:id/basic-auth", put(site_handlers::set_basic_auth))
        .route("/sites/:id/basic-auth/users", post(site_handlers::add_basic_auth_user))
        .route(
            "/sites/:id/basic-auth/users/:uid",
            delete(site_handlers::delete_basic_auth_user),
        )
        // Site apps
        .route("/sites/:id/app", put(app_handlers::update_app))
        .route("/sites/:id/app/env", get(app_handlers::get_env))
        .route("/sites/:id/app/logs", get(app_handlers::app_logs))
        .route("/sites/:id/app/install", post(app_handlers::install_dependencies))
        .route("/sites/:id/app/build", post(app_handlers::build_app))
        .route("/sites/:id/app/deploy", post(app_handlers::deploy_app))
        .route("/sites/:id/app/:action", post(app_handlers::app_action))
        // SSH / SFTP users
        .route(
            "/sites/:id/ssh-users",
            get(ssh_handlers::list_ssh_users).post(ssh_handlers::create_ssh_user),
        )
        .route(
            "/sites/:id/ssh-users/:uid",
            patch(ssh_handlers::update_ssh_user).delete(ssh_handlers::delete_ssh_user),
        )
        .route(
            "/sites/:id/ssh-users/:uid/password",
            post(ssh_handlers::set_ssh_password),
        )
        .route("/sites/:id/ssh-users/:uid/keys", post(ssh_handlers::add_ssh_key))
        .route(
            "/sites/:id/ssh-users/:uid/keys/:kid",
            delete(ssh_handlers::delete_ssh_key),
        )
        // Databases
        .route("/databases/engines", get(database_handlers::list_engines))
        .route(
            "/sites/:id/databases",
            get(database_handlers::list_site_databases).post(database_handlers::create_database),
        )
        .route("/databases/:id", delete(database_handlers::delete_database))
        .route("/databases/:id/users", post(database_handlers::add_database_user))
        .route(
            "/databases/:id/users/:username",
            delete(database_handlers::delete_database_user),
        )
        .route(
            "/databases/:id/users/:username/password",
            post(database_handlers::set_database_password),
        )
        .route("/databases/:id/export", get(database_handlers::export_database))
        .route(
            "/databases/:id/import",
            post(database_handlers::import_database).layer(database_handlers::upload_limit()),
        )
        // File manager
        .route("/sites/:id/files", get(file_handlers::list))
        .route(
            "/sites/:id/files/content",
            get(file_handlers::read)
                .put(file_handlers::write)
                .layer(file_handlers::edit_limit()),
        )
        .route("/sites/:id/files/op", post(file_handlers::op))
        .route("/sites/:id/files/download", get(file_handlers::download))
        .route(
            "/sites/:id/files/upload",
            post(file_handlers::upload).layer(file_handlers::upload_limit()),
        )
        // Backups
        .route(
            "/sites/:id/backups",
            get(backup_handlers::list_site_backups).post(backup_handlers::create_site_backup),
        )
        .route("/sites/:id/backups/policy", put(backup_handlers::set_backup_policy))
        .route("/backups/:id", delete(backup_handlers::delete_backup))
        .route("/backups/:id/download", get(backup_handlers::download_backup))
        .route("/backups/:id/restore", post(backup_handlers::restore_backup))
        .route(
            "/backups/panel",
            get(backup_handlers::list_panel_backups).post(backup_handlers::create_panel_backup),
        )
        .route(
            "/backups/remote",
            get(backup_handlers::get_remote)
                .put(backup_handlers::set_remote)
                .delete(backup_handlers::delete_remote),
        )
        // Services & updates
        .route("/services", get(service_handlers::list_services))
        .route("/services/:name/logs", get(service_handlers::service_logs))
        .route("/services/:name/:action", post(service_handlers::service_action))
        .route("/system/info", get(service_handlers::system_info))
        .route("/system/updates", get(service_handlers::get_updates))
        .route("/system/updates/refresh", post(service_handlers::refresh_updates))
        .route("/system/updates/upgrade", post(service_handlers::upgrade_all))
        .route("/system/reboot", post(service_handlers::reboot))
        // Docker
        .route("/docker/status", get(docker_handlers::get_docker_status))
        .route(
            "/docker/containers",
            get(docker_handlers::list_docker_containers).post(docker_handlers::create_container),
        )
        .route("/docker/stats", get(docker_handlers::docker_stats))
        .route(
            "/docker/containers/:id",
            delete(docker_handlers::remove_docker_container),
        )
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
        .route(
            "/docker/images",
            get(docker_handlers::list_images).post(docker_handlers::pull_image),
        )
        .route("/docker/images/prune", post(docker_handlers::prune_images))
        .route("/docker/images/*id", delete(docker_handlers::remove_image))
        .route("/docker/stacks", get(docker_handlers::list_stacks))
        .route(
            "/docker/stacks/:name",
            get(docker_handlers::get_stack).put(docker_handlers::save_stack),
        )
        .route("/docker/stacks/:name/logs", get(docker_handlers::stack_logs))
        .route("/docker/stacks/:name/:action", post(docker_handlers::stack_action))
        // Alerts & panel certificate
        .route("/alerts", get(alert_handlers::get_alerts))
        .route("/alerts/rules", put(alert_handlers::set_rules))
        .route("/alerts/channels", post(alert_handlers::create_channel))
        .route(
            "/alerts/channels/:id",
            delete(alert_handlers::delete_channel).patch(alert_handlers::set_channel_enabled),
        )
        .route("/alerts/channels/:id/test", post(alert_handlers::test_channel))
        .route(
            "/settings/panel-cert",
            get(alert_handlers::get_panel_cert)
                .post(alert_handlers::issue_panel_cert)
                .delete(alert_handlers::remove_panel_cert),
        )
        // Firewall
        .route(
            "/firewall/rules",
            get(firewall_handlers::get_rules).post(firewall_handlers::add_rule),
        )
        .route("/firewall/rules/:id", delete(firewall_handlers::delete_rule))
        .route("/firewall/status", get(firewall_handlers::firewall_status))
        .route(
            "/fail2ban",
            get(firewall_handlers::get_fail2ban).put(firewall_handlers::set_fail2ban),
        )
        .route("/fail2ban/ban", post(firewall_handlers::fail2ban_ban))
        .route("/fail2ban/unban", post(firewall_handlers::fail2ban_unban))
        // Cron
        .route(
            "/cron/jobs",
            get(cron_handlers::get_cron_jobs).post(cron_handlers::add_cron_job),
        )
        .route(
            "/cron/jobs/:id",
            put(cron_handlers::update_cron_job).delete(cron_handlers::remove_cron_job),
        )
        .route("/cron/jobs/:id/run", post(cron_handlers::run_cron_job))
        .route("/cron/jobs/:id/runs", get(cron_handlers::cron_runs))
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
            // HTTP/2 (what browsers negotiate over TLS) has no Host header; the
            // host travels in the :authority pseudo-header, i.e. the request URI.
            let host = h
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| req.uri().authority().map(|a| a.as_str()))
                .unwrap_or("");
            let origin_host = origin.split_once("://").map(|(_, rest)| rest).unwrap_or("");
            if host.is_empty() || !origin_host.eq_ignore_ascii_case(host) {
                return denied();
            }
        }
    }
    Ok(next.run(req).await)
}
