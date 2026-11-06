use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::{AdminUser, AuthUser};
use crate::authz::{require_admin, require_site, visible_sites};
use crate::config::Config;
use crate::db::{self, models::Site, models::SiteType};
use crate::services::sites::{deprovision, provision, www_choice, SiteInput};
use crate::services::{apps, pm2, runtimes, NginxService, SslService};
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateSiteRequest {
    pub domain: String,
    pub site_type: String, // nodejs, python, static, docker_proxy, reverse_proxy
    pub target_port: Option<u16>,
    pub document_root: Option<String>,
    pub system_user: Option<String>,
    /// Handle www.<domain>. Defaults to on.
    pub include_www: Option<bool>,
    /// Redirect www to the naked domain rather than serving both. Defaults to on.
    pub www_redirect: Option<bool>,
    pub app_command: Option<String>,
    /// `systemd` or `pm2`. Node.js sites default to PM2.
    pub app_manager: Option<String>,
}

#[derive(Deserialize)]
pub struct SslRequest {
    pub email: Option<String>,
    pub custom_cert: Option<String>,
    pub custom_key: Option<String>,
}

/// Apply a changed site to nginx and persist it; restores the previous vhost on failure.
pub fn apply_site(config: &Config, conn: &Connection, previous: &Site, site: &Site) -> ApiResult<()> {
    if let Err(e) = NginxService::write_and_apply(config, site) {
        let _ = NginxService::write_and_apply(config, previous);
        return Err(ApiError::Unprocessable(e));
    }
    db::save_site(conn, site)?;
    Ok(())
}

pub async fn get_sites(user: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    Ok(Json(state.db(move |conn| visible_sites(conn, &user)).await?))
}

pub async fn create_new_site(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateSiteRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let admin_id = admin.0.id;
    let (include_www, www_redirect) = www_choice(p.include_www, p.www_redirect);
    let site = state
        .db(move |conn| {
            let site = provision(
                &config,
                conn,
                SiteInput {
                    domain: p.domain,
                    site_type: p.site_type,
                    target_port: p.target_port,
                    document_root: p.document_root,
                    system_user: p.system_user,
                    include_www,
                    www_redirect,
                    app_command: p.app_command,
                    app_manager: p.app_manager,
                    create_user: true,
                },
            )?;
            audit::record(conn, &admin.0, "site.create", Some(&site.domain), Some(&site.site_type));
            Ok(site)
        })
        .await?;
    // Node.js sites need a system-wide runtime (and PM2, if that runs the app); install what
    // is missing in the background and start the app once it's there.
    let mut runtime_job_id = None;
    let needs_pm2 = site.uses_pm2() && !pm2::installed() && runtimes::can_install(&state.config);
    if site.kind() == Some(SiteType::Nodejs) && (runtimes::node_needed(&state.config) || needs_pm2) {
        let config = state.config.clone();
        let s = site.clone();
        runtime_job_id = Some(
            crate::jobs::spawn(
                &state.pool,
                "runtime.nodejs",
                Some(&site.domain),
                Some(admin_id),
                move |log| {
                    runtimes::ensure_nodejs(&config, &|l| log.line(l))?;
                    if s.uses_pm2() {
                        pm2::ensure(&config, &|l| log.line(l))?;
                    }
                    if s.app_enabled && apps::has_start(&s) {
                        log.line(&format!("Starting {}", apps::unit_name(&s.domain)));
                        apps::apply(&config, &s)?;
                    }
                    Ok(())
                },
            )
            .map_err(ApiError::internal)?,
        );
    }
    let mut v = serde_json::to_value(&site).map_err(ApiError::internal)?;
    v["runtime_job_id"] = json!(runtime_job_id);
    Ok((StatusCode::CREATED, Json(v)))
}

pub async fn get_site(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let cert = site.ssl_cert_path.as_deref().and_then(SslService::cert_info);
            let app = site
                .kind()
                .filter(|k| k.has_app())
                .map(|_| apps::status(&config, &site));
            let mut v = serde_json::to_value(&site).map_err(ApiError::internal)?;
            v["certificate"] = json!(cert);
            v["certificate_covers_www"] = json!(NginxService::cert_covers_www(&site));
            if site.kind() == Some(SiteType::Nodejs) {
                v["pm2"] = json!(site.pm2_options());
                v["pm2_installed"] = json!(pm2::installed());
                v["ecosystem_file"] = json!(pm2::detect_ecosystem(&site));
                v["project"] = json!(apps::inspect_project(std::path::Path::new(&apps::workdir(&site))));
            }
            v["certificate_managed"] = json!(site.ssl_cert_path.as_deref().is_some_and(SslService::is_letsencrypt));
            v["app"] = json!(app);
            v["app_workdir_default"] = json!(apps::workdir(&Site {
                app_workdir: None,
                ..site.clone()
            }));
            v["basic_auth_users"] = json!(db::list_basic_auth_users(conn, id)?);
            Ok(v)
        })
        .await?;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct UpdateSiteRequest {
    pub target_port: Option<u16>,
    pub include_www: Option<bool>,
    pub www_redirect: Option<bool>,
    pub document_root: Option<String>,
    pub websocket: Option<bool>,
    pub max_body_mb: Option<i64>,
}

pub async fn update_site(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<UpdateSiteRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            let previous = require_site(conn, &user, id)?;
            let mut site = previous.clone();
            if let Some(port) = p.target_port {
                if site.site_type == "static" {
                    return Err(ApiError::BadRequest("Static sites have no app port".into()));
                }
                let port = validate::port(Some(port)).map_err(ApiError::BadRequest)?;
                if Some(port) == config.panel_port() {
                    return Err(ApiError::BadRequest(
                        "That port is used by the control panel itself".into(),
                    ));
                }
                site.target_port = Some(port);
            }
            if let Some(w) = p.include_www {
                if w && site.domain.starts_with("www.") {
                    return Err(ApiError::BadRequest("This domain already starts with www.".into()));
                }
                site.include_www = w;
            }
            if let Some(r) = p.www_redirect {
                site.www_redirect = r;
            }
            site.www_redirect = site.www_redirect && site.include_www;
            if let Some(ws) = p.websocket {
                site.websocket = ws;
            }
            if let Some(mb) = p.max_body_mb {
                if !(1..=10240).contains(&mb) {
                    return Err(ApiError::BadRequest(
                        "Upload limit must be between 1 and 10240 MB".into(),
                    ));
                }
                site.max_body_mb = mb;
            }
            if let Some(root) = p.document_root.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
                if site.site_type != "static" {
                    return Err(ApiError::BadRequest("Only static sites have a document root".into()));
                }
                let base = site
                    .home_dir
                    .clone()
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| validate::absolute(&config.sites_dir));
                let path = validate::path_within(root, &base).map_err(ApiError::BadRequest)?;
                std::fs::create_dir_all(&path).map_err(ApiError::internal)?;
                site.document_root = Some(crate::services::sites::display_path(&path));
            }
            apply_site(&config, conn, &previous, &site)?;
            if previous.target_port != site.target_port {
                let _ = apps::apply(&config, &site);
            }
            audit::record(conn, &user, "site.update", Some(&site.domain), None);
            Ok(site)
        })
        .await?;
    Ok(Json(site))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    #[serde(default)]
    pub delete_files: bool,
}

pub async fn delete_existing_site(
    Path(id): Path<i64>,
    Query(q): Query<DeleteQuery>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let (domain, warnings) = state
        .db(move |conn| {
            let site = db::find_site_by_id(conn, id)?.ok_or(ApiError::NotFound("Site"))?;
            let warnings = deprovision(&config, conn, &site, q.delete_files)?;
            for w in &warnings {
                tracing::warn!("deleting {}: {w}", site.domain);
            }
            audit::record(
                conn,
                &admin.0,
                "site.delete",
                Some(&site.domain),
                Some(if q.delete_files { "files deleted" } else { "files kept" }),
            );
            Ok((site.domain, warnings))
        })
        .await?;
    Ok(Json(json!({
        "message": format!("{domain} deleted"),
        "warning": if warnings.is_empty() { None } else { Some(warnings.join("; ")) },
    })))
}

pub async fn setup_site_ssl(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(payload): Json<SslRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let (site, warning) = state
        .db(move |conn| {
            let mut site = require_site(conn, &user, id)?;
            // Re-validate the stored domain before it reaches certbot or the filesystem.
            let domain = validate::domain(&site.domain).map_err(ApiError::BadRequest)?;
            let mut warning = None;

            let (cert, key, kind) = match (
                payload.custom_cert.as_deref(),
                payload.custom_key.as_deref(),
                payload.email.as_deref(),
            ) {
                (Some(cert), Some(key), _) if !cert.trim().is_empty() && !key.trim().is_empty() => {
                    let (c, k) = SslService::install_custom_cert(&config.ssl_dir(), &domain, cert, key)
                        .map_err(ApiError::BadRequest)?;
                    (c, k, "custom")
                }
                (_, _, Some(email)) if !email.trim().is_empty() => {
                    let email = validate::email(email).map_err(ApiError::BadRequest)?;
                    let issued =
                        SslService::issue_for_site(&site.server_names(), &email).map_err(ApiError::Unprocessable)?;
                    warning = issued.warning;
                    (issued.cert_path, issued.key_path, "letsencrypt")
                }
                _ => {
                    return Err(ApiError::BadRequest(
                        "Provide an email for Let's Encrypt, or both a certificate and private key".into(),
                    ))
                }
            };

            let previous = site.clone();
            site.ssl_enabled = true;
            site.ssl_cert_path = Some(cert);
            site.ssl_key_path = Some(key);
            apply_site(&config, conn, &previous, &site)?;
            audit::record(conn, &user, "site.ssl_install", Some(&site.domain), Some(kind));
            Ok((site, warning))
        })
        .await?;
    let mut v = serde_json::to_value(&site).map_err(ApiError::internal)?;
    v["warning"] = json!(warning);
    Ok(Json(v))
}

pub async fn renew_site_ssl(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let cert = site
                .ssl_cert_path
                .clone()
                .ok_or_else(|| ApiError::BadRequest("SSL is not enabled".into()))?;
            if !SslService::is_letsencrypt(&cert) {
                return Err(ApiError::BadRequest(
                    "Only Let's Encrypt certificates can be renewed; upload a new custom certificate instead".into(),
                ));
            }
            let domain = validate::domain(&site.domain).map_err(ApiError::BadRequest)?;
            SslService::renew_letsencrypt(&domain).map_err(ApiError::Unprocessable)?;
            NginxService::reload().map_err(ApiError::Unprocessable)?;
            audit::record(conn, &user, "site.ssl_renew", Some(&site.domain), None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "message": "Certificate renewed" })))
}

pub async fn remove_site_ssl(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            let previous = require_site(conn, &user, id)?;
            let mut site = previous.clone();
            site.ssl_enabled = false;
            site.ssl_cert_path = None;
            site.ssl_key_path = None;
            apply_site(&config, conn, &previous, &site)?;
            audit::record(conn, &user, "site.ssl_remove", Some(&site.domain), None);
            Ok(site)
        })
        .await?;
    Ok(Json(site))
}

#[derive(Deserialize)]
pub struct StateRequest {
    pub active: bool,
}

/// Enable or disable a site. Disabled sites answer 503 and their app is stopped.
pub async fn set_site_state(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<StateRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            let previous = require_site(conn, &user, id)?;
            let mut site = previous.clone();
            site.is_active = p.active;
            apply_site(&config, conn, &previous, &site)?;
            if site.kind().is_some_and(|k| k.has_app()) {
                if let Err(e) = apps::apply(&config, &site) {
                    tracing::warn!("app unit for {}: {e}", site.domain);
                }
            }
            audit::record(
                conn,
                &user,
                if p.active { "site.enable" } else { "site.disable" },
                Some(&site.domain),
                None,
            );
            Ok(site)
        })
        .await?;
    Ok(Json(site))
}

#[derive(Deserialize)]
pub struct LogQuery {
    pub kind: Option<String>,
    pub lines: Option<usize>,
}

pub async fn get_site_logs(
    Path(id): Path<i64>,
    Query(q): Query<LogQuery>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let lines = q.lines.unwrap_or(200).clamp(10, 5000);
    let kind = q.kind.unwrap_or_else(|| "access".into());
    let logs = state
        .db(move |conn| -> ApiResult<String> {
            let site = require_site(conn, &user, id)?;
            let domain = validate::domain(&site.domain).map_err(ApiError::BadRequest)?;
            match kind.as_str() {
                "access" | "error" => {
                    let path = config.nginx_log_dir.join(format!("{domain}.{kind}.log"));
                    Ok(crate::fsutil::tail_file(&path, lines).unwrap_or_else(|_| String::new()))
                }
                "app" => apps::logs(&site, lines).map_err(ApiError::Unprocessable),
                _ => Err(ApiError::BadRequest("kind must be access, error or app".into())),
            }
        })
        .await?;
    Ok(Json(json!({ "logs": logs })))
}

pub async fn get_site_vhost(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let current = NginxService::read_vhost(&config, &site.domain)
                .unwrap_or_else(|| NginxService::generate_config(&config, &site));
            Ok(json!({ "vhost": current, "custom_directives": site.custom_directives }))
        })
        .await?;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct DirectivesRequest {
    pub custom_directives: String,
}

/// Custom nginx directives are admin-only: they can proxy to anything or read any file.
pub async fn set_site_directives(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<DirectivesRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(&user)?;
    let directives = validate::nginx_directives(&p.custom_directives).map_err(ApiError::BadRequest)?;
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            let previous = require_site(conn, &user, id)?;
            let mut site = previous.clone();
            site.custom_directives = directives;
            apply_site(&config, conn, &previous, &site)?;
            audit::record(conn, &user, "site.directives", Some(&site.domain), None);
            Ok(site)
        })
        .await?;
    Ok(Json(site))
}

// ---------- Basic auth ----------

#[derive(Deserialize)]
pub struct BasicAuthRequest {
    pub enabled: bool,
    #[serde(default)]
    pub allow: Vec<String>,
}

pub async fn set_basic_auth(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<BasicAuthRequest>,
) -> ApiResult<impl IntoResponse> {
    let allow = p
        .allow
        .iter()
        .map(|a| a.trim())
        .filter(|a| !a.is_empty())
        .map(|a| validate::cidr(a).map_err(ApiError::BadRequest))
        .collect::<ApiResult<Vec<_>>>()?;
    if allow.len() > 100 {
        return Err(ApiError::BadRequest("At most 100 allow-list entries".into()));
    }
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            let previous = require_site(conn, &user, id)?;
            let users = db::list_basic_auth_users(conn, id)?;
            if p.enabled && users.is_empty() {
                return Err(ApiError::BadRequest(
                    "Add at least one user before enabling basic auth".into(),
                ));
            }
            NginxService::write_htpasswd(&config, &previous.domain, &users).map_err(ApiError::internal)?;
            let mut site = previous.clone();
            site.basic_auth_enabled = p.enabled;
            site.basic_auth_allow = allow.join("\n");
            apply_site(&config, conn, &previous, &site)?;
            audit::record(
                conn,
                &user,
                if p.enabled {
                    "site.basic_auth_on"
                } else {
                    "site.basic_auth_off"
                },
                Some(&site.domain),
                None,
            );
            Ok(site)
        })
        .await?;
    Ok(Json(site))
}

#[derive(Deserialize)]
pub struct BasicAuthUserRequest {
    pub username: String,
    pub password: String,
}

pub async fn add_basic_auth_user(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<BasicAuthUserRequest>,
) -> ApiResult<impl IntoResponse> {
    let username = validate::username(&p.username).map_err(ApiError::BadRequest)?;
    if p.password.len() < 8 || p.password.len() > 128 || p.password.contains(['\n', '\r']) {
        return Err(ApiError::BadRequest(
            "Password must be 8-128 characters on one line".into(),
        ));
    }
    let hash =
        crate::state::blocking(move || NginxService::hash_htpasswd(&p.password).map_err(ApiError::Unprocessable))
            .await?;
    let config = state.config.clone();
    state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            db::upsert_basic_auth_user(conn, id, &username, &hash)?;
            NginxService::write_htpasswd(&config, &site.domain, &db::list_basic_auth_users(conn, id)?)
                .map_err(ApiError::internal)?;
            audit::record(conn, &user, "site.basic_auth_user", Some(&site.domain), Some(&username));
            Ok(())
        })
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "ok": true }))))
}

pub async fn delete_basic_auth_user(
    Path((id, uid)): Path<(i64, i64)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let previous = require_site(conn, &user, id)?;
            if !db::delete_basic_auth_user(conn, id, uid)? {
                return Err(ApiError::NotFound("User"));
            }
            let users = db::list_basic_auth_users(conn, id)?;
            NginxService::write_htpasswd(&config, &previous.domain, &users).map_err(ApiError::internal)?;
            if users.is_empty() && previous.basic_auth_enabled {
                let mut site = previous.clone();
                site.basic_auth_enabled = false;
                apply_site(&config, conn, &previous, &site)?;
            }
            audit::record(conn, &user, "site.basic_auth_user_delete", Some(&previous.domain), None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}
