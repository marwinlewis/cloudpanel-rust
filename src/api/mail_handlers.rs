//! The email sending service (`src/mail`): install it, and manage its domains, forwarding
//! addresses, API keys and webhooks, and read its delivery log. Administrators only.
//!
//! The service keeps its own database (owned by its user). The panel opens it briefly for each
//! request and hands the files back to the service's user after writing. Postfix's forwarding
//! tables live under `/etc/postfix`, which the panel's sandbox can't write, so they are rewritten by
//! running `cloudpanel mail-postfix-sync` outside it.

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AdminUser;
use crate::config::Config;
use crate::mail::{self, events, install, manage, store, MailConfig};
use crate::services::cmd::{run_host, run_host_streaming, CmdOpts};
use crate::state::{blocking, SharedState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};

/// The service's paths. Tests keep its database under the panel's temporary data directory.
fn mail_config(config: &Config) -> MailConfig {
    let mut mc = MailConfig::from_env();
    if cfg!(test) {
        mc.state_dir = config.data_dir.join("mail");
        mc.hostname = "mail.example.com".into();
    }
    mc
}

fn installed(config: &Config) -> bool {
    cfg!(test) || install::installed(config)
}

/// Can the panel install it itself? It needs a real systemd host with apt.
fn can_install(config: &Config) -> bool {
    crate::services::runtimes::can_install(config)
}

fn require_installed(config: &Config) -> ApiResult<()> {
    if installed(config) {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "The email service is not installed. Install it on the Email page.".into(),
        ))
    }
}

fn map_err(e: manage::Error, what: &'static str) -> ApiError {
    match e {
        manage::Error::Invalid(m) => ApiError::BadRequest(m),
        manage::Error::NotFound(_) => ApiError::NotFound(what),
        manage::Error::Conflict(m) => ApiError::Conflict(m),
        manage::Error::Failed(m) => ApiError::Unprocessable(m),
    }
}

/// Run `f` against the service's database off the async runtime. With `write`, hand the files
/// back to the service's user afterwards.
async fn with_mail<T, F>(state: &SharedState, write: bool, f: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Connection, &MailConfig) -> ApiResult<T> + Send + 'static,
{
    require_installed(&state.config)?;
    let mc = mail_config(&state.config);
    blocking(move || {
        let conn = manage::open(&mc).map_err(|e| map_err(e, "Email database"))?;
        let out = f(&conn, &mc);
        drop(conn);
        if write && !cfg!(test) {
            install::fix_db_ownership(&mc);
        }
        out
    })
    .await
}

/// Rewrite Postfix's forwarding tables, outside the panel's sandbox.
async fn sync_postfix() -> ApiResult<()> {
    // Development hosts have no Postfix to update.
    if cfg!(test) || !cfg!(target_os = "linux") {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(ApiError::internal)?;
    blocking(move || {
        let r = run_host(
            &exe.to_string_lossy(),
            &["mail-postfix-sync"],
            &CmdOpts::default().timeout(60),
        );
        if r.success() {
            Ok(())
        } else {
            Err(ApiError::Unprocessable(format!(
                "Saved, but Postfix could not be updated: {}",
                r.combined().trim()
            )))
        }
    })
    .await
}

async fn record(state: &SharedState, admin: &AdminUser, action: &'static str, target: String) -> ApiResult<()> {
    let actor = admin.0.clone();
    state
        .db(move |conn| {
            audit::record(conn, &actor, action, Some(&target), None);
            Ok(())
        })
        .await
}

// ---------- Overview ----------

/// Everything the Email page lists. Cheap: the slower network checks are under `/mail/status`.
pub async fn get_mail(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let base = json!({
        "can_install": can_install(&state.config),
        "smtp_username": mail::SMTP_USERNAME,
        "event_types": events::EVENT_TYPES,
        "permissions": manage::PERMISSIONS,
        "log_statuses": manage::LOG_STATUSES,
        "default_hourly_limit": mail::DEFAULT_HOURLY_LIMIT,
    });
    if !installed(&state.config) {
        let mut v = base;
        v["installed"] = json!(false);
        return Ok(Json(v));
    }
    let lists = with_mail(&state, false, |conn, mc| {
        let domains: Vec<Value> = store::list_domains(conn)?
            .into_iter()
            .map(|d| {
                let mut v = serde_json::to_value(&d).unwrap_or_default();
                v["records"] = json!(manage::records(mc, &d));
                v
            })
            .collect();
        Ok(json!({
            "hostname": mc.hostname,
            "domains": domains,
            "keys": store::list_keys(conn)?,
            "forwards": store::list_forwards(conn)?,
            "webhooks": store::list_webhooks(conn)?,
        }))
    })
    .await?;
    let mut v = base;
    v["installed"] = json!(true);
    if let (Some(dst), Some(src)) = (v.as_object_mut(), lists.as_object()) {
        dst.extend(src.clone());
    }
    Ok(Json(v))
}

/// Units, ports, outbound port 25 and counts. Takes a few seconds (it probes port 25).
pub async fn get_status(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let s = with_mail(&state, false, |conn, mc| {
        manage::status(conn, mc).map_err(|e| map_err(e, "Email service"))
    })
    .await?;
    Ok(Json(
        json!({ "status": s, "port_25_warning": install::PORT_25_WARNING }),
    ))
}

#[derive(Deserialize)]
pub struct InstallRequest {
    pub hostname: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub self_signed: bool,
}

pub async fn install(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(req): Json<InstallRequest>,
) -> ApiResult<impl IntoResponse> {
    if !can_install(&state.config) {
        return Err(ApiError::BadRequest(
            "This system can't install the email service from the panel. Run: cloudpanel mail-install --hostname mail.example.com".into(),
        ));
    }
    let hostname = manage::clean_domain(&req.hostname).map_err(|e| map_err(e, "Hostname"))?;
    let email = req
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(manage::clean_address)
        .transpose()
        .map_err(|e| map_err(e, "Email"))?;
    let actor = admin.0.clone();
    let host = hostname.clone();
    state
        .db(move |conn| {
            let sites = crate::db::list_sites(conn)?;
            let panel = crate::services::panel_cert::load(conn).map(|t| t.hostname);
            manage::check_hostname_free(&sites, panel.as_deref(), &host).map_err(|e| map_err(e, "Hostname"))?;
            audit::record(conn, &actor, "mail.install", Some(&host), None);
            Ok(())
        })
        .await?;
    let exe = std::env::current_exe().map_err(ApiError::internal)?;
    let mut args = vec!["mail-install".to_string(), "--hostname".into(), hostname.clone()];
    if let Some(e) = email {
        args.push("--email".into());
        args.push(e);
    } else if req.self_signed {
        args.push("--self-signed".into());
    }
    let job_id = crate::jobs::spawn(
        &state.pool,
        "mail.install",
        Some(&hostname),
        Some(admin.0.id),
        move |log| {
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let r = run_host_streaming(
                &exe.to_string_lossy(),
                &argv,
                &CmdOpts::default().timeout(20 * 60),
                &mut |l, _| log.line(l),
            );
            if r.success() {
                Ok(())
            } else {
                Err(format!(
                    "Installing the email service failed (exit code {})",
                    r.code.unwrap_or(-1)
                ))
            }
        },
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

pub async fn uninstall(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    require_installed(&state.config)?;
    record(&state, &admin, "mail.uninstall", String::new()).await?;
    let exe = std::env::current_exe().map_err(ApiError::internal)?;
    let job_id = crate::jobs::spawn(&state.pool, "mail.uninstall", None, Some(admin.0.id), move |log| {
        let r = run_host_streaming(
            &exe.to_string_lossy(),
            &["mail-uninstall"],
            &CmdOpts::default().timeout(5 * 60),
            &mut |l, _| log.line(l),
        );
        if r.success() {
            Ok(())
        } else {
            Err(format!(
                "Removing the email service failed (exit code {})",
                r.code.unwrap_or(-1)
            ))
        }
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- Domains ----------

#[derive(Deserialize)]
pub struct DomainRequest {
    pub domain: String,
}

pub async fn add_domain(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(req): Json<DomainRequest>,
) -> ApiResult<impl IntoResponse> {
    let (domain, records) = with_mail(&state, true, move |conn, mc| {
        let d = manage::add_domain(conn, mc, &req.domain).map_err(|e| map_err(e, "Domain"))?;
        let records = manage::records(mc, &d);
        Ok((d, records))
    })
    .await?;
    record(&state, &admin, "mail.domain_add", domain.name.clone()).await?;
    let mut v = serde_json::to_value(&domain).unwrap_or_default();
    v["records"] = json!(records);
    Ok((StatusCode::CREATED, Json(v)))
}

pub async fn domain_dns(
    _admin: AdminUser,
    State(state): State<SharedState>,
    Path(domain): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let records = with_mail(&state, false, move |conn, mc| {
        manage::domain_records(conn, mc, &domain).map_err(|e| map_err(e, "Domain"))
    })
    .await?;
    Ok(Json(json!({ "records": records })))
}

#[derive(Deserialize, Default)]
pub struct VerifyRequest {
    #[serde(default)]
    pub force: bool,
}

pub async fn verify_domain(
    admin: AdminUser,
    State(state): State<SharedState>,
    Path(domain): Path<String>,
    body: Option<Json<VerifyRequest>>,
) -> ApiResult<impl IntoResponse> {
    let force = body.map(|Json(b)| b.force).unwrap_or(false);
    let v = with_mail(&state, true, move |conn, mc| {
        manage::verify_domain(conn, mc, &domain, force).map_err(|e| map_err(e, "Domain"))
    })
    .await?;
    if v.verified {
        record(&state, &admin, "mail.domain_verify", v.domain.clone()).await?;
    }
    Ok(Json(v))
}

pub async fn remove_domain(
    admin: AdminUser,
    State(state): State<SharedState>,
    Path(domain): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let (name, removed) = with_mail(&state, true, move |conn, mc| {
        let r = manage::remove_domain(conn, mc, &domain).map_err(|e| map_err(e, "Domain"))?;
        Ok((manage::clean_domain(&domain).unwrap_or(domain), r))
    })
    .await?;
    record(&state, &admin, "mail.domain_remove", name.clone()).await?;
    if removed.needs_postfix_sync() {
        sync_postfix().await?;
    }
    Ok(Json(json!({
        "message": format!(
            "Removed {name}, {} address(es) and {} key(s). Remove its DNS records too.",
            removed.forwards_removed, removed.keys_revoked
        ),
    })))
}

// ---------- Forwarding addresses ----------

#[derive(Deserialize)]
pub struct ForwardRequest {
    pub address: String,
    pub to: String,
}

pub async fn add_forward(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(req): Json<ForwardRequest>,
) -> ApiResult<impl IntoResponse> {
    let f = with_mail(&state, true, move |conn, _| {
        manage::add_forward(conn, &req.address, &req.to).map_err(|e| map_err(e, "Address"))
    })
    .await?;
    record(&state, &admin, "mail.forward_add", f.address.clone()).await?;
    sync_postfix().await?;
    Ok((StatusCode::CREATED, Json(f)))
}

pub async fn remove_forward(
    admin: AdminUser,
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let address = with_mail(&state, true, move |conn, _| {
        manage::remove_forward(conn, &address).map_err(|e| map_err(e, "Address"))
    })
    .await?;
    record(&state, &admin, "mail.forward_remove", address.clone()).await?;
    sync_postfix().await?;
    Ok(Json(
        json!({ "message": format!("Mail to {address} is no longer accepted.") }),
    ))
}

// ---------- API keys ----------

#[derive(Deserialize)]
pub struct KeyRequest {
    pub name: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_permission")]
    pub permission: String,
    #[serde(default = "default_limit")]
    pub hourly_limit: u32,
}

fn default_permission() -> String {
    "sending".into()
}

fn default_limit() -> u32 {
    mail::DEFAULT_HOURLY_LIMIT
}

pub async fn create_key(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(req): Json<KeyRequest>,
) -> ApiResult<impl IntoResponse> {
    let (key, secret, host) = with_mail(&state, true, move |conn, mc| {
        let (k, s) = manage::create_key(
            conn,
            &req.name,
            req.domain.as_deref(),
            &req.permission,
            req.hourly_limit,
        )
        .map_err(|e| map_err(e, "Domain"))?;
        Ok((k, s, mc.hostname.clone()))
    })
    .await?;
    record(&state, &admin, "mail.key_create", key.id.clone()).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "key": key,
            "secret": secret,
            "smtp": { "host": host, "ports": [587, 465], "username": mail::SMTP_USERNAME },
            "api_url": format!("https://{host}/emails"),
        })),
    ))
}

pub async fn revoke_key(
    admin: AdminUser,
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let target = id.trim().to_string();
    with_mail(&state, true, move |conn, _| {
        manage::revoke_key(conn, &id).map_err(|e| map_err(e, "Key"))
    })
    .await?;
    record(&state, &admin, "mail.key_revoke", target).await?;
    Ok(Json(
        json!({ "message": "Key revoked. Clients using it can no longer send." }),
    ))
}

// ---------- Webhooks ----------

#[derive(Deserialize)]
pub struct WebhookRequest {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
}

pub async fn add_webhook(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(req): Json<WebhookRequest>,
) -> ApiResult<impl IntoResponse> {
    let (hook, secret) = with_mail(&state, true, move |conn, _| {
        manage::add_webhook(conn, &req.url, &req.events).map_err(|e| map_err(e, "Webhook"))
    })
    .await?;
    record(&state, &admin, "mail.webhook_add", hook.url.clone()).await?;
    Ok((StatusCode::CREATED, Json(json!({ "webhook": hook, "secret": secret }))))
}

pub async fn remove_webhook(
    admin: AdminUser,
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let target = id.trim().to_string();
    with_mail(&state, true, move |conn, _| {
        manage::remove_webhook(conn, &id).map_err(|e| map_err(e, "Webhook"))
    })
    .await?;
    record(&state, &admin, "mail.webhook_remove", target).await?;
    Ok(Json(json!({ "message": "Webhook removed." })))
}

// ---------- Log ----------

#[derive(Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub status: Option<String>,
}

pub async fn list_log(
    _admin: AdminUser,
    State(state): State<SharedState>,
    Query(q): Query<LogQuery>,
) -> ApiResult<impl IntoResponse> {
    if let Some(s) = q.status.as_deref().filter(|s| !s.is_empty()) {
        if !manage::LOG_STATUSES.contains(&s) {
            return Err(ApiError::BadRequest("Unknown status".into()));
        }
    }
    let messages = with_mail(&state, false, move |conn, _| {
        manage::messages(conn, q.limit.unwrap_or(100), q.status.as_deref()).map_err(|e| map_err(e, "Email"))
    })
    .await?;
    Ok(Json(json!({ "messages": messages })))
}

pub async fn get_message(
    _admin: AdminUser,
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let m = with_mail(&state, false, move |conn, _| {
        manage::message(conn, &id).map_err(|e| map_err(e, "Email"))
    })
    .await?;
    Ok(Json(m))
}
