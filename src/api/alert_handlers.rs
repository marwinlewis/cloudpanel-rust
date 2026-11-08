//! Alert channels and rules, plus the panel's own TLS certificate (admin only).

use crate::api::error::{ApiError, ApiResult};
use crate::api::ViaPanelSite;
use crate::audit;
use crate::auth::AdminUser;
use crate::db;
use crate::services::alerts::{self, AlertRules, ChannelConfig};
use crate::services::panel_cert::{self, PanelTls};
use crate::services::{NginxService, SslService};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

pub async fn get_alerts(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            let channels: Vec<_> = db::list_alert_channels(conn)?
                .into_iter()
                .map(|c| {
                    let summary = crate::secrets::open::<ChannelConfig>(&config.etc_dir, &c.config)
                        .map(|cfg| cfg.summary())
                        .unwrap_or_else(|_| "(unreadable)".into());
                    json!({ "id": c.id, "kind": c.kind, "name": c.name, "enabled": c.enabled, "summary": summary, "created_at": c.created_at })
                })
                .collect();
            let rules: AlertRules = db::get_json(conn, alerts::RULES_SETTING)?;
            Ok(json!({ "channels": channels, "rules": rules, "firing": alerts::firing(conn) }))
        })
        .await?;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct ChannelRequest {
    pub name: String,
    #[serde(flatten)]
    pub config: ChannelConfig,
}

pub async fn create_channel(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<ChannelRequest>,
) -> ApiResult<impl IntoResponse> {
    let name = validate::short_text(Some(&p.name), 60)
        .map_err(ApiError::BadRequest)?
        .ok_or_else(|| ApiError::BadRequest("Name is required".into()))?;
    p.config.validate().map_err(ApiError::BadRequest)?;
    let sealed = crate::secrets::seal(&state.config.etc_dir, &p.config).map_err(ApiError::internal)?;
    let kind = p.config.kind();
    let id = state
        .db(move |conn| {
            let id = db::create_alert_channel(conn, kind, &name, &sealed)?;
            audit::record(conn, &admin.0, "alerts.channel_create", Some(&name), Some(kind));
            Ok(id)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

pub async fn delete_channel(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            let c = db::find_alert_channel(conn, id)?.ok_or(ApiError::NotFound("Channel"))?;
            db::delete_alert_channel(conn, id)?;
            audit::record(conn, &admin.0, "alerts.channel_delete", Some(&c.name), None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct EnabledRequest {
    pub enabled: bool,
}

pub async fn set_channel_enabled(
    Path(id): Path<i64>,
    _admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<EnabledRequest>,
) -> ApiResult<impl IntoResponse> {
    let found = state
        .db(move |conn| Ok(db::set_alert_channel_enabled(conn, id, p.enabled)?))
        .await?;
    if !found {
        return Err(ApiError::NotFound("Channel"));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn test_channel(
    Path(id): Path<i64>,
    _admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let etc = state.config.etc_dir.clone();
    let c = state
        .db(move |conn| db::find_alert_channel(conn, id)?.ok_or(ApiError::NotFound("Channel")))
        .await?;
    blocking(move || {
        let cfg: ChannelConfig = crate::secrets::open(&etc, &c.config).map_err(ApiError::internal)?;
        alerts::deliver(
            &cfg,
            "CloudPanel test notification",
            "If you can read this, alerts are working.",
            "info",
        )
        .map_err(ApiError::Unprocessable)
    })
    .await?;
    Ok(Json(json!({ "message": "Test notification sent" })))
}

pub async fn set_rules(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(rules): Json<AlertRules>,
) -> ApiResult<impl IntoResponse> {
    rules.validate().map_err(ApiError::BadRequest)?;
    state
        .db(move |conn| {
            db::set_json(conn, alerts::RULES_SETTING, &rules)?;
            audit::record(conn, &admin.0, "alerts.rules", None, None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "message": "Alert rules saved" })))
}

// ---------- Panel certificate ----------

pub async fn get_panel_cert(
    _admin: AdminUser,
    via: Option<Extension<ViaPanelSite>>,
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let (stored, closed_setting) = state
        .db(|conn| Ok((panel_cert::load(conn), panel_cert::direct_closed(conn))))
        .await?;
    let on_hostname = stored
        .as_ref()
        .is_some_and(|s| on_panel_hostname(via.is_some(), &headers, &s.hostname));
    let paths = panel_cert::effective_paths(&state.config, stored.as_ref());
    let info = paths
        .as_ref()
        .and_then(|(c, _)| SslService::cert_info(&c.to_string_lossy()));
    let tls_live = state.tls.lock().unwrap_or_else(|e| e.into_inner()).is_some();
    let cloudflare = state
        .cloudflare
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .status(chrono::Utc::now());
    Ok(Json(json!({
        "url": stored.as_ref().map(|s| format!("https://{}", s.hostname)),
        "hostname": stored.as_ref().map(|s| s.hostname.clone()),
        "managed": stored.is_some(),
        "tls": tls_live,
        "certificate": info,
        "cloudflare": cloudflare,
        "direct": {
            "port": state.config.panel_port(),
            "closed": state.direct_closed,
            // Set to closed, but opened again because the hostname isn't being served.
            "fell_back": closed_setting && !state.direct_closed,
            "on_hostname": on_hostname,
        },
    })))
}

#[derive(Deserialize)]
pub struct PanelCertRequest {
    pub hostname: String,
    pub email: String,
    /// Skip the DNS check (servers behind NAT where the public IP isn't on an interface).
    #[serde(default)]
    pub skip_dns_check: bool,
}

pub async fn issue_panel_cert(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<PanelCertRequest>,
) -> ApiResult<impl IntoResponse> {
    let host = validate::domain(&p.hostname).map_err(ApiError::BadRequest)?;
    let email = validate::email(&p.email).map_err(ApiError::BadRequest)?;
    let h = host.clone();
    let taken = state
        .db(move |conn| Ok(panel_cert::site_on_hostname(&db::list_sites(conn)?, &h)))
        .await?;
    if let Some(site) = taken {
        return Err(ApiError::Conflict(format!(
            "The site {site} already answers on {host}. Use a different hostname for the panel."
        )));
    }
    if !p.skip_dns_check {
        panel_cert::resolves_here(&host).await.map_err(ApiError::BadRequest)?;
    }
    let h = host.clone();
    let (cert, key) = blocking(move || {
        SslService::issue_letsencrypt(std::slice::from_ref(&h), &email).map_err(ApiError::Unprocessable)
    })
    .await?;
    let live = panel_cert::reload(&state, std::path::Path::new(&cert), std::path::Path::new(&key))
        .await
        .map_err(ApiError::Unprocessable)?;
    let stored = PanelTls {
        hostname: host.clone(),
        cert,
        key,
    };
    let saved = stored.clone();
    let name = host.clone();
    state
        .db(move |conn| {
            db::set_json(conn, panel_cert::SETTING, &saved)?;
            audit::record(conn, &admin.0, "panel.certificate", Some(&name), None);
            Ok(())
        })
        .await?;
    // The certificate is good by now, so a problem here is a warning and not a failure.
    let config = state.config.clone();
    let secret = state.proxy_secret.clone();
    let tls_on = state.tls.lock().unwrap_or_else(|e| e.into_inner()).is_some();
    let cloudflare = state.cloudflare.read().unwrap_or_else(|e| e.into_inner()).clone();
    let vhost = blocking(move || Ok(panel_cert::apply_vhost(&config, &stored, tls_on, &secret, &cloudflare))).await?;
    let message = match (live, vhost) {
        (true, Ok(())) => format!("Certificate installed. The panel is now at https://{host}"),
        (false, Ok(())) => format!(
            "Certificate issued and https://{host} is set up. Restart CloudPanel to serve the certificate on its own port too."
        ),
        (_, Err(e)) => {
            tracing::warn!("could not serve the panel on {host} through nginx: {e}");
            format!("Certificate installed, but nginx could not serve https://{host}, so use the panel's own port for now: {e}")
        }
    };
    Ok(Json(json!({ "message": message })))
}

#[derive(Deserialize)]
pub struct PanelAccessRequest {
    /// Whether the panel's own port should accept connections from outside.
    pub open: bool,
}

/// Did the admin reach this request by the panel's hostname, through its nginx site?
fn on_panel_hostname(via: bool, headers: &HeaderMap, hostname: &str) -> bool {
    via && headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.eq_ignore_ascii_case(hostname))
}

/// Open or close the panel's own port. Closing is only allowed from a session that is using the
/// hostname: that is the proof it works from where the admin is, which a test from this server
/// could not give. The panel has to restart to listen on its new address.
pub async fn set_panel_access(
    admin: AdminUser,
    via: Option<Extension<ViaPanelSite>>,
    headers: HeaderMap,
    State(state): State<SharedState>,
    Json(p): Json<PanelAccessRequest>,
) -> ApiResult<impl IntoResponse> {
    let via = via.is_some();
    let config = state.config.clone();
    state
        .db(move |conn| {
            if !p.open {
                let stored = panel_cert::load(conn).ok_or_else(|| {
                    ApiError::BadRequest("Set up a hostname for the panel before closing its port".into())
                })?;
                if !on_panel_hostname(via, &headers, &stored.hostname) {
                    return Err(ApiError::BadRequest(format!(
                        "Open the panel at https://{} and close the port from there, so it's clear the hostname works for you",
                        stored.hostname
                    )));
                }
                if db::running_job_count(conn)? > 0 {
                    return Err(ApiError::Conflict(
                        "A background job is running, and closing the port restarts the panel. Try again when it finishes."
                            .into(),
                    ));
                }
            }
            panel_cert::set_direct_closed(conn, !p.open)?;
            if p.open {
                panel_cert::allow_in_firewall(&config, conn);
            }
            audit::record(
                conn,
                &admin.0,
                if p.open { "panel.direct_open" } else { "panel.direct_close" },
                None,
                None,
            );
            Ok(())
        })
        .await?;
    // Let this response get out before the restart.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = tokio::task::spawn_blocking(panel_cert::restart_panel).await;
    });
    Ok(Json(json!({ "restarting": true })))
}

pub async fn remove_panel_cert(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            if panel_cert::direct_closed(conn) {
                return Err(ApiError::Conflict(
                    "The panel's port is closed, so this hostname is the only way in. Reopen the port first.".into(),
                ));
            }
            db::delete_setting(conn, panel_cert::SETTING)?;
            audit::record(conn, &admin.0, "panel.certificate_remove", None, None);
            Ok(())
        })
        .await?;
    if let (Some(c), Some(k)) = (state.config.tls_cert.clone(), state.config.tls_key.clone()) {
        let _ = panel_cert::reload(&state, &c, &k).await;
    }
    let config = state.config.clone();
    blocking(move || NginxService::remove_panel_vhost(&config).map_err(ApiError::Unprocessable)).await?;
    Ok(Json(
        json!({ "message": "The panel is back on its default certificate" }),
    ))
}
