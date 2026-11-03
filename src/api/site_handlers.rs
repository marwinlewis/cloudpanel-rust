use crate::api::error::{ApiError, ApiResult};
use crate::auth::AdminUser;
use crate::db::{delete_site, find_site_by_id, list_sites, update_site_ssl};
use crate::services::sites::{provision, SiteInput};
use crate::services::{NginxService, SslService};
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
pub struct CreateSiteRequest {
    pub domain: String,
    pub site_type: String, // nodejs, python, static, docker_proxy, reverse_proxy
    pub target_port: Option<u16>,
    pub document_root: Option<String>,
    pub system_user: Option<String>,
    #[serde(default)]
    pub include_www: bool,
}

#[derive(Deserialize)]
pub struct SslRequest {
    pub email: Option<String>,
    pub custom_cert: Option<String>,
    pub custom_key: Option<String>,
}

pub async fn get_sites(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    Ok(Json(state.db(|conn| Ok(list_sites(conn)?)).await?))
}

pub async fn create_new_site(
    _admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateSiteRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            provision(
                &config,
                conn,
                SiteInput {
                    domain: p.domain,
                    site_type: p.site_type,
                    target_port: p.target_port,
                    document_root: p.document_root,
                    system_user: p.system_user,
                    include_www: p.include_www,
                },
            )
        })
        .await?;
    Ok((StatusCode::CREATED, Json(site)))
}

pub async fn get_site(
    Path(id): Path<i64>,
    _admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let site = state
        .db(move |conn| Ok(find_site_by_id(conn, id)?))
        .await?
        .ok_or(ApiError::NotFound("Site"))?;
    Ok(Json(site))
}

pub async fn delete_existing_site(
    Path(id): Path<i64>,
    _admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let (domain, warning) = state
        .db(move |conn| {
            let site = find_site_by_id(conn, id)?.ok_or(ApiError::NotFound("Site"))?;
            let warning = NginxService::remove_site(&config, &site.domain).err();
            if let Some(w) = &warning {
                tracing::warn!("removing nginx config for {}: {w}", site.domain);
            }
            delete_site(conn, id)?;
            Ok((site.domain, warning))
        })
        .await?;
    Ok(Json(serde_json::json!({
        "message": format!("{domain} deleted"),
        "warning": warning,
    })))
}

pub async fn setup_site_ssl(
    Path(id): Path<i64>,
    _admin: AdminUser,
    State(state): State<SharedState>,
    Json(payload): Json<SslRequest>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let site = state
        .db(move |conn| {
            let mut site = find_site_by_id(conn, id)?.ok_or(ApiError::NotFound("Site"))?;
            // Re-validate the stored domain before it reaches certbot or the filesystem.
            let domain = validate::domain(&site.domain).map_err(ApiError::BadRequest)?;

            let (cert, key) = match (
                payload.custom_cert.as_deref(),
                payload.custom_key.as_deref(),
                payload.email.as_deref(),
            ) {
                (Some(cert), Some(key), _) if !cert.trim().is_empty() && !key.trim().is_empty() => {
                    SslService::install_custom_cert(&config.ssl_dir(), &domain, cert, key)
                        .map_err(ApiError::BadRequest)?
                }
                (_, _, Some(email)) if !email.trim().is_empty() => {
                    let email = validate::email(email).map_err(ApiError::BadRequest)?;
                    SslService::issue_letsencrypt(&site.server_names(), &email).map_err(ApiError::Unprocessable)?
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
            if let Err(e) = NginxService::write_and_apply(&config, &site) {
                // Keep serving the old config; nginx rejected the certificate.
                let _ = NginxService::write_and_apply(&config, &previous);
                return Err(ApiError::Unprocessable(e));
            }
            update_site_ssl(
                conn,
                id,
                true,
                site.ssl_cert_path.as_deref(),
                site.ssl_key_path.as_deref(),
            )?;
            Ok(site)
        })
        .await?;
    Ok(Json(site))
}
