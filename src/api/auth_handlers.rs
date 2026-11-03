use crate::api::error::{ApiError, ApiResult};
use crate::auth::{create_jwt, hash_password, session_cookie, verify_dummy, verify_password, AuthUser};
use crate::db::{bump_token_version, find_user_by_id, find_user_by_username, set_user_password};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

fn cookie_headers(state: &SharedState, token: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&session_cookie(token, state.config.tls_enabled())) {
        headers.insert(header::SET_COOKIE, v);
    }
    headers
}

pub async fn login(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<impl IntoResponse> {
    let ip = addr.ip();
    state.limiter.check(ip).map_err(ApiError::TooManyRequests)?;

    if payload.username.len() > 64 || payload.password.len() > 256 {
        return Err(ApiError::BadRequest("Invalid username or password".into()));
    }

    let username = payload.username.trim().to_string();
    let user = state
        .db(move |conn| Ok(find_user_by_username(conn, &username)?))
        .await?;

    let password = payload.password;
    let (user, ok) = blocking(move || {
        let ok = match &user {
            Some(u) => verify_password(&password, &u.password_hash),
            None => {
                verify_dummy(&password);
                false
            }
        };
        Ok((user, ok))
    })
    .await?;

    let user = match (user, ok) {
        (Some(u), true) => u,
        _ => {
            state.limiter.record_failure(ip);
            tracing::warn!("failed login from {ip}");
            return Err(ApiError::Unauthorized("Invalid username or password".into()));
        }
    };

    state.limiter.reset(ip);
    let token = create_jwt(user.id, &user.username, user.token_version, &state.jwt_secret)?;
    tracing::info!("user '{}' signed in from {ip}", user.username);

    Ok((
        cookie_headers(&state, Some(&token)),
        Json(serde_json::json!({ "username": user.username, "role": user.role })),
    ))
}

pub async fn me(auth: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let user = state
        .db(move |conn| Ok(find_user_by_id(conn, auth.id)?))
        .await?
        .ok_or(ApiError::NotFound("User"))?;
    Ok(Json(user))
}

pub async fn logout(State(state): State<SharedState>) -> impl IntoResponse {
    (
        cookie_headers(&state, None),
        Json(serde_json::json!({ "message": "Signed out" })),
    )
}

/// Revoke every session for the current user (all devices).
pub async fn logout_all(auth: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    state.db(move |conn| Ok(bump_token_version(conn, auth.id)?)).await?;
    Ok((
        cookie_headers(&state, None),
        Json(serde_json::json!({ "message": "All sessions revoked" })),
    ))
}

pub async fn change_password(
    auth: AuthUser,
    State(state): State<SharedState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    validate::password(&payload.new_password).map_err(ApiError::BadRequest)?;
    if payload.new_password == payload.current_password {
        return Err(ApiError::BadRequest("New password must be different".into()));
    }

    let uid = auth.id;
    let user = state
        .db(move |conn| Ok(find_user_by_id(conn, uid)?))
        .await?
        .ok_or(ApiError::NotFound("User"))?;

    let (current, new) = (payload.current_password, payload.new_password);
    let stored = user.password_hash.clone();
    let new_hash = blocking(move || {
        if !verify_password(&current, &stored) {
            return Err(ApiError::BadRequest("Current password is incorrect".into()));
        }
        hash_password(&new).map_err(ApiError::internal)
    })
    .await?;

    let username = user.username.clone();
    let version = state
        .db(move |conn| Ok(set_user_password(conn, &username, &new_hash)?))
        .await?
        .ok_or(ApiError::NotFound("User"))?;

    let _ = std::fs::remove_file(state.config.data_dir.join("initial_admin_password"));
    let token = create_jwt(user.id, &user.username, version, &state.jwt_secret)?;
    tracing::info!("user '{}' changed their password", user.username);

    Ok((
        cookie_headers(&state, Some(&token)),
        Json(serde_json::json!({ "message": "Password updated. Other sessions were signed out." })),
    ))
}
