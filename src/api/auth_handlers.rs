use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::{
    create_jwt, create_mfa_token, hash_password, session_cookie, totp, verify_dummy, verify_jwt, verify_password,
    AuthUser,
};
use crate::db::{self, bump_token_version, find_user_by_id, find_user_by_username, models::User, set_user_password};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct MfaLoginRequest {
    pub mfa_token: String,
    pub code: String,
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

/// Append a failed attempt to `/var/log/cloudpanel/auth.log` for fail2ban.
///
/// Not for a Cloudflare address: that is a request that didn't name its visitor, so these failures
/// aren't that address's, and everyone connecting through it would share the ban.
fn log_auth_failure(state: &SharedState, ip: IpAddr, username: &str, reason: &str) {
    use std::io::Write;
    if state.is_cloudflare(ip) {
        return;
    }
    let dir = &state.config.log_dir;
    let _ = std::fs::create_dir_all(dir);
    let user: String = username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(64)
        .collect();
    let line = format!(
        "{} cloudpanel auth failure from {ip} user={user} reason={reason}\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("auth.log"))
    {
        let _ = f.write_all(line.as_bytes());
    }
}

async fn record_failure(state: &SharedState, ip: IpAddr, username: String, reason: &'static str) {
    tracing::warn!("failed login ({reason}) from {ip}");
    log_auth_failure(state, ip, &username, reason);
    let ip_s = ip.to_string();
    let _ = state
        .db(move |conn| {
            audit::record_system(
                conn,
                Some(&username),
                Some(&ip_s),
                "auth.login_failed",
                None,
                Some(reason),
            );
            Ok(())
        })
        .await;
}

async fn finish_login(state: &SharedState, user: User, ip: IpAddr, via: &'static str) -> ApiResult<impl IntoResponse> {
    let (uid, name, ip_s) = (user.id, user.username.clone(), ip.to_string());
    state
        .db(move |conn| {
            db::insert_event(
                conn,
                &db::NewEvent {
                    user_id: Some(uid),
                    username: Some(&name),
                    ip: Some(&ip_s),
                    action: "auth.login",
                    target: None,
                    detail: Some(via),
                },
            )?;
            Ok(())
        })
        .await?;
    let token = create_jwt(user.id, &user.username, user.token_version, &state.jwt_secret)?;
    tracing::info!("user '{}' signed in from {ip}", user.username);
    Ok((
        cookie_headers(state, Some(&token)),
        Json(json!({ "username": user.username, "role": user.role })),
    ))
}

pub async fn login(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<axum::response::Response> {
    let ip = addr.ip();
    state.limiter.check(ip).map_err(ApiError::TooManyRequests)?;

    if payload.username.len() > 64 || payload.password.len() > 256 {
        return Err(ApiError::BadRequest("Invalid username or password".into()));
    }

    let username = payload.username.trim().to_string();
    if let Err(wait) = state.limiter.begin_password(ip, &username) {
        // Refused for the account rather than this address: fail2ban still has to hear about the
        // address, or guesses spread over many addresses would never get any of them banned.
        if state.limiter.check(ip).is_ok() {
            log_auth_failure(&state, ip, &username, "limited");
        }
        return Err(ApiError::TooManyRequests(wait));
    }
    let lookup = username.clone();
    let user = state.db(move |conn| Ok(find_user_by_username(conn, &lookup)?)).await?;

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
            record_failure(&state, ip, username, "password").await;
            return Err(ApiError::Unauthorized("Invalid username or password".into()));
        }
    };

    state.limiter.password_ok(ip, &username);

    if user.totp_enabled {
        let token = create_mfa_token(user.id, &user.username, user.token_version, &state.jwt_secret)?;
        return Ok(Json(json!({ "mfa_required": true, "mfa_token": token })).into_response());
    }
    Ok(finish_login(&state, user, ip, "password").await?.into_response())
}

/// Second login step: TOTP code or a recovery code.
pub async fn login_mfa(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(p): Json<MfaLoginRequest>,
) -> ApiResult<impl IntoResponse> {
    let ip = addr.ip();
    state.limiter.check(ip).map_err(ApiError::TooManyRequests)?;
    let expired = || ApiError::Unauthorized("Sign-in expired, please enter your password again".into());
    let claims = verify_jwt(&p.mfa_token, &state.jwt_secret).map_err(|_| expired())?;
    if claims.purpose.as_deref() != Some("mfa") {
        return Err(expired());
    }
    if p.code.len() > 32 {
        return Err(ApiError::BadRequest("Invalid code".into()));
    }
    let uid = claims.uid;
    let user = state
        .db(move |conn| Ok(find_user_by_id(conn, uid)?))
        .await?
        .ok_or_else(expired)?;
    if user.token_version != claims.ver || !user.totp_enabled {
        return Err(expired());
    }
    // Limited per account as well as per address: whoever is here knows the password already, and
    // may well have more than one address to guess from. Only for a token that's real, or anyone
    // could lock this step for anyone.
    state
        .limiter
        .begin_second_step(ip, user.id)
        .map_err(ApiError::TooManyRequests)?;
    let secret = user.totp_secret.clone().unwrap_or_default();
    let code = p.code.trim().to_string();
    if totp::verify(&secret, &user.username, &code) {
        state.limiter.second_step_ok(ip, user.id);
        return finish_login(&state, user, ip, "password+totp").await;
    }
    if let Some(remaining) = totp::consume_recovery_code(&user.recovery_codes, &code) {
        state.limiter.second_step_ok(ip, user.id);
        let id = user.id;
        state
            .db(move |conn| Ok(db::set_recovery_codes(conn, id, &remaining)?))
            .await?;
        return finish_login(&state, user, ip, "password+recovery_code").await;
    }
    record_failure(&state, ip, user.username, "totp").await;
    Err(ApiError::Unauthorized("That code is not valid".into()))
}

pub async fn me(auth: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let (user, site_ids) = state
        .db(move |conn| {
            let user = find_user_by_id(conn, auth.id)?.ok_or(ApiError::NotFound("User"))?;
            Ok((user, db::user_site_ids(conn, auth.id)?))
        })
        .await?;
    let mut v = serde_json::to_value(&user).map_err(ApiError::internal)?;
    v["site_ids"] = json!(site_ids);
    v["recovery_codes_left"] = json!(totp::remaining_recovery_codes(&user.recovery_codes));
    Ok(Json(v))
}

/// Sign out. The token stops working here and now, not only in this browser: whoever might have
/// copied it can't go on using it for the rest of its 12 hours.
pub async fn logout(State(state): State<SharedState>, headers: HeaderMap) -> ApiResult<impl IntoResponse> {
    if let Some(token) = crate::auth::jwt::token_from_headers(&headers) {
        if let Ok(claims) = verify_jwt(&token, &state.jwt_secret) {
            let hash = crate::auth::jwt::token_hash(&token);
            let expires = chrono::DateTime::from_timestamp(claims.exp as i64, 0).unwrap_or_else(chrono::Utc::now);
            state
                .db(move |conn| Ok(db::revoke_token(conn, &hash, expires)?))
                .await?;
        }
    }
    Ok((cookie_headers(&state, None), Json(json!({ "message": "Signed out" }))))
}

/// Revoke every session for the current user (all devices).
pub async fn logout_all(auth: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            bump_token_version(conn, auth.id)?;
            audit::record(conn, &auth, "auth.logout_all", None, None);
            Ok(())
        })
        .await?;
    Ok((
        cookie_headers(&state, None),
        Json(json!({ "message": "All sessions revoked" })),
    ))
}

/// Verify the current user's password (for sensitive account changes).
async fn check_own_password(state: &SharedState, auth: &AuthUser, password: String) -> ApiResult<User> {
    let uid = auth.id;
    let user = state
        .db(move |conn| Ok(find_user_by_id(conn, uid)?))
        .await?
        .ok_or(ApiError::NotFound("User"))?;
    let hash = user.password_hash.clone();
    let ok = blocking(move || Ok(verify_password(&password, &hash))).await?;
    if !ok {
        return Err(ApiError::BadRequest("Current password is incorrect".into()));
    }
    Ok(user)
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
    let user = check_own_password(&state, &auth, payload.current_password).await?;
    let new = payload.new_password;
    let new_hash = blocking(move || hash_password(&new).map_err(ApiError::internal)).await?;

    let username = user.username.clone();
    let actor = auth.clone();
    let version = state
        .db(move |conn| {
            let v = set_user_password(conn, &username, &new_hash)?;
            audit::record(conn, &actor, "auth.password_changed", None, None);
            Ok(v)
        })
        .await?
        .ok_or(ApiError::NotFound("User"))?;

    let _ = std::fs::remove_file(state.config.data_dir.join("initial_admin_password"));
    let token = create_jwt(user.id, &user.username, version, &state.jwt_secret)?;
    tracing::info!("user '{}' changed their password", user.username);

    Ok((
        cookie_headers(&state, Some(&token)),
        Json(json!({ "message": "Password updated. Other sessions were signed out." })),
    ))
}

#[derive(Deserialize)]
pub struct EmailRequest {
    pub email: String,
}

pub async fn change_email(
    auth: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<EmailRequest>,
) -> ApiResult<impl IntoResponse> {
    let email = validate::email(&p.email).map_err(ApiError::BadRequest)?;
    state
        .db(move |conn| {
            conn.execute(
                "UPDATE users SET email = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![email, chrono::Utc::now(), auth.id],
            )
            .map_err(|e| {
                if db::is_unique_violation(&e) {
                    ApiError::Conflict("That email is used by another account".into())
                } else {
                    e.into()
                }
            })?;
            audit::record(conn, &auth, "auth.email_changed", None, None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "message": "Email updated" })))
}

// ---------- Two-factor authentication ----------

/// Start enrollment: store a pending secret and return it with a QR matrix. It needs the password,
/// or anyone who got hold of a session could put the second factor on a phone of their own.
pub async fn totp_setup(
    auth: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<PasswordConfirm>,
) -> ApiResult<impl IntoResponse> {
    let uid = auth.id;
    let user = check_own_password(&state, &auth, p.password).await?;
    if user.totp_enabled {
        return Err(ApiError::Conflict(
            "Two-factor authentication is already enabled".into(),
        ));
    }
    let secret = totp::generate_secret();
    let url = totp::otpauth_url(&secret, &user.username).map_err(ApiError::internal)?;
    let (width, modules) = totp::qr_matrix(&url).map_err(ApiError::internal)?;
    let s = secret.clone();
    state.db(move |conn| Ok(db::set_totp_pending(conn, uid, &s)?)).await?;
    Ok(Json(
        json!({ "secret": secret, "otpauth_url": url, "qr": { "width": width, "modules": modules } }),
    ))
}

#[derive(Deserialize)]
pub struct CodeRequest {
    pub code: String,
}

pub async fn totp_enable(
    auth: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<CodeRequest>,
) -> ApiResult<impl IntoResponse> {
    let uid = auth.id;
    let user = state
        .db(move |conn| Ok(find_user_by_id(conn, uid)?))
        .await?
        .ok_or(ApiError::NotFound("User"))?;
    // Turning it on again would hand out new recovery codes without the password.
    if user.totp_enabled {
        return Err(ApiError::Conflict(
            "Two-factor authentication is already enabled".into(),
        ));
    }
    let secret = user
        .totp_secret
        .clone()
        .ok_or_else(|| ApiError::BadRequest("Start the setup first".into()))?;
    if !totp::verify(&secret, &user.username, &p.code) {
        return Err(ApiError::BadRequest(
            "That code is not valid. Check the time on your phone and try again.".into(),
        ));
    }
    let (codes, hashes) = totp::generate_recovery_codes();
    let (name, actor) = (user.username.clone(), auth.clone());
    let version = state
        .db(move |conn| {
            db::enable_totp(conn, uid, &hashes)?;
            // Sign out other sessions now that the account is better protected.
            bump_token_version(conn, uid)?;
            audit::record(conn, &actor, "auth.2fa_enabled", None, None);
            Ok(find_user_by_id(conn, uid)?.map(|u| u.token_version))
        })
        .await?
        .ok_or(ApiError::NotFound("User"))?;
    let token = create_jwt(uid, &name, version, &state.jwt_secret)?;
    Ok((
        cookie_headers(&state, Some(&token)),
        Json(json!({ "recovery_codes": codes })),
    ))
}

#[derive(Deserialize)]
pub struct PasswordConfirm {
    pub password: String,
}

pub async fn totp_disable(
    auth: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<PasswordConfirm>,
) -> ApiResult<impl IntoResponse> {
    check_own_password(&state, &auth, p.password).await?;
    let name = auth.username.clone();
    let uid = auth.id;
    // Other sessions end: if this wasn't the account's owner, the owner's devices aren't left
    // signed in alongside whoever it was.
    let version = state
        .db(move |conn| {
            db::disable_totp(conn, auth.id)?;
            bump_token_version(conn, auth.id)?;
            audit::record(conn, &auth, "auth.2fa_disabled", None, None);
            Ok(find_user_by_id(conn, auth.id)?.map(|u| u.token_version))
        })
        .await?
        .ok_or(ApiError::NotFound("User"))?;
    let token = create_jwt(uid, &name, version, &state.jwt_secret)?;
    crate::services::alerts::notify_event(
        &state.config,
        &state.pool,
        "Security: two-factor authentication disabled",
        &format!("'{name}' turned off two-factor authentication."),
    );
    Ok((
        cookie_headers(&state, Some(&token)),
        Json(json!({ "message": "Two-factor authentication disabled. Other sessions were signed out." })),
    ))
}

pub async fn totp_recovery_codes(
    auth: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<PasswordConfirm>,
) -> ApiResult<impl IntoResponse> {
    let user = check_own_password(&state, &auth, p.password).await?;
    if !user.totp_enabled {
        return Err(ApiError::BadRequest("Two-factor authentication is not enabled".into()));
    }
    let (codes, hashes) = totp::generate_recovery_codes();
    state
        .db(move |conn| {
            db::set_recovery_codes(conn, auth.id, &hashes)?;
            audit::record(conn, &auth, "auth.recovery_codes", None, None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "recovery_codes": codes })))
}
