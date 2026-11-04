use crate::api::error::ApiError;
use crate::db::{find_user_by_id, models::ROLE_ADMIN};
use crate::state::SharedState;
use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const SESSION_COOKIE: &str = "cp_session";
pub const SESSION_HOURS: i64 = 12;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub uid: i64,
    /// Must match `users.token_version`; bumping it revokes every issued token.
    pub ver: i64,
    pub iat: usize,
    pub exp: usize,
    /// Set for limited-purpose tokens (e.g. `"mfa"` between password and TOTP steps).
    /// Such tokens are never accepted as a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

pub fn create_jwt(user_id: i64, username: &str, token_version: i64, secret: &[u8]) -> Result<String, ApiError> {
    sign(
        user_id,
        username,
        token_version,
        secret,
        Duration::hours(SESSION_HOURS),
        None,
    )
}

/// Short-lived token proving the password step succeeded for a 2FA user.
pub fn create_mfa_token(user_id: i64, username: &str, token_version: i64, secret: &[u8]) -> Result<String, ApiError> {
    sign(
        user_id,
        username,
        token_version,
        secret,
        Duration::minutes(5),
        Some("mfa"),
    )
}

fn sign(
    user_id: i64,
    username: &str,
    token_version: i64,
    secret: &[u8],
    ttl: Duration,
    purpose: Option<&str>,
) -> Result<String, ApiError> {
    let now = Utc::now();
    let claims = Claims {
        sub: username.to_string(),
        uid: user_id,
        ver: token_version,
        iat: now.timestamp() as usize,
        exp: (now + ttl).timestamp() as usize,
        purpose: purpose.map(str::to_string),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(ApiError::internal)
}

pub fn verify_jwt(token: &str, secret: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation).map(|d| d.claims)
}

/// `Set-Cookie` value for a session token (or an expired one when `token` is None).
pub fn session_cookie(token: Option<&str>, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    match token {
        Some(t) => format!(
            "{SESSION_COOKIE}={t}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
            SESSION_HOURS * 3600
        ),
        None => format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"),
    }
}

fn token_from_parts(parts: &Parts) -> Option<String> {
    if let Some(t) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(t.trim().to_string());
    }
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (name, value) = c.trim().split_once('=')?;
            (name == SESSION_COOKIE && !value.is_empty()).then(|| value.to_string())
        })
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: i64,
    pub username: String,
    pub role: String,
    /// Client address, for the audit log.
    pub ip: Option<String>,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == ROLE_ADMIN
    }
}

#[async_trait]
impl FromRequestParts<SharedState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        let token = token_from_parts(parts).ok_or_else(|| ApiError::Unauthorized("Not signed in".into()))?;
        let claims = verify_jwt(&token, &state.jwt_secret)
            .map_err(|_| ApiError::Unauthorized("Session expired, please sign in again".into()))?;
        if claims.purpose.is_some() {
            return Err(ApiError::Unauthorized("Not signed in".into()));
        }

        let uid = claims.uid;
        let user = state
            .db(move |conn| Ok(find_user_by_id(conn, uid)?))
            .await?
            .ok_or_else(|| ApiError::Unauthorized("Session expired, please sign in again".into()))?;

        if user.token_version != claims.ver {
            return Err(ApiError::Unauthorized("Session expired, please sign in again".into()));
        }

        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string());
        Ok(AuthUser {
            id: user.id,
            username: user.username,
            role: user.role,
            ip,
        })
    }
}

/// An authenticated user with the `admin` role.
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

#[async_trait]
impl FromRequestParts<SharedState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin() {
            return Err(ApiError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_token_signed_with_other_secret() {
        let forged = create_jwt(
            1,
            "admin",
            0,
            b"cloudpanel_super_secret_jwt_key_change_in_production_32chars",
        )
        .unwrap();
        assert!(verify_jwt(&forged, b"a-completely-different-random-secret-value").is_err());
        let ok = create_jwt(1, "admin", 0, b"a-completely-different-random-secret-value").unwrap();
        assert_eq!(
            verify_jwt(&ok, b"a-completely-different-random-secret-value")
                .unwrap()
                .uid,
            1
        );
    }

    #[test]
    fn mfa_token_carries_purpose() {
        let t = create_mfa_token(1, "admin", 0, b"a-completely-different-random-secret-value").unwrap();
        let c = verify_jwt(&t, b"a-completely-different-random-secret-value").unwrap();
        assert_eq!(c.purpose.as_deref(), Some("mfa"));
    }

    #[test]
    fn rejects_alg_none() {
        // header {"alg":"none","typ":"JWT"}
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInVpZCI6MSwidmVyIjowLCJpYXQiOjAsImV4cCI6OTk5OTk5OTk5OX0.";
        assert!(verify_jwt(token, b"secret").is_err());
    }
}
