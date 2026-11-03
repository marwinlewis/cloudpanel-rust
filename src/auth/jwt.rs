use crate::api::error::ApiError;
use crate::db::find_user_by_id;
use crate::state::SharedState;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

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
}

pub fn create_jwt(user_id: i64, username: &str, token_version: i64, secret: &[u8]) -> Result<String, ApiError> {
    let now = Utc::now();
    let claims = Claims {
        sub: username.to_string(),
        uid: user_id,
        ver: token_version,
        iat: now.timestamp() as usize,
        exp: (now + Duration::hours(SESSION_HOURS)).timestamp() as usize,
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
    pub role: String,
}

#[async_trait]
impl FromRequestParts<SharedState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        let token = token_from_parts(parts).ok_or_else(|| ApiError::Unauthorized("Not signed in".into()))?;
        let claims = verify_jwt(&token, &state.jwt_secret)
            .map_err(|_| ApiError::Unauthorized("Session expired, please sign in again".into()))?;

        let uid = claims.uid;
        let user = state
            .db(move |conn| Ok(find_user_by_id(conn, uid)?))
            .await?
            .ok_or_else(|| ApiError::Unauthorized("Session expired, please sign in again".into()))?;

        if user.token_version != claims.ver {
            return Err(ApiError::Unauthorized("Session expired, please sign in again".into()));
        }

        Ok(AuthUser {
            id: user.id,
            role: user.role,
        })
    }
}

/// An authenticated user with the `admin` role.
#[derive(Debug, Clone)]
pub struct AdminUser(#[allow(dead_code)] pub AuthUser);

#[async_trait]
impl FromRequestParts<SharedState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if user.role != "admin" {
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
    fn rejects_alg_none() {
        // header {"alg":"none","typ":"JWT"}
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInVpZCI6MSwidmVyIjowLCJpYXQiOjAsImV4cCI6OTk5OTk5OTk5OX0.";
        assert!(verify_jwt(token, b"secret").is_err());
    }
}
