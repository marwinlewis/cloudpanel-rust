//! Panel user management (admin only).

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::{hash_password, AdminUser};
use crate::db::{
    self,
    models::{ROLE_ADMIN, ROLE_SITE_MANAGER},
};
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

fn role(r: &str) -> ApiResult<&'static str> {
    match r {
        "admin" => Ok(ROLE_ADMIN),
        "site_manager" => Ok(ROLE_SITE_MANAGER),
        _ => Err(ApiError::BadRequest("Role must be admin or site_manager".into())),
    }
}

pub async fn list_users(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let out = state
        .db(|conn| {
            let mut out = Vec::new();
            for u in db::list_users(conn)? {
                let mut v = serde_json::to_value(&u).map_err(ApiError::internal)?;
                v["site_ids"] = json!(db::user_site_ids(conn, u.id)?);
                out.push(v);
            }
            Ok(out)
        })
        .await?;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: String,
    #[serde(default)]
    pub site_ids: Vec<i64>,
}

pub async fn create_user(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateUserRequest>,
) -> ApiResult<impl IntoResponse> {
    let username = validate::username(&p.username).map_err(ApiError::BadRequest)?;
    let email = validate::email(&p.email).map_err(ApiError::BadRequest)?;
    validate::password(&p.password).map_err(ApiError::BadRequest)?;
    let role = role(&p.role)?;
    let pw = p.password;
    let hash = blocking(move || hash_password(&pw).map_err(ApiError::internal)).await?;
    let actor_name = admin.0.username.clone();
    let id = state
        .db(move |conn| {
            let id = db::create_user(conn, &username, &hash, &email, role).map_err(|e| {
                if db::is_unique_violation(&e) {
                    ApiError::Conflict("That username or email is already in use".into())
                } else {
                    e.into()
                }
            })?;
            if role == ROLE_SITE_MANAGER {
                db::set_user_sites(conn, id, &p.site_ids)?;
            }
            audit::record(conn, &admin.0, "user.create", Some(&username), Some(role));
            Ok((id, username))
        })
        .await?;
    let (id, username) = id;
    if role == ROLE_ADMIN {
        crate::services::alerts::notify_event(
            &state.config,
            &state.pool,
            "Security: new administrator",
            &format!("{actor_name} created the administrator account '{username}'."),
        );
    }
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub site_ids: Vec<i64>,
}

pub async fn update_user(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<UpdateUserRequest>,
) -> ApiResult<impl IntoResponse> {
    let email = validate::email(&p.email).map_err(ApiError::BadRequest)?;
    let role = role(&p.role)?;
    state
        .db(move |conn| {
            let user = db::find_user_by_id(conn, id)?.ok_or(ApiError::NotFound("User"))?;
            if user.role == ROLE_ADMIN && role != ROLE_ADMIN && db::count_admins(conn)? <= 1 {
                return Err(ApiError::BadRequest("At least one administrator is required".into()));
            }
            db::update_user(conn, id, &email, role).map_err(|e| {
                if db::is_unique_violation(&e) {
                    ApiError::Conflict("That email is already in use".into())
                } else {
                    ApiError::from(e)
                }
            })?;
            db::set_user_sites(conn, id, if role == ROLE_SITE_MANAGER { &p.site_ids } else { &[] })?;
            audit::record(conn, &admin.0, "user.update", Some(&user.username), Some(role));
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_user(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    if id == admin.0.id {
        return Err(ApiError::BadRequest("You cannot delete your own account".into()));
    }
    state
        .db(move |conn| {
            let user = db::find_user_by_id(conn, id)?.ok_or(ApiError::NotFound("User"))?;
            if user.role == ROLE_ADMIN && db::count_admins(conn)? <= 1 {
                return Err(ApiError::BadRequest("At least one administrator is required".into()));
            }
            db::delete_user(conn, id)?;
            audit::record(conn, &admin.0, "user.delete", Some(&user.username), None);
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

pub async fn reset_password(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<ResetPasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    validate::password(&p.password).map_err(ApiError::BadRequest)?;
    let pw = p.password;
    let hash = blocking(move || hash_password(&pw).map_err(ApiError::internal)).await?;
    state
        .db(move |conn| {
            let user = db::find_user_by_id(conn, id)?.ok_or(ApiError::NotFound("User"))?;
            db::set_user_password(conn, &user.username, &hash)?;
            audit::record(conn, &admin.0, "user.password_reset", Some(&user.username), None);
            Ok(())
        })
        .await?;
    Ok(Json(
        json!({ "message": "Password reset; the user's sessions were signed out" }),
    ))
}

pub async fn reset_2fa(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let actor_name = admin.0.username.clone();
    state
        .db(move |conn| {
            let user = db::find_user_by_id(conn, id)?.ok_or(ApiError::NotFound("User"))?;
            db::disable_totp(conn, id)?;
            db::bump_token_version(conn, id)?;
            audit::record(conn, &admin.0, "user.2fa_reset", Some(&user.username), None);
            Ok(user.username)
        })
        .await
        .map(|name| {
            crate::services::alerts::notify_event(
                &state.config,
                &state.pool,
                "Security: two-factor authentication reset",
                &format!("{actor_name} turned off 2FA for '{name}'."),
            );
        })?;
    Ok(Json(
        json!({ "message": "Two-factor authentication was turned off for this user" }),
    ))
}
