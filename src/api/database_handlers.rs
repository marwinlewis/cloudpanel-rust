use crate::api::download::{file_response, receive_upload};
use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::AuthUser;
use crate::authz::require_site;
use crate::db::{self, models::Database};
use crate::services::databases::{self, Engine, ALL};
use crate::state::SharedState;
use crate::validate;
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;

pub fn upload_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(4 * 1024 * 1024 * 1024)
}

fn engine_of(d: &Database) -> ApiResult<Engine> {
    Engine::parse(&d.engine).ok_or_else(|| ApiError::internal("unknown engine"))
}

/// Load a database and the site it belongs to, checking access.
fn load(conn: &Connection, user: &AuthUser, id: i64) -> ApiResult<(Database, crate::db::models::Site)> {
    let d = db::find_database(conn, id)?.ok_or(ApiError::NotFound("Database"))?;
    let site = require_site(conn, user, d.site_id).map_err(|_| ApiError::NotFound("Database"))?;
    Ok((d, site))
}

fn resolve_password(p: Option<&str>) -> ApiResult<String> {
    match p.map(str::trim).filter(|s| !s.is_empty()) {
        Some(pw) => {
            databases::check_password(pw).map_err(ApiError::BadRequest)?;
            Ok(pw.to_string())
        }
        None => Ok(databases::generate_password()),
    }
}

pub async fn list_engines(_user: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let list = crate::state::blocking(move || Ok(ALL.iter().map(|e| e.status(&config)).collect::<Vec<_>>())).await?;
    Ok(Json(list))
}

pub async fn list_site_databases(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let list = state
        .db(move |conn| {
            require_site(conn, &user, id)?;
            Ok(db::list_databases(conn, Some(id))?)
        })
        .await?;
    Ok(Json(list))
}

#[derive(Deserialize)]
pub struct CreateDatabaseRequest {
    pub engine: String,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub async fn create_database(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateDatabaseRequest>,
) -> ApiResult<impl IntoResponse> {
    let engine = Engine::parse(&p.engine).ok_or_else(|| ApiError::BadRequest("Unknown database engine".into()))?;
    let name = validate::db_identifier(&p.name).map_err(ApiError::BadRequest)?;
    let username = match p.username.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(u) if engine.has_users() => Some(validate::db_identifier(u).map_err(ApiError::BadRequest)?),
        _ if engine.has_users() => Some(name.clone()),
        _ => None,
    };
    let password = resolve_password(p.password.as_deref())?;
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            let site = require_site(conn, &user, id)?;
            let st = engine.status(&config);
            if !st.available {
                return Err(ApiError::BadRequest(format!(
                    "{} is not {} on this server",
                    engine.label(),
                    if st.configured {
                        "installed"
                    } else {
                        "enabled (choose it when running the installer)"
                    }
                )));
            }
            if db::list_databases(conn, None)?
                .iter()
                .any(|d| d.engine == engine.as_str() && d.name == name)
            {
                return Err(ApiError::Conflict(format!(
                    "A {} database named {name} already exists",
                    engine.label()
                )));
            }
            if let Some(u) = &username {
                if db::database_user_exists(conn, engine.as_str(), u)? {
                    return Err(ApiError::Conflict(format!("The database user {u} already exists")));
                }
            }
            databases::create_db(&config, engine, &site, &name).map_err(ApiError::Unprocessable)?;
            let db_id = db::create_database(conn, id, engine.as_str(), &name)?;
            if let Some(u) = &username {
                if let Err(e) = databases::create_user(&config, engine, &name, u, &password) {
                    let _ = databases::drop_db(&config, engine, &site, &name, &[]);
                    db::delete_database(conn, db_id)?;
                    return Err(ApiError::Unprocessable(e));
                }
                db::add_database_user(conn, db_id, u)?;
            }
            audit::record(
                conn,
                &user,
                "database.create",
                Some(&site.domain),
                Some(&format!("{}:{name}", engine.as_str())),
            );
            let mut v = json!({ "database": db::find_database(conn, db_id)? });
            if let Some(u) = username {
                v["username"] = json!(u);
                v["password"] = json!(password);
            }
            if engine == Engine::Sqlite {
                v["path"] = json!(databases::sqlite_path(&site, &name)
                    .map(|p| p.to_string_lossy().into_owned())
                    .ok());
            }
            Ok(v)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(out)))
}

pub async fn delete_database(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    state
        .db(move |conn| {
            let (d, site) = load(conn, &user, id)?;
            let engine = engine_of(&d)?;
            databases::drop_db(&config, engine, &site, &d.name, &d.users).map_err(ApiError::Unprocessable)?;
            db::delete_database(conn, id)?;
            audit::record(
                conn,
                &user,
                "database.delete",
                Some(&site.domain),
                Some(&format!("{}:{}", d.engine, d.name)),
            );
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct DbUserRequest {
    pub username: String,
    pub password: Option<String>,
}

pub async fn add_database_user(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<DbUserRequest>,
) -> ApiResult<impl IntoResponse> {
    let username = validate::db_identifier(&p.username).map_err(ApiError::BadRequest)?;
    let password = resolve_password(p.password.as_deref())?;
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            let (d, site) = load(conn, &user, id)?;
            let engine = engine_of(&d)?;
            if !engine.has_users() {
                return Err(ApiError::BadRequest("SQLite databases have no users".into()));
            }
            if db::database_user_exists(conn, engine.as_str(), &username)? {
                return Err(ApiError::Conflict(format!(
                    "The database user {username} already exists"
                )));
            }
            databases::create_user(&config, engine, &d.name, &username, &password).map_err(ApiError::Unprocessable)?;
            db::add_database_user(conn, id, &username)?;
            audit::record(
                conn,
                &user,
                "database.user_create",
                Some(&site.domain),
                Some(&format!("{}:{username}", d.name)),
            );
            Ok(json!({ "username": username, "password": password }))
        })
        .await?;
    Ok((StatusCode::CREATED, Json(out)))
}

pub async fn delete_database_user(
    Path((id, username)): Path<(i64, String)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let username = validate::db_identifier(&username).map_err(ApiError::BadRequest)?;
    let config = state.config.clone();
    state
        .db(move |conn| {
            let (d, site) = load(conn, &user, id)?;
            if !d.users.contains(&username) {
                return Err(ApiError::NotFound("Database user"));
            }
            databases::drop_user(&config, engine_of(&d)?, &d.name, &username).map_err(ApiError::Unprocessable)?;
            db::delete_database_user(conn, id, &username)?;
            audit::record(
                conn,
                &user,
                "database.user_delete",
                Some(&site.domain),
                Some(&format!("{}:{username}", d.name)),
            );
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct DbPasswordRequest {
    pub password: Option<String>,
}

pub async fn set_database_password(
    Path((id, username)): Path<(i64, String)>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<DbPasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    let username = validate::db_identifier(&username).map_err(ApiError::BadRequest)?;
    let password = resolve_password(p.password.as_deref())?;
    let config = state.config.clone();
    let out = state
        .db(move |conn| {
            let (d, site) = load(conn, &user, id)?;
            if !d.users.contains(&username) {
                return Err(ApiError::NotFound("Database user"));
            }
            databases::set_password(&config, engine_of(&d)?, &d.name, &username, &password)
                .map_err(ApiError::Unprocessable)?;
            audit::record(
                conn,
                &user,
                "database.password",
                Some(&site.domain),
                Some(&format!("{}:{username}", d.name)),
            );
            Ok(json!({ "username": username, "password": password }))
        })
        .await?;
    Ok(Json(out))
}

pub async fn export_database(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<axum::response::Response> {
    let config = state.config.clone();
    let (path, name) = state
        .db(move |conn| {
            let (d, site) = load(conn, &user, id)?;
            let engine = engine_of(&d)?;
            let name = format!(
                "{}-{}.{}",
                d.name,
                chrono::Utc::now().format("%Y%m%d-%H%M%S"),
                engine.dump_ext()
            );
            let dir = crate::services::backups::exports_dir(&config);
            crate::fsutil::create_private_dir(&dir, 0o700).map_err(ApiError::internal)?;
            let path = dir.join(format!("{}-{}", crate::auth::random_password(8), name));
            databases::export(&config, engine, &site, &d.name, &path).map_err(ApiError::Unprocessable)?;
            audit::record(conn, &user, "database.export", Some(&site.domain), Some(&d.name));
            Ok((path, name))
        })
        .await?;
    // The export is removed by the scheduler after an hour.
    file_response(path, &name).await
}

pub async fn import_database(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    mp: Multipart,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    // Check access before accepting a large body.
    let actor = user.clone();
    state.db(move |conn| load(conn, &actor, id).map(|_| ())).await?;
    let upload = receive_upload(
        mp,
        &crate::services::backups::exports_dir(&config),
        4 * 1024 * 1024 * 1024,
    )
    .await?;
    let lower = upload.file_name.to_lowercase();
    // Keep the extension so the importer can detect gzip.
    let ext = [".sql.gz", ".sql", ".archive.gz", ".archive", ".gz", ".sqlite", ".db"]
        .iter()
        .find(|e| lower.ends_with(*e))
        .copied()
        .unwrap_or("");
    let named = upload.temp_path.with_extension(format!("import{ext}"));
    std::fs::rename(&upload.temp_path, &named).map_err(ApiError::internal)?;
    let result = state
        .db(move |conn| {
            let (d, site) = load(conn, &user, id)?;
            let r = databases::import(&config, engine_of(&d)?, &site, &d.name, &named);
            let _ = std::fs::remove_file(&named);
            r.map_err(ApiError::Unprocessable)?;
            audit::record(conn, &user, "database.import", Some(&site.domain), Some(&d.name));
            Ok(())
        })
        .await;
    drop(upload);
    result?;
    Ok(Json(json!({ "message": "Import complete" })))
}
