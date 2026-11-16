//! GitHub Actions self-hosted runners.
//!
//! A runner belongs to a site, and the managers of that site manage it. Runners adopted from a
//! user that owns no site belong to no site, and only administrators see them. Stored GitHub
//! tokens, installing the runner release and adopting runners are for administrators.
//!
//! `POST /runner-hook/deploy` is how a runner's workflow deploys its own site: it signs in with
//! the deploy token from the runner's unit, which works for that one site only.

use crate::api::error::{ApiError, ApiResult};
use crate::audit;
use crate::auth::{AdminUser, AuthUser};
use crate::authz::{require_site, visible_sites};
use crate::config::Config;
use crate::db::{self, models::Runner, DbPool, NewRunner};
use crate::secrets;
use crate::services::apps::{self, AppAction};
use crate::services::runners::{self, Found, Registration};
use crate::services::runtimes;
use crate::state::{blocking, SharedState};
use crate::validate;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Load a runner the user may manage. Other people's runners look missing.
fn require_runner(conn: &Connection, user: &AuthUser, id: i64) -> ApiResult<Runner> {
    let r = db::find_runner(conn, id)?.ok_or(ApiError::NotFound("Runner"))?;
    if user.is_admin() {
        return Ok(r);
    }
    match r.site_id {
        Some(site) if db::user_has_site(conn, user.id, site)? => Ok(r),
        _ => Err(ApiError::NotFound("Runner")),
    }
}

fn not_installed() -> ApiError {
    ApiError::BadRequest(
        "GitHub runners are not installed. An administrator can install them on the Runners page.".into(),
    )
}

fn home_of(r: &Runner) -> String {
    runners::home_of(&r.system_user).unwrap_or_else(|| r.dir.clone())
}

/// The decrypted token of a stored credential.
fn credential_token(config: &Config, conn: &Connection, id: i64) -> ApiResult<String> {
    let c = db::find_github_credential(conn, id)?.ok_or(ApiError::NotFound("GitHub token"))?;
    secrets::decrypt(&config.etc_dir, &c.token_sealed).map_err(ApiError::internal)
}

/// A pasted registration or removal token: GitHub's are ~29 base32 characters.
fn pasted_token(input: Option<&str>) -> ApiResult<Option<String>> {
    let Some(t) = input.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if t.len() > 200 || !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(ApiError::BadRequest(
            "That doesn't look like a token from GitHub".into(),
        ));
    }
    Ok(Some(t.to_string()))
}

// ---------- Overview ----------

pub async fn list_runners(user: AuthUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let u = user.clone();
    let (rows, sites, creds) = state
        .db(move |conn| {
            let sites = visible_sites(conn, &u)?;
            let ids: Vec<i64> = sites.iter().map(|s| s.id).collect();
            let rows: Vec<Runner> = db::list_runners(conn, None)?
                .into_iter()
                .filter(|r| u.is_admin() || r.site_id.is_some_and(|s| ids.contains(&s)))
                .collect();
            let creds = if u.is_admin() {
                db::list_github_credentials(conn)?
            } else {
                Vec::new()
            };
            Ok((rows, sites, creds))
        })
        .await?;
    let config = state.config.clone();
    let admin = user.is_admin();
    let dirs: Vec<String> = if admin {
        let conn_rows = state.db(|conn| Ok(db::list_runners(conn, None)?)).await?;
        conn_rows.into_iter().map(|r| r.dir).collect()
    } else {
        Vec::new()
    };
    let rows_c = rows.clone();
    let (installed, can_install, statuses, unmanaged) = blocking(move || {
        let statuses: Vec<_> = rows_c.iter().map(|r| runners::status(&config, r)).collect();
        let unmanaged = if admin { runners::scan(&config, &dirs).len() } else { 0 };
        Ok((
            runners::installed(&config),
            runners::can_install(&config),
            statuses,
            unmanaged,
        ))
    })
    .await?;
    let remote = remote_states(&state, &rows).await;
    let runners: Vec<Value> = rows
        .iter()
        .zip(statuses)
        .map(|(r, st)| {
            let mut v = json!(r);
            v["status"] = json!(st);
            v["org"] = json!(r.is_org());
            v["deploy_hook"] = json!(r.deploy_token_hash.is_some());
            v["github"] = remote.get(&r.id).cloned().unwrap_or(Value::Null);
            v
        })
        .collect();
    let sites: Vec<Value> = sites
        .iter()
        .map(|s| json!({ "id": s.id, "domain": s.domain, "has_user": s.home_dir.is_some(), "system_user": s.system_user }))
        .collect();
    let credentials: Vec<Value> = creds
        .iter()
        .map(|c| json!({ "id": c.id, "name": c.name, "created_at": c.created_at }))
        .collect();
    Ok(Json(json!({
        "installed": installed,
        "can_install": can_install,
        "version": runners::VERSION,
        "is_admin": admin,
        "hook_url": runners::hook_url(&state.config),
        "runners": runners,
        "sites": sites,
        "credentials": credentials,
        "unmanaged": unmanaged,
    })))
}

/// What GitHub says about runners registered with a stored token, by runner id. Errors and
/// timeouts just leave runners out.
async fn remote_states(state: &SharedState, rows: &[Runner]) -> HashMap<i64, Value> {
    let mut groups: HashMap<(i64, String), Vec<(i64, String)>> = HashMap::new();
    for r in rows {
        if let Some(c) = r.credential_id {
            groups
                .entry((c, r.github_url.clone()))
                .or_default()
                .push((r.id, r.name.clone()));
        }
    }
    let mut out = HashMap::new();
    if groups.is_empty() {
        return out;
    }
    let config = state.config.clone();
    let cred_ids: Vec<i64> = groups.keys().map(|(c, _)| *c).collect();
    let Ok(tokens) = state
        .db(move |conn| {
            let mut m = HashMap::new();
            for id in cred_ids {
                if let Ok(t) = credential_token(&config, conn, id) {
                    m.insert(id, t);
                }
            }
            Ok(m)
        })
        .await
    else {
        return out;
    };
    let api = state.config.github_api_url.clone();
    let lookups = groups.into_iter().filter_map(|((cred, url), members)| {
        let token = tokens.get(&cred)?.clone();
        let api = api.clone();
        Some(async move {
            let res = tokio::time::timeout(Duration::from_secs(10), runners::list_remote(&api, &token, &url)).await;
            (members, res.ok().and_then(Result::ok))
        })
    });
    for (members, list) in futures_util::future::join_all(lookups).await {
        let Some(list) = list else { continue };
        for (id, name) in members {
            let v = list
                .iter()
                .find(|x| x.name == name)
                .map(|x| json!({ "status": x.status, "busy": x.busy }))
                .unwrap_or_else(|| json!({ "status": "not registered", "busy": false }));
            out.insert(id, v);
        }
    }
    out
}

pub async fn install(admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    if !runners::can_install(&state.config) {
        return Err(ApiError::BadRequest(
            "This system can't install GitHub runners from the panel. Run the CloudPanel installer with --with-runners."
                .into(),
        ));
    }
    let exe = std::env::current_exe().map_err(ApiError::internal)?;
    let actor = admin.0.clone();
    state
        .db(move |conn| {
            audit::record(conn, &actor, "runner.install", None, Some(runners::VERSION));
            Ok(())
        })
        .await?;
    let job_id = crate::jobs::spawn(&state.pool, "runner.install", None, Some(admin.0.id), move |log| {
        let exe = exe.to_string_lossy().into_owned();
        let r = crate::services::cmd::run_host_streaming(
            &exe,
            &["runners-install"],
            &crate::services::cmd::CmdOpts::default().timeout(30 * 60),
            &mut |l, _| log.line(l),
        );
        if r.success() {
            Ok(())
        } else {
            Err(format!(
                "Installing the runner release failed (exit code {})",
                r.code.unwrap_or(-1)
            ))
        }
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- Creating ----------

#[derive(Deserialize)]
pub struct CreateRunner {
    pub site_id: Option<i64>,
    #[serde(default)]
    pub url: String,
    pub name: Option<String>,
    pub labels: Option<String>,
    pub group: Option<String>,
    /// A registration token copied from GitHub.
    pub token: Option<String>,
    /// Or a stored GitHub token the panel asks for one with (administrators only).
    pub credential_id: Option<i64>,
}

/// Create the runner's row, deploy token and unit, once GitHub has accepted it.
fn finish(pool: &DbPool, config: &Config, new: &NewRunner, token: Option<&str>) -> Result<Runner, String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let id = db::create_runner(&conn, new).map_err(|e| e.to_string())?;
    let r = db::find_runner(&conn, id)
        .map_err(|e| e.to_string())?
        .ok_or("The runner disappeared")?;
    drop(conn);
    runners::apply(config, &r, token)?;
    Ok(r)
}

pub async fn create_runner(
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateRunner>,
) -> ApiResult<impl IntoResponse> {
    let site_id = p.site_id.ok_or_else(|| ApiError::BadRequest("Choose a site".into()))?;
    let (url, _, repo) = validate::github_url(&p.url).map_err(ApiError::BadRequest)?;
    let labels = validate::runner_labels(p.labels.as_deref().unwrap_or("")).map_err(ApiError::BadRequest)?;
    // Repository runners always join the default group.
    let group = if repo.is_none() {
        validate::runner_group(p.group.as_deref().unwrap_or("")).map_err(ApiError::BadRequest)?
    } else {
        String::new()
    };
    let token = pasted_token(p.token.as_deref())?;
    if token.is_some() == p.credential_id.is_some() {
        return Err(ApiError::BadRequest(
            "Paste a registration token from GitHub, or choose a saved GitHub token".into(),
        ));
    }
    if p.credential_id.is_some() && !user.is_admin() {
        return Err(ApiError::Forbidden);
    }
    let actor = user.clone();
    let config = state.config.clone();
    let cred = p.credential_id;
    let name_in = p.name.clone();
    let (site, name, dir, pat) = state
        .db(move |conn| {
            let site = require_site(conn, &actor, site_id)?;
            let home = site
                .home_dir
                .clone()
                .ok_or_else(|| ApiError::BadRequest("This site has no Linux user to run a runner as".into()))?;
            let name = match name_in.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
                Some(n) => validate::runner_name(n).map_err(ApiError::BadRequest)?,
                None => {
                    let taken: Vec<String> = db::list_runners(conn, None)?.into_iter().map(|r| r.name).collect();
                    let base = site.domain.replace('.', "-");
                    (1..)
                        .map(|i| format!("{base}-{i}"))
                        .find(|n| !taken.contains(n))
                        .unwrap_or(base)
                }
            };
            let dir = format!("{home}/{}/{name}", runners::RUNNERS_DIR);
            if !runners::plain_path(&dir) {
                return Err(ApiError::BadRequest(format!("{dir} can't be used for a runner")));
            }
            if db::list_runners(conn, None)?.iter().any(|r| r.dir == dir) {
                return Err(ApiError::Conflict(format!(
                    "This site already has a runner named {name}"
                )));
            }
            let pat = cred.map(|c| credential_token(&config, conn, c)).transpose()?;
            audit::record(conn, &actor, "runner.create", Some(&site.domain), Some(&name));
            Ok((site, name, dir, pat))
        })
        .await?;
    if !runners::installed(&state.config) && !cfg!(test) {
        return Err(not_installed());
    }
    let config = state.config.clone();
    let pool = state.pool.clone();
    let handle = tokio::runtime::Handle::current();
    let target = site.domain.clone();
    let job_id = crate::jobs::spawn(&state.pool, "runner.create", Some(&target), Some(user.id), move |log| {
        let home = site.home_dir.clone().unwrap_or_default();
        let reg_token = match (token, pat) {
            (Some(t), _) => t,
            (None, Some(pat)) => {
                log.line("Asking GitHub for a registration token");
                handle.block_on(runners::registration_token(&config.github_api_url, &pat, &url))?
            }
            (None, None) => return Err("No registration token".into()),
        };
        runners::unpack_and_register(
            &config,
            &site.system_user,
            &home,
            &dir,
            &Registration {
                url: &url,
                token: &reg_token,
                name: &name,
                labels: &labels,
                group: &group,
            },
            &|l| log.line(l),
        )?;
        let (deploy_token, hash) = runners::new_deploy_token();
        let r = finish(
            &pool,
            &config,
            &NewRunner {
                site_id: Some(site.id),
                name: &name,
                github_url: &url,
                labels: &labels,
                runner_group: &group,
                system_user: &site.system_user,
                dir: &dir,
                credential_id: cred,
                deploy_token_hash: Some(&hash),
                adopted: false,
            },
            Some(&deploy_token),
        )?;
        log.line(&format!(
            "Runner {} is running as {} ({}).",
            r.name,
            r.system_user,
            runners::unit_name(r.id)
        ));
        Ok(())
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- One runner ----------

pub async fn get_runner(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let r = state.db(move |conn| require_runner(conn, &user, id)).await?;
    let config = state.config.clone();
    let rc = r.clone();
    let st = blocking(move || Ok(runners::status(&config, &rc))).await?;
    let mut v = json!(r);
    v["status"] = json!(st);
    v["org"] = json!(r.is_org());
    Ok(Json(v))
}

pub async fn runner_action(
    Path((id, action)): Path<(i64, String)>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let act = runners::Action::parse(&action).ok_or(ApiError::NotFound("Action"))?;
    let r = state
        .db(move |conn| {
            let r = require_runner(conn, &user, id)?;
            audit::record(conn, &user, &format!("runner.{action}"), Some(&r.name), None);
            Ok(r)
        })
        .await?;
    let config = state.config.clone();
    blocking(move || {
        if !runners::unit_path(&config, r.id).exists() && !cfg!(test) {
            return Err(ApiError::BadRequest(
                "This runner has no unit; remove it and add it again".into(),
            ));
        }
        runners::act(r.id, act).map_err(ApiError::Unprocessable)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct LogsQuery {
    pub lines: Option<usize>,
}

pub async fn runner_logs(
    Path(id): Path<i64>,
    Query(q): Query<LogsQuery>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let r = state.db(move |conn| require_runner(conn, &user, id)).await?;
    let lines = q.lines.unwrap_or(200).clamp(10, 2000);
    let logs = blocking(move || runners::logs(r.id, lines).map_err(ApiError::Unprocessable)).await?;
    Ok(Json(json!({ "logs": logs })))
}

/// Give the runner a new deploy token, which also restarts it.
pub async fn rotate_deploy_token(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    let (token, hash) = runners::new_deploy_token();
    let r = state
        .db(move |conn| {
            let r = require_runner(conn, &user, id)?;
            if r.site_id.is_none() {
                return Err(ApiError::BadRequest(
                    "This runner belongs to no site, so it has nothing to deploy".into(),
                ));
            }
            db::set_runner_deploy_token(conn, r.id, Some(&hash))?;
            audit::record(conn, &user, "runner.deploy_token", Some(&r.name), None);
            Ok(r)
        })
        .await?;
    let config = state.config.clone();
    blocking(move || runners::apply(&config, &r, Some(&token)).map_err(ApiError::Unprocessable)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
pub struct RemoveRunner {
    /// A removal token copied from GitHub.
    pub token: Option<String>,
    /// Remove it here even though GitHub isn't told; it then shows offline there.
    #[serde(default)]
    pub force: bool,
}

pub async fn remove_runner(
    Path(id): Path<i64>,
    user: AuthUser,
    State(state): State<SharedState>,
    Json(p): Json<RemoveRunner>,
) -> ApiResult<impl IntoResponse> {
    let pasted = pasted_token(p.token.as_deref())?;
    let no_paste = pasted.is_none();
    let config = state.config.clone();
    let actor = user.clone();
    let (r, pat) = state
        .db(move |conn| {
            let r = require_runner(conn, &actor, id)?;
            let pat = match (no_paste, r.credential_id) {
                (true, Some(c)) => credential_token(&config, conn, c).ok(),
                _ => None,
            };
            audit::record(conn, &actor, "runner.remove", Some(&r.name), p.force.then_some("force"));
            Ok((r, pat))
        })
        .await?;
    if pasted.is_none() && pat.is_none() && !p.force {
        return Err(ApiError::BadRequest(
            "Paste a removal token from GitHub, or remove the runner from this server only".into(),
        ));
    }
    let config = state.config.clone();
    let pool = state.pool.clone();
    let handle = tokio::runtime::Handle::current();
    let force = p.force;
    let target = r.name.clone();
    let job_id = crate::jobs::spawn(&state.pool, "runner.remove", Some(&target), Some(user.id), move |log| {
        let home = home_of(&r);
        log.line(&format!("Stopping {}", runners::unit_name(r.id)));
        let _ = apps::systemctl(&["stop", &runners::unit_name(r.id)]);
        let token = match (pasted, pat) {
            (Some(t), _) => Some(t),
            (None, Some(pat)) => {
                log.line("Asking GitHub for a removal token");
                match handle.block_on(runners::removal_token(&config.github_api_url, &pat, &r.github_url)) {
                    Ok(t) => Some(t),
                    Err(e) if force => {
                        log.line(&e);
                        None
                    }
                    Err(e) => {
                        let _ = runners::act(r.id, runners::Action::Start);
                        return Err(e);
                    }
                }
            }
            (None, None) => None,
        };
        if let Some(t) = token {
            if std::path::Path::new(&r.dir).join(".runner").is_file() {
                if let Err(e) = runners::unregister(&r, &home, &t, &|l| log.line(l)) {
                    if !force {
                        let _ = runners::act(r.id, runners::Action::Start);
                        return Err(e);
                    }
                    log.line(&e);
                }
            }
        }
        if force {
            log.line("GitHub was not told: delete the runner there too (Settings → Actions → Runners).");
        }
        runners::remove_unit(&config, r.id);
        runners::delete_dir(&r, &home);
        let conn = pool.get().map_err(|e| e.to_string())?;
        db::delete_runner(&conn, r.id).map_err(|e| e.to_string())?;
        log.line(&format!("Runner {} was removed.", r.name));
        Ok(())
    })
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- Adopting runners installed by hand ----------

/// Runners on this machine the panel doesn't manage, with the site of their user, if any.
fn scan_with_sites(conn: &Connection, config: &Config) -> ApiResult<Vec<Found>> {
    let managed: Vec<String> = db::list_runners(conn, None)?.into_iter().map(|r| r.dir).collect();
    let sites = db::list_sites(conn)?;
    let mut found = runners::scan(config, &managed);
    for f in &mut found {
        if let Some(s) = sites.iter().find(|s| s.home_dir.is_some() && s.system_user == f.user) {
            f.site_id = Some(s.id);
            f.site_domain = Some(s.domain.clone());
        }
    }
    Ok(found)
}

pub async fn scan(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let found = state.db(move |conn| scan_with_sites(conn, &config)).await?;
    Ok(Json(json!({ "runners": found })))
}

#[derive(Deserialize)]
pub struct AdoptRunner {
    #[serde(default)]
    pub dir: String,
}

pub async fn adopt(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<AdoptRunner>,
) -> ApiResult<impl IntoResponse> {
    let config = state.config.clone();
    let actor = admin.0.clone();
    let found = state
        .db(move |conn| {
            // What the scan finds now, not what the request says about it.
            let f = scan_with_sites(conn, &config)?
                .into_iter()
                .find(|f| f.dir == p.dir)
                .ok_or(ApiError::NotFound("Runner"))?;
            if let Some(problem) = &f.problem {
                return Err(ApiError::BadRequest(problem.clone()));
            }
            validate::github_url(&f.github_url).map_err(ApiError::BadRequest)?;
            audit::record(conn, &actor, "runner.adopt", Some(&f.name), Some(&f.dir));
            Ok(f)
        })
        .await?;
    let config = state.config.clone();
    let pool = state.pool.clone();
    let target = found.name.clone();
    let job_id = crate::jobs::spawn(
        &state.pool,
        "runner.adopt",
        Some(&target),
        Some(admin.0.id),
        move |log| {
            runners::adopt(&config, &found, &|l| log.line(l))?;
            let (url, _, _) = validate::github_url(&found.github_url)?;
            let deploy = found.site_id.map(|_| runners::new_deploy_token());
            let r = finish(
                &pool,
                &config,
                &NewRunner {
                    site_id: found.site_id,
                    name: &found.name,
                    github_url: &url,
                    labels: "",
                    runner_group: "",
                    system_user: &found.user,
                    dir: &found.dir,
                    credential_id: None,
                    deploy_token_hash: deploy.as_ref().map(|(_, h)| h.as_str()),
                    adopted: true,
                },
                deploy.as_ref().map(|(t, _)| t.as_str()),
            )?;
            log.line(&format!(
                "Runner {} is now managed by the panel ({}).",
                r.name,
                runners::unit_name(r.id)
            ));
            Ok(())
        },
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({ "job_id": job_id })))
}

// ---------- Stored GitHub tokens ----------

pub async fn list_credentials(_admin: AdminUser, State(state): State<SharedState>) -> ApiResult<impl IntoResponse> {
    let creds = state.db(|conn| Ok(db::list_github_credentials(conn)?)).await?;
    Ok(Json(json!({ "credentials": creds })))
}

#[derive(Deserialize)]
pub struct CreateCredential {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub token: String,
}

pub async fn create_credential(
    admin: AdminUser,
    State(state): State<SharedState>,
    Json(p): Json<CreateCredential>,
) -> ApiResult<impl IntoResponse> {
    let name = p.name.trim().to_string();
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "Give the token a name of up to 64 characters".into(),
        ));
    }
    let token = p.token.trim().to_string();
    if token.len() < 20 || token.len() > 255 || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ApiError::BadRequest(
            "That doesn't look like a GitHub token (ghp_…, github_pat_…)".into(),
        ));
    }
    let sealed = secrets::encrypt(&state.config.etc_dir, &token).map_err(ApiError::internal)?;
    let id = state
        .db(move |conn| {
            if db::list_github_credentials(conn)?
                .iter()
                .any(|c| c.name.eq_ignore_ascii_case(&name))
            {
                return Err(ApiError::Conflict(format!("A token named {name} already exists")));
            }
            let id = db::create_github_credential(conn, &name, &sealed)?;
            audit::record(conn, &admin.0, "github_token.create", Some(&name), None);
            Ok(id)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

pub async fn delete_credential(
    Path(id): Path<i64>,
    admin: AdminUser,
    State(state): State<SharedState>,
) -> ApiResult<impl IntoResponse> {
    state
        .db(move |conn| {
            let c = db::find_github_credential(conn, id)?.ok_or(ApiError::NotFound("GitHub token"))?;
            db::delete_github_credential(conn, id)?;
            audit::record(conn, &admin.0, "github_token.delete", Some(&c.name), None);
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- Deploy hook ----------

#[derive(Deserialize)]
pub struct HookRequest {
    /// `deploy` (install, build, restart; the default), `restart` or `reload` (PM2).
    pub action: Option<String>,
    /// Answer once the deploy has finished, with its log. Lets the workflow step fail with it.
    #[serde(default)]
    pub wait: bool,
}

/// One deploy per runner (by its token) every few seconds.
static LAST_HOOK: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);
const HOOK_INTERVAL: Duration = Duration::from_secs(3);

fn throttle(key: &str) -> ApiResult<()> {
    let mut guard = LAST_HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    map.retain(|_, t| now.duration_since(*t) < HOOK_INTERVAL);
    if map.contains_key(key) {
        return Err(ApiError::TooManyRequests(HOOK_INTERVAL.as_secs()));
    }
    map.insert(key.to_string(), now);
    Ok(())
}

pub async fn hook_deploy(
    State(state): State<SharedState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(p): Json<HookRequest>,
) -> ApiResult<impl IntoResponse> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.starts_with("cpr_"))
        .ok_or_else(|| ApiError::Unauthorized("A runner deploy token is required".into()))?
        .to_string();
    let action = p.action.as_deref().unwrap_or("deploy").to_string();
    if !matches!(action.as_str(), "deploy" | "restart" | "reload") {
        return Err(ApiError::BadRequest("action is deploy, restart or reload".into()));
    }
    let hash = crate::auth::jwt::token_hash(&token);
    let throttle_key = hash.clone();
    let ip = connect.map(|c| c.0.ip().to_string());
    let act = action.clone();
    let (runner, site) = state
        .db(move |conn| {
            let r = db::find_runner_by_deploy_token(conn, &hash)?
                .ok_or_else(|| ApiError::Unauthorized("Unknown deploy token".into()))?;
            let site_id = r
                .site_id
                .ok_or_else(|| ApiError::Unauthorized("Unknown deploy token".into()))?;
            let site = db::find_site_by_id(conn, site_id)?
                .ok_or_else(|| ApiError::Unauthorized("Unknown deploy token".into()))?;
            audit::record_system(
                conn,
                Some(&format!("runner:{}", r.name)),
                ip.as_deref(),
                &format!("runner.hook.{act}"),
                Some(&site.domain),
                None,
            );
            Ok((r, site))
        })
        .await?;
    throttle(&throttle_key)?;
    if site.home_dir.is_none() {
        return Err(ApiError::BadRequest("This site has no Linux user".into()));
    }
    let config = state.config.clone();
    let kind = format!("runner.{action}");
    let target = site.domain.clone();
    let job_id = crate::jobs::spawn(&state.pool, &kind, Some(&target), None, move |log| {
        log.line(&format!("Requested by runner {}", runner.name));
        match action.as_str() {
            "restart" => apps::act(&config, &site, AppAction::Restart),
            "reload" => apps::act(&config, &site, AppAction::Reload),
            _ => {
                if site.kind() == Some(crate::db::models::SiteType::Nodejs) {
                    runtimes::ensure_nodejs(&config, &|l| log.line(l))?;
                }
                apps::deploy(&config, &site, log)
            }
        }
    })
    .map_err(ApiError::internal)?;
    if !p.wait {
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "job_id": job_id, "status": "running" })),
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(30 * 60);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let job = state
            .db(move |conn| db::find_job(conn, job_id)?.ok_or(ApiError::NotFound("Job")))
            .await?;
        if job.status != "running" || Instant::now() > deadline {
            let code = match job.status.as_str() {
                "succeeded" => StatusCode::OK,
                "running" => StatusCode::ACCEPTED,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            return Ok((
                code,
                Json(json!({ "job_id": job_id, "status": job.status, "output": job.output })),
            ));
        }
    }
}
