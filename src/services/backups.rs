//! Site backups: a `.tar.gz` of the site home plus a dump of each site database and a
//! JSON manifest, stored under `backup_dir/<domain>/` and optionally copied to S3.

use super::cmd::CmdOpts;
use super::databases::{self, Engine};
use super::s3::{self, S3Config};
use super::{apps, sysusers};
use crate::config::Config;
use crate::db::{self, models::Site, DbPool};
use crate::jobs::JobLog;
use crate::state::SharedState;
use chrono::{Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const S3_SETTING: &str = "backup_s3";

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub domain: String,
    pub site_type: String,
    pub system_user: String,
    pub home_name: String,
    pub created_at: chrono::DateTime<Utc>,
    pub databases: Vec<ManifestDb>,
}

#[derive(Serialize, Deserialize)]
pub struct ManifestDb {
    pub engine: String,
    pub name: String,
    pub file: String,
}

pub fn remote_config(config: &Config, conn: &rusqlite::Connection) -> Option<S3Config> {
    let sealed = db::get_setting(conn, S3_SETTING).ok()??;
    crate::secrets::open(&config.etc_dir, &sealed).ok()
}

pub fn exports_dir(config: &Config) -> PathBuf {
    config.backup_dir.join("exports")
}

fn tar(args: &[&str], log: &JobLog) -> Result<(), String> {
    let r = super::cmd::run_streaming("tar", args, &CmdOpts::default().timeout(6 * 3600), &mut |l, _| {
        log.line(l)
    });
    if r.missing {
        return Err("tar is not installed".into());
    }
    // GNU tar exits 1 when files changed while reading ("file changed as we read it").
    match r.code {
        Some(0) | Some(1) if !r.timed_out => Ok(()),
        _ => Err(format!("tar exited with code {}", r.code.unwrap_or(-1))),
    }
}

/// Create a backup of one site. Runs inside a job.
pub fn backup_site(config: &Config, pool: &DbPool, site_id: i64, log: &JobLog) -> Result<i64, String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let site = db::find_site_by_id(&conn, site_id)
        .map_err(|e| e.to_string())?
        .ok_or("Site not found")?;
    let home = site
        .home_dir
        .clone()
        .ok_or("This site has no home directory to back up")?;
    let home = PathBuf::from(home);
    let home_name = home
        .file_name()
        .ok_or("Invalid home directory")?
        .to_string_lossy()
        .into_owned();
    let home_parent = home.parent().ok_or("Invalid home directory")?.to_path_buf();

    let ts = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let dir = config.backup_dir.join(&site.domain);
    crate::fsutil::create_private_dir(&dir, 0o700).map_err(|e| e.to_string())?;
    let dest = dir.join(format!("{}-{ts}.tar.gz", site.domain));
    let id =
        db::create_backup(&conn, Some(site.id), &site.domain, &dest.to_string_lossy()).map_err(|e| e.to_string())?;
    log.line(&format!("Backing up {} to {}", site.domain, dest.display()));

    let result = (|| -> Result<Option<String>, String> {
        let staging = config.backup_dir.join(".staging").join(format!("{id}"));
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(staging.join("databases")).map_err(|e| e.to_string())?;
        let cleanup = scopeguard(staging.clone());

        let mut dbs = Vec::new();
        for d in db::list_databases(&conn, Some(site.id)).map_err(|e| e.to_string())? {
            let Some(engine) = Engine::parse(&d.engine) else {
                continue;
            };
            let file = format!("{}__{}.{}", engine.as_str(), d.name, engine.dump_ext());
            log.line(&format!("Dumping {} database {}", engine.label(), d.name));
            databases::export(config, engine, &site, &d.name, &staging.join("databases").join(&file))?;
            dbs.push(ManifestDb {
                engine: engine.as_str().into(),
                name: d.name.clone(),
                file,
            });
        }
        let manifest = Manifest {
            version: 1,
            domain: site.domain.clone(),
            site_type: site.site_type.clone(),
            system_user: site.system_user.clone(),
            home_name: home_name.clone(),
            created_at: Utc::now(),
            databases: dbs,
        };
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;

        log.line("Archiving files…");
        let dest_s = dest.to_string_lossy().into_owned();
        let staging_s = staging.to_string_lossy().into_owned();
        let parent_s = home_parent.to_string_lossy().into_owned();
        let ex_cache = format!("--exclude={home_name}/.cache");
        let ex_npm = format!("--exclude={home_name}/.npm");
        tar(
            &[
                "-czf",
                &dest_s,
                &ex_cache,
                &ex_npm,
                "-C",
                &staging_s,
                "manifest.json",
                "databases",
                "-C",
                &parent_s,
                &home_name,
            ],
            log,
        )?;
        crate::fsutil::set_mode(&dest, 0o600).map_err(|e| e.to_string())?;
        drop(cleanup);

        let policy = db::get_backup_policy(&conn, site.id).map_err(|e| e.to_string())?;
        if policy.remote_enabled {
            if let Some(remote) = remote_config(config, &conn) {
                let key = remote.key(&format!(
                    "{}/{}",
                    site.domain,
                    dest.file_name().unwrap_or_default().to_string_lossy()
                ));
                log.line(&format!("Uploading to s3://{}/{key}", remote.bucket));
                s3::upload(&remote, &key, &dest)?;
                return Ok(Some(key));
            }
            log.line("Remote storage is enabled for this site but not configured; skipped upload");
        }
        Ok(None)
    })();

    let size = fs::metadata(&dest).map(|m| m.len() as i64).unwrap_or(0);
    match result {
        Ok(remote_key) => {
            db::finish_backup(&conn, id, size, None, remote_key.as_deref()).map_err(|e| e.to_string())?;
            log.line(&format!("Backup complete ({} bytes)", size));
            prune(config, &conn, &site, log);
            Ok(id)
        }
        Err(e) => {
            let _ = db::finish_backup(&conn, id, size, Some(&e), None);
            let _ = fs::remove_file(&dest);
            crate::services::alerts::notify_event(config, pool, "Backup failed", &format!("{}: {e}", site.domain));
            Err(e)
        }
    }
}

/// Removes a directory when dropped.
struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn scopeguard(p: PathBuf) -> DirGuard {
    DirGuard(p)
}

/// Keep only the newest `retention` successful backups of a site.
fn prune(config: &Config, conn: &rusqlite::Connection, site: &Site, log: &JobLog) {
    let Ok(policy) = db::get_backup_policy(conn, site.id) else {
        return;
    };
    let keep = policy.retention.max(1) as usize;
    let Ok(all) = db::list_backups(conn, Some(site.id)) else {
        return;
    };
    let ok: Vec<_> = all.into_iter().filter(|b| b.status == "ok").collect();
    for b in ok.into_iter().skip(keep) {
        log.line(&format!("Pruning old backup {}", b.file_name));
        let _ = delete(config, conn, b.id);
    }
}

pub fn delete(config: &Config, conn: &rusqlite::Connection, id: i64) -> Result<(), String> {
    let b = db::find_backup(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or("Backup not found")?;
    let path = PathBuf::from(&b.path);
    if path.starts_with(crate::validate::absolute(&config.backup_dir)) || path.starts_with(&config.backup_dir) {
        let _ = fs::remove_file(&path);
    }
    if let (Some(key), Some(remote)) = (&b.remote_key, remote_config(config, conn)) {
        if let Err(e) = s3::delete(&remote, key) {
            tracing::warn!("remote delete of {key} failed: {e}");
        }
    }
    db::delete_backup(conn, id).map_err(|e| e.to_string())?;
    Ok(())
}

/// Restore a site from a backup: files are swapped in atomically, databases re-imported.
pub fn restore(config: &Config, pool: &DbPool, backup_id: i64, log: &JobLog) -> Result<(), String> {
    let conn = pool.get().map_err(|e| e.to_string())?;
    let b = db::find_backup(&conn, backup_id)
        .map_err(|e| e.to_string())?
        .ok_or("Backup not found")?;
    let site_id = b
        .site_id
        .ok_or("The site of this backup was deleted; create the site again first")?;
    let site = db::find_site_by_id(&conn, site_id)
        .map_err(|e| e.to_string())?
        .ok_or("Site not found")?;
    let home = PathBuf::from(site.home_dir.clone().ok_or("Site has no home directory")?);
    let home_parent = home.parent().ok_or("Invalid home")?.to_path_buf();

    let mut archive = PathBuf::from(&b.path);
    let mut downloaded = None;
    if !archive.exists() {
        let key = b
            .remote_key
            .clone()
            .ok_or("The backup file is missing and there is no remote copy")?;
        let remote = remote_config(config, &conn).ok_or("Remote storage is not configured")?;
        let tmp = config
            .backup_dir
            .join(".staging")
            .join(format!("download-{backup_id}.tar.gz"));
        fs::create_dir_all(tmp.parent().unwrap_or(&config.backup_dir)).map_err(|e| e.to_string())?;
        log.line(&format!("Downloading s3://{}/{key}", remote.bucket));
        s3::download(&remote, &key, &tmp)?;
        archive = tmp.clone();
        downloaded = Some(tmp);
    }

    let ts = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let work = home_parent.join(format!(".cloudpanel-restore-{ts}"));
    fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let _guard = DirGuard(work.clone());
    log.line("Extracting backup…");
    tar(
        &[
            "-xzf",
            &archive.to_string_lossy(),
            "-C",
            &work.to_string_lossy(),
            "--no-same-owner",
        ],
        log,
    )?;
    if let Some(d) = downloaded {
        let _ = fs::remove_file(d);
    }
    let manifest: Manifest = serde_json::from_slice(&fs::read(work.join("manifest.json")).map_err(|e| e.to_string())?)
        .map_err(|e| format!("invalid manifest: {e}"))?;
    if manifest.domain != site.domain {
        return Err(format!(
            "This backup belongs to {}, not {}",
            manifest.domain, site.domain
        ));
    }
    let restored_home = work.join(&manifest.home_name);
    if !restored_home.is_dir() {
        return Err("The backup does not contain the site files".into());
    }

    log.line("Stopping the app…");
    let _ = apps::act(&site.domain, apps::AppAction::Stop);
    let old = home_parent.join(format!(".cloudpanel-old-{}-{ts}", manifest.home_name));
    fs::rename(&home, &old).map_err(|e| format!("move current files aside: {e}"))?;
    if let Err(e) = fs::rename(&restored_home, &home) {
        let _ = fs::rename(&old, &home);
        return Err(format!("swap restored files: {e}"));
    }
    let _ = sysusers::chown_recursive(&home, &site.system_user, &site.system_user);
    log.line("Files restored.");

    let existing = db::list_databases(&conn, Some(site.id)).map_err(|e| e.to_string())?;
    for d in &manifest.databases {
        let Some(engine) = Engine::parse(&d.engine) else {
            continue;
        };
        if !existing.iter().any(|x| x.engine == d.engine && x.name == d.name) {
            log.line(&format!("Recreating {} database {}", engine.label(), d.name));
            if engine != Engine::Sqlite {
                databases::create_db(config, engine, &site, &d.name)?;
            }
            db::create_database(&conn, site.id, engine.as_str(), &d.name).map_err(|e| e.to_string())?;
        }
        log.line(&format!("Importing {} database {}", engine.label(), d.name));
        databases::import(config, engine, &site, &d.name, &work.join("databases").join(&d.file))?;
    }

    let _ = fs::remove_dir_all(&old);
    if site.app_enabled {
        log.line("Starting the app…");
        let _ = apps::apply(config, &site);
    }
    log.line("Restore complete.");
    Ok(())
}

/// Back up the panel itself: database (consistent copy), /etc/cloudpanel, vhosts and cron.
pub fn backup_panel(config: &Config, pool: &DbPool, log: &JobLog) -> Result<(), String> {
    let ts = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let dir = config.backup_dir.join("_panel");
    crate::fsutil::create_private_dir(&dir, 0o700).map_err(|e| e.to_string())?;
    let staging = config.backup_dir.join(".staging").join(format!("panel-{ts}"));
    fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    let _guard = DirGuard(staging.clone());
    let conn = pool.get().map_err(|e| e.to_string())?;
    let db_copy = staging.join("cloudpanel.db");
    conn.execute("VACUUM INTO ?1", [db_copy.to_string_lossy().as_ref()])
        .map_err(|e| format!("database snapshot failed: {e}"))?;
    log.line("Database snapshot taken");

    let dest = dir.join(format!("panel-{ts}.tar.gz"));
    let dest_s = dest.to_string_lossy().into_owned();
    let mut args: Vec<String> = vec![
        "-czf".into(),
        dest_s.clone(),
        "-C".into(),
        staging.to_string_lossy().into_owned(),
        "cloudpanel.db".into(),
    ];
    for p in [&config.etc_dir, &config.nginx_sites_available] {
        let p = crate::validate::absolute(p);
        if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
            if p.exists() {
                args.extend([
                    "-C".into(),
                    parent.to_string_lossy().into_owned(),
                    name.to_string_lossy().into_owned(),
                ]);
            }
        }
    }
    let cron = crate::validate::absolute(&config.cron_file);
    if cron.exists() {
        if let (Some(parent), Some(name)) = (cron.parent(), cron.file_name()) {
            args.extend([
                "-C".into(),
                parent.to_string_lossy().into_owned(),
                name.to_string_lossy().into_owned(),
            ]);
        }
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let id = db::create_backup(&conn, None, "_panel", &dest_s).map_err(|e| e.to_string())?;
    match tar(&argv, log) {
        Ok(()) => {
            let _ = crate::fsutil::set_mode(&dest, 0o600);
            let size = fs::metadata(&dest).map(|m| m.len() as i64).unwrap_or(0);
            db::finish_backup(&conn, id, size, None, None).map_err(|e| e.to_string())?;
            log.line(&format!("Panel backup written to {}", dest.display()));
            Ok(())
        }
        Err(e) => {
            let _ = db::finish_backup(&conn, id, 0, Some(&e), None);
            Err(e)
        }
    }
}

/// Called every minute by the scheduler: start due scheduled backups (times are UTC).
pub fn run_scheduled(state: &SharedState) {
    let Ok(conn) = state.pool.get() else { return };
    let now = Utc::now();
    let Ok(policies) = db::list_backup_policies(&conn) else {
        return;
    };
    for mut p in policies {
        if now.hour() as i64 != p.hour {
            continue;
        }
        let recent = |h: i64| p.last_run.is_some_and(|last| now - last < chrono::Duration::hours(h));
        let due = match p.frequency.as_str() {
            "daily" => !recent(20),
            "weekly" => now.weekday() == chrono::Weekday::Sun && !recent(6 * 24),
            _ => false,
        };
        if !due {
            continue;
        }
        p.last_run = Some(now);
        if db::save_backup_policy(&conn, &p).is_err() {
            continue;
        }
        let (config, pool, sid) = (state.config.clone(), state.pool.clone(), p.site_id);
        let _ = crate::jobs::spawn(&state.pool, "backup.scheduled", None, None, move |log| {
            backup_site(&config, &pool, sid, log).map(|_| ())
        });
    }
    // Remove stale database exports (download links) after an hour.
    if let Ok(entries) = fs::read_dir(exports_dir(&state.config)) {
        for e in entries.flatten() {
            if e.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t.elapsed().unwrap_or_default() > std::time::Duration::from_secs(3600))
            {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

/// Is `path` a backup archive inside the backup directory (for downloads)?
pub fn is_backup_file(config: &Config, path: &Path) -> bool {
    let base = crate::validate::absolute(&config.backup_dir);
    let p = crate::validate::absolute(path);
    p.starts_with(&base) && p.is_file()
}
