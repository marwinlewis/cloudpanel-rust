//! Site databases on MariaDB/MySQL, MongoDB and SQLite. Engines are chosen at install
//! time (`CLOUDPANEL_DB_ENGINES`) and must also be detected on the host.
//!
//! Identifiers are validated with `validate::db_identifier` and passwords are restricted
//! to a quote-free alphabet, so SQL statements can be built safely and are sent on stdin.
//! MongoDB arguments are passed as JSON in an environment variable, never interpolated.

use super::cmd::{run_with, which, CmdOpts};
use super::sysusers;
use crate::config::Config;
use crate::db::models::Site;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Engine {
    MariaDb,
    MongoDb,
    Sqlite,
}

pub const ALL: [Engine; 3] = [Engine::MariaDb, Engine::MongoDb, Engine::Sqlite];

#[derive(Serialize)]
pub struct EngineStatus {
    pub engine: &'static str,
    pub label: &'static str,
    pub configured: bool,
    pub installed: bool,
    pub available: bool,
    pub has_users: bool,
}

impl Engine {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mariadb" | "mysql" => Some(Engine::MariaDb),
            "mongodb" => Some(Engine::MongoDb),
            "sqlite" => Some(Engine::Sqlite),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Engine::MariaDb => "mariadb",
            Engine::MongoDb => "mongodb",
            Engine::Sqlite => "sqlite",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Engine::MariaDb => "MySQL / MariaDB",
            Engine::MongoDb => "MongoDB",
            Engine::Sqlite => "SQLite",
        }
    }

    pub fn has_users(self) -> bool {
        self != Engine::Sqlite
    }

    pub fn installed(self) -> bool {
        match self {
            Engine::MariaDb => which("mariadb") || which("mysql"),
            Engine::MongoDb => which("mongosh"),
            Engine::Sqlite => true, // bundled
        }
    }

    pub fn status(self, config: &Config) -> EngineStatus {
        let configured = config.engine_configured(self.as_str());
        let installed = self.installed();
        EngineStatus {
            engine: self.as_str(),
            label: self.label(),
            configured,
            installed,
            available: configured && installed,
            has_users: self.has_users(),
        }
    }

    /// File extension of exports.
    pub fn dump_ext(self) -> &'static str {
        match self {
            Engine::MariaDb => "sql.gz",
            Engine::MongoDb => "archive.gz",
            Engine::Sqlite => "sqlite",
        }
    }
}

/// Database passwords: generated, or user-chosen from a quote-free alphabet.
pub fn check_password(pw: &str) -> Result<(), String> {
    let ok = pw.len() >= 10
        && pw.len() <= 64
        && pw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#%+,-./:=@^_~".contains(c));
    if ok {
        Ok(())
    } else {
        Err("Database passwords must be 10-64 characters: letters, digits and ! # % + , - . / : = @ ^ _ ~".into())
    }
}

pub fn generate_password() -> String {
    crate::auth::random_password(24)
}

// ---------- MariaDB ----------

fn mysql_bin() -> &'static str {
    if which("mariadb") {
        "mariadb"
    } else {
        "mysql"
    }
}

fn mysql(sql: &str) -> Result<String, String> {
    let r = run_with(
        mysql_bin(),
        &["--batch", "--skip-column-names"],
        &CmdOpts::default().stdin(sql.to_string()).timeout(60),
    );
    r.into_result("mysql", "MariaDB/MySQL is not installed")
}

// ---------- MongoDB ----------

/// Shared mongosh prelude: connect and authenticate as the panel admin from env vars.
const MONGO_PRELUDE: &str = "const a = JSON.parse(process.env.CP_ARGS); \
    const conn = new Mongo('mongodb://127.0.0.1:27017'); \
    const admin = conn.getDB('admin'); \
    if (process.env.CP_MONGO_USER) { admin.auth(process.env.CP_MONGO_USER, process.env.CP_MONGO_PASSWORD); } ";

fn mongo_creds(config: &Config) -> (String, String) {
    let path = config.etc_dir.join("mongodb.env");
    let text = fs::read_to_string(path).unwrap_or_default();
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string()
    };
    (get("MONGO_ADMIN_USER"), get("MONGO_ADMIN_PASSWORD"))
}

fn mongosh(config: &Config, script: &str, args: serde_json::Value) -> Result<String, String> {
    let (user, pw) = mongo_creds(config);
    let full = format!("{MONGO_PRELUDE}{script}");
    let r = run_with(
        "mongosh",
        &["--quiet", "--nodb", "--eval", &full],
        &CmdOpts::default()
            .env("CP_ARGS", &args.to_string())
            .env("CP_MONGO_USER", &user)
            .env("CP_MONGO_PASSWORD", &pw)
            .timeout(60),
    );
    r.into_result("mongosh", "MongoDB shell (mongosh) is not installed")
}

/// Temporary mongodump/mongorestore config holding the admin password (0600).
fn mongo_tool_config(config: &Config) -> Result<(tempfile_lite::TempFile, String), String> {
    let (user, pw) = mongo_creds(config);
    let dir = config.etc_dir.join("tmp");
    crate::fsutil::create_private_dir(&dir, 0o700).map_err(|e| e.to_string())?;
    let file = tempfile_lite::TempFile::new(&dir, "mongo-", ".yaml")?;
    crate::fsutil::write_atomic(file.path(), format!("password: \"{pw}\"\n").as_bytes(), 0o600)
        .map_err(|e| e.to_string())?;
    Ok((file, user))
}

/// Minimal self-deleting temp file (avoids a runtime dependency on `tempfile`).
pub mod tempfile_lite {
    use std::path::{Path, PathBuf};

    pub struct TempFile(PathBuf);

    impl TempFile {
        pub fn new(dir: &Path, prefix: &str, suffix: &str) -> Result<Self, String> {
            let name = format!(
                "{prefix}{}{suffix}",
                crate::auth::random_password(12).to_ascii_lowercase()
            );
            Ok(TempFile(dir.join(name)))
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

// ---------- SQLite ----------

pub fn sqlite_path(site: &Site, name: &str) -> Result<PathBuf, String> {
    let home = site
        .home_dir
        .as_deref()
        .ok_or("SQLite databases need a site with a home directory")?;
    Ok(Path::new(home).join("databases").join(format!("{name}.sqlite")))
}

fn sqlite_valid(path: &Path) -> Result<(), String> {
    let mut header = [0u8; 16];
    use std::io::Read;
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut header))
        .map_err(|_| "File is not a SQLite database".to_string())?;
    if &header != b"SQLite format 3\0" {
        return Err("File is not a SQLite database".into());
    }
    let conn = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if check != "ok" {
        return Err(format!("Integrity check failed: {check}"));
    }
    Ok(())
}

// ---------- Operations ----------

pub fn create_db(config: &Config, engine: Engine, site: &Site, name: &str) -> Result<(), String> {
    match engine {
        Engine::MariaDb => {
            mysql(&format!(
                "CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
            ))?;
        }
        Engine::MongoDb => {
            mongosh(
                config,
                "conn.getDB(a.db).createCollection('_cloudpanel'); print('ok');",
                serde_json::json!({ "db": name }),
            )?;
        }
        Engine::Sqlite => {
            let path = sqlite_path(site, name)?;
            if path.exists() {
                return Err(format!("{} already exists", path.display()));
            }
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            let conn = rusqlite::Connection::open(&path).map_err(|e| e.to_string())?;
            conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA user_version = 1;")
                .map_err(|e| e.to_string())?;
            drop(conn);
            let _ = sysusers::chown_one(&path, &site.system_user);
            if let Some(dir) = path.parent() {
                let _ = sysusers::chown_one(dir, &site.system_user);
            }
        }
    }
    Ok(())
}

pub fn drop_db(config: &Config, engine: Engine, site: &Site, name: &str, users: &[String]) -> Result<(), String> {
    for u in users {
        drop_user(config, engine, name, u)?;
    }
    match engine {
        Engine::MariaDb => {
            mysql(&format!("DROP DATABASE IF EXISTS `{name}`;"))?;
        }
        Engine::MongoDb => {
            mongosh(
                config,
                "conn.getDB(a.db).dropDatabase(); print('ok');",
                serde_json::json!({ "db": name }),
            )?;
        }
        Engine::Sqlite => {
            let path = sqlite_path(site, name)?;
            for suffix in ["", "-wal", "-shm"] {
                let p = PathBuf::from(format!("{}{suffix}", path.display()));
                if p.exists() {
                    fs::remove_file(&p).map_err(|e| format!("remove {}: {e}", p.display()))?;
                }
            }
        }
    }
    Ok(())
}

pub fn create_user(config: &Config, engine: Engine, db: &str, user: &str, password: &str) -> Result<(), String> {
    check_password(password)?;
    match engine {
        Engine::MariaDb => {
            mysql(&format!(
                "CREATE USER '{user}'@'localhost' IDENTIFIED BY '{password}';\n\
                 GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'localhost';\nFLUSH PRIVILEGES;"
            ))?;
        }
        Engine::MongoDb => {
            mongosh(
                config,
                "conn.getDB(a.db).createUser({ user: a.user, pwd: a.pwd, roles: [{ role: 'readWrite', db: a.db }, { role: 'dbAdmin', db: a.db }] }); print('ok');",
                serde_json::json!({ "db": db, "user": user, "pwd": password }),
            )?;
        }
        Engine::Sqlite => return Err("SQLite databases have no users".into()),
    }
    Ok(())
}

pub fn drop_user(config: &Config, engine: Engine, db: &str, user: &str) -> Result<(), String> {
    match engine {
        Engine::MariaDb => {
            mysql(&format!("DROP USER IF EXISTS '{user}'@'localhost';"))?;
        }
        Engine::MongoDb => {
            mongosh(
                config,
                "const d = conn.getDB(a.db); if (d.getUser(a.user)) { d.dropUser(a.user); } print('ok');",
                serde_json::json!({ "db": db, "user": user }),
            )?;
        }
        Engine::Sqlite => {}
    }
    Ok(())
}

pub fn set_password(config: &Config, engine: Engine, db: &str, user: &str, password: &str) -> Result<(), String> {
    check_password(password)?;
    match engine {
        Engine::MariaDb => {
            mysql(&format!(
                "ALTER USER '{user}'@'localhost' IDENTIFIED BY '{password}';\nFLUSH PRIVILEGES;"
            ))?;
        }
        Engine::MongoDb => {
            mongosh(
                config,
                "conn.getDB(a.db).updateUser(a.user, { pwd: a.pwd }); print('ok');",
                serde_json::json!({ "db": db, "user": user, "pwd": password }),
            )?;
        }
        Engine::Sqlite => return Err("SQLite databases have no users".into()),
    }
    Ok(())
}

/// Dump a database to `dest` (gzip for MariaDB/MongoDB, a consistent copy for SQLite).
pub fn export(config: &Config, engine: Engine, site: &Site, db: &str, dest: &Path) -> Result<(), String> {
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    match engine {
        Engine::MariaDb => {
            let raw = dest.with_extension(""); // strip .gz
            let dump = if which("mariadb-dump") {
                "mariadb-dump"
            } else {
                "mysqldump"
            };
            let raw_s = raw.to_string_lossy().into_owned();
            run_with(
                dump,
                &[
                    "--single-transaction",
                    "--routines",
                    "--triggers",
                    "--events",
                    &format!("--result-file={raw_s}"),
                    "--",
                    db,
                ],
                &CmdOpts::default().timeout(3600),
            )
            .into_result(dump, "mysqldump is not installed")?;
            run_with("gzip", &["-f", "--", &raw_s], &CmdOpts::default().timeout(3600))
                .into_result("gzip", "gzip is not installed")?;
        }
        Engine::MongoDb => {
            let (cfg, user) = mongo_tool_config(config)?;
            let mut args = vec![
                "--host".to_string(),
                "127.0.0.1".into(),
                format!("--db={db}"),
                format!("--archive={}", dest.display()),
                "--gzip".into(),
            ];
            if !user.is_empty() {
                args.push(format!("--username={user}"));
                args.push("--authenticationDatabase=admin".into());
                args.push(format!("--config={}", cfg.path().display()));
            }
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            run_with("mongodump", &argv, &CmdOpts::default().timeout(3600))
                .into_result("mongodump", "mongodump (MongoDB database tools) is not installed")?;
        }
        Engine::Sqlite => {
            let src = sqlite_path(site, db)?;
            let conn = rusqlite::Connection::open_with_flags(&src, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| format!("open {}: {e}", src.display()))?;
            let _ = fs::remove_file(dest);
            conn.execute("VACUUM INTO ?1", [dest.to_string_lossy().as_ref()])
                .map_err(|e| format!("export failed: {e}"))?;
        }
    }
    Ok(())
}

/// Restore a dump produced by [`export`] (or an uploaded `.sql`/`.sql.gz`/archive/sqlite file).
pub fn import(config: &Config, engine: Engine, site: &Site, db: &str, src: &Path) -> Result<(), String> {
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match engine {
        Engine::MariaDb => {
            let plain = if name.ends_with(".gz") {
                let out = src.with_extension("");
                let r = run_with(
                    "gzip",
                    &["-dkf", "--", &src.to_string_lossy()],
                    &CmdOpts::default().timeout(3600),
                );
                r.into_result("gzip", "gzip is not installed")?;
                Some(out)
            } else {
                None
            };
            let file = plain.clone().unwrap_or_else(|| src.to_path_buf());
            let r = run_with(
                mysql_bin(),
                &["--", db],
                &CmdOpts::default().stdin_file(&file).timeout(3600),
            );
            if let Some(p) = plain {
                let _ = fs::remove_file(p);
            }
            r.into_result("mysql", "MariaDB/MySQL is not installed")?;
        }
        Engine::MongoDb => {
            let (cfg, user) = mongo_tool_config(config)?;
            let mut args = vec![
                "--host".to_string(),
                "127.0.0.1".into(),
                format!("--archive={}", src.display()),
                format!("--nsInclude={db}.*"),
                "--drop".into(),
            ];
            if name.ends_with(".gz") {
                args.push("--gzip".into());
            }
            if !user.is_empty() {
                args.push(format!("--username={user}"));
                args.push("--authenticationDatabase=admin".into());
                args.push(format!("--config={}", cfg.path().display()));
            }
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            run_with("mongorestore", &argv, &CmdOpts::default().timeout(3600))
                .into_result("mongorestore", "mongorestore (MongoDB database tools) is not installed")?;
        }
        Engine::Sqlite => {
            sqlite_valid(src)?;
            let dest = sqlite_path(site, db)?;
            let tmp = dest.with_extension("sqlite.importing");
            fs::copy(src, &tmp).map_err(|e| e.to_string())?;
            for suffix in ["-wal", "-shm"] {
                let _ = fs::remove_file(format!("{}{suffix}", dest.display()));
            }
            fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
            let _ = sysusers::chown_one(&dest, &site.system_user);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords() {
        assert!(check_password(&generate_password()).is_ok());
        assert!(check_password("short").is_err());
        assert!(check_password("has'quote-in-it").is_err());
        assert!(check_password("back\\slash-in-it").is_err());
        assert!(check_password("ok-Password_123").is_ok());
    }

    #[test]
    fn sqlite_create_export_import() {
        let dir = tempfile::tempdir().unwrap();
        let mut site = crate::services::nginx::test_site("static");
        site.home_dir = Some(dir.path().to_string_lossy().into_owned());
        let cfg = Config::from_env();
        create_db(&cfg, Engine::Sqlite, &site, "app").unwrap();
        let p = sqlite_path(&site, "app").unwrap();
        rusqlite::Connection::open(&p)
            .unwrap()
            .execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (42);")
            .unwrap();
        let dump = dir.path().join("dump.sqlite");
        export(&cfg, Engine::Sqlite, &site, "app", &dump).unwrap();
        rusqlite::Connection::open(&p)
            .unwrap()
            .execute_batch("DELETE FROM t;")
            .unwrap();
        import(&cfg, Engine::Sqlite, &site, "app", &dump).unwrap();
        let v: i64 = rusqlite::Connection::open(&p)
            .unwrap()
            .query_row("SELECT x FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 42);
        let junk = dir.path().join("junk.sqlite");
        fs::write(&junk, b"not a database at all").unwrap();
        assert!(import(&cfg, Engine::Sqlite, &site, "app", &junk).is_err());
        drop_db(&cfg, Engine::Sqlite, &site, "app", &[]).unwrap();
        assert!(!p.exists());
    }
}
