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
use crate::fsutil::Confined;
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

/// Credentials for a server whose root account has a password, as on one migrated from
/// CloudPanel CE. Elsewhere root logs in over the local socket and this file doesn't exist.
fn mysql_admin_file() -> PathBuf {
    let etc = std::env::var("CLOUDPANEL_ETC_DIR").unwrap_or_else(|_| "/etc/cloudpanel".into());
    Path::new(&etc).join("mysql-admin.cnf")
}

/// Arguments for the mysql tools: the credentials option, which has to come first, then `rest`.
fn mysql_args<'a>(defaults: &'a Option<String>, rest: &[&'a str]) -> Vec<&'a str> {
    let mut args: Vec<&str> = defaults.iter().map(String::as_str).collect();
    args.extend_from_slice(rest);
    args
}

fn mysql_defaults() -> Option<String> {
    let file = mysql_admin_file();
    file.exists()
        .then(|| format!("--defaults-extra-file={}", file.display()))
}

fn mysql(sql: &str) -> Result<String, String> {
    let defaults = mysql_defaults();
    let r = run_with(
        mysql_bin(),
        &mysql_args(&defaults, &["--batch", "--skip-column-names"]),
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

/// A site's SQLite file, in terms of its home. That folder and everything in it belongs to the site's
/// user, who can replace any of it at any moment, and the panel is working there as root.
fn sqlite_rel(name: &str, suffix: &str) -> PathBuf {
    Path::new("databases").join(format!("{name}.sqlite{suffix}"))
}

fn site_home(site: &Site) -> Result<Confined, String> {
    let home = site
        .home_dir
        .as_deref()
        .ok_or("SQLite databases need a site with a home directory")?;
    Confined::open(Path::new(home)).map_err(|e| format!("Site home is not accessible: {e}"))
}

fn site_owner(site: &Site) -> Result<Option<(u32, u32)>, String> {
    match sysusers::ids(&site.system_user) {
        Ok(ids) => Ok(ids),
        Err(e) if crate::fsutil::running_as_root() => Err(e),
        // Tests and development, where the file stays with whoever is running this.
        Err(_) => Ok(None),
    }
}

const NOT_A_FILE: &str = "The database must be a regular file, not a link or folder";

/// Is this really the site's database? As well as what's at the path, the owner matters: a hard
/// link to a root-owned file would pass as a regular file here.
fn sqlite_source(site: &Site, name: &str) -> Result<PathBuf, String> {
    let home = site_home(site)?;
    let at = home.pin(&sqlite_rel(name, ""), false).map_err(|e| e.to_string())?;
    let meta = at
        .lstat()
        .map_err(|e| e.to_string())?
        .ok_or("The database file is missing")?;
    if !meta.file_type().is_file() {
        return Err(NOT_A_FILE.into());
    }
    if crate::fsutil::running_as_root() {
        let uid = site_owner(site)?.map(|o| o.0);
        if crate::fsutil::owner_uid(&meta) != uid {
            return Err("The database file doesn't belong to the site's user".into());
        }
    }
    // SQLite opens its journals by name next to the database, and a link there would be followed.
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = home.pin(&sqlite_rel(name, suffix), false).map_err(|e| e.to_string())?;
        if side
            .lstat()
            .map_err(|e| e.to_string())?
            .is_some_and(|m| !m.file_type().is_file())
        {
            return Err(NOT_A_FILE.into());
        }
    }
    Ok(home.canonical().join(sqlite_rel(name, "")))
}

/// Put a database file in place, from a file only the panel can touch. Everything is done through
/// a new file with a name nobody could plant anything at, then a rename, which replaces a link
/// rather than following it.
fn install_sqlite(site: &Site, name: &str, src: &Path) -> Result<(), String> {
    use std::io::Write;
    let home = site_home(site)?;
    let owner = site_owner(site)?;
    home.mkdir_all(Path::new("databases"), owner)
        .map_err(|e| e.to_string())?;
    let at = home.pin(&sqlite_rel(name, ""), false).map_err(|e| e.to_string())?;
    if at.lstat().map_err(|e| e.to_string())?.is_some_and(|m| m.is_dir()) {
        return Err(NOT_A_FILE.into());
    }
    let temp = at.sibling(&format!(".{name}.{}.importing", crate::auth::random_password(12)));
    let result = (|| -> std::io::Result<()> {
        let mut input = fs::File::open(src)?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        crate::fsutil::fchmod(&output, 0o640)?;
        std::io::copy(&mut input, &mut output)?;
        output.flush()?;
        crate::fsutil::fchown(&output, owner)?;
        output.sync_all()?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(at.sibling(&format!("{name}.sqlite{suffix}")));
        }
        fs::rename(&temp, at.path())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|e| e.to_string())
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
            let home = site_home(site)?;
            // A dangling link counts as being there, which is why this doesn't ask `exists`.
            if let Ok(at) = home.pin(&sqlite_rel(name, ""), false) {
                if at.lstat().map_err(|e| e.to_string())?.is_some() {
                    return Err(format!("{} already exists", sqlite_path(site, name)?.display()));
                }
            }
            // Made somewhere private and then moved in, because SQLite itself would open the
            // database and its journals by name in a folder the site's user can write to.
            let dir = std::env::temp_dir().join(format!(
                "cloudpanel-new-{}",
                crate::auth::random_password(12).to_ascii_lowercase()
            ));
            crate::fsutil::create_private_dir(&dir, 0o700).map_err(|e| e.to_string())?;
            let built = dir.join("new.sqlite");
            let result = rusqlite::Connection::open(&built)
                .and_then(|conn| conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA user_version = 1;"))
                .map_err(|e| e.to_string())
                .and_then(|()| install_sqlite(site, name, &built));
            let _ = fs::remove_dir_all(&dir);
            result?;
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
            mysql(&format!(
                "DROP USER IF EXISTS '{}'@'localhost';",
                import_account_name(name)
            ))?;
        }
        Engine::MongoDb => {
            mongosh(
                config,
                "conn.getDB(a.db).dropDatabase(); print('ok');",
                serde_json::json!({ "db": name }),
            )?;
        }
        Engine::Sqlite => {
            let home = match site_home(site) {
                Ok(home) => home,
                // Nothing to remove with the home already gone.
                Err(_) if !sqlite_path(site, name).is_ok_and(|p| p.exists()) => return Ok(()),
                Err(e) => return Err(e),
            };
            for suffix in ["", "-wal", "-shm"] {
                match home.pin(&sqlite_rel(name, suffix), false) {
                    Ok(at) => {
                        if at.lstat().map_err(|e| e.to_string())?.is_some() {
                            fs::remove_file(at.path()).map_err(|e| format!("remove {name}: {e}"))?;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("remove {name}: {e}")),
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

/// The hosts an account exists for. The panel creates `'user'@'localhost'`, but accounts imported
/// from CloudPanel CE are `'user'@'%'`. Hosts come back from MySQL, and only what a host name can
/// be made of goes into a statement.
fn parse_hosts(output: &str) -> Vec<String> {
    let hosts: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric() || ".:%_-/".contains(c)))
        .map(str::to_string)
        .collect();
    if hosts.is_empty() {
        vec!["localhost".to_string()]
    } else {
        hosts
    }
}

fn mysql_user_hosts(user: &str) -> Result<Vec<String>, String> {
    Ok(parse_hosts(&mysql(&format!(
        "SELECT Host FROM mysql.user WHERE User = '{user}';"
    ))?))
}

pub fn drop_user(config: &Config, engine: Engine, db: &str, user: &str) -> Result<(), String> {
    match engine {
        Engine::MariaDb => {
            for host in mysql_user_hosts(user)? {
                mysql(&format!("DROP USER IF EXISTS '{user}'@'{host}';"))?;
            }
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
            for host in mysql_user_hosts(user)? {
                mysql(&format!(
                    "ALTER USER '{user}'@'{host}' IDENTIFIED BY '{password}';\nFLUSH PRIVILEGES;"
                ))?;
            }
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
            let result_file = format!("--result-file={raw_s}");
            let defaults = mysql_defaults();
            run_with(
                dump,
                &mysql_args(
                    &defaults,
                    &[
                        "--single-transaction",
                        "--routines",
                        "--triggers",
                        "--events",
                        &result_file,
                        "--",
                        db,
                    ],
                ),
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
            let src = sqlite_source(site, db)?;
            // NOFOLLOW refuses a link anywhere along the path. That covers the moment between the
            // check above and here, and the file's own contents aren't to be trusted either.
            let conn = rusqlite::Connection::open_with_flags(
                &src,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(|e| format!("open {}: {e}", src.display()))?;
            conn.execute_batch("PRAGMA trusted_schema = OFF;")
                .map_err(|e| format!("export failed: {e}"))?;
            let _ = fs::remove_file(dest);
            conn.execute("VACUUM INTO ?1", [dest.to_string_lossy().as_ref()])
                .map_err(|e| format!("export failed: {e}"))?;
        }
    }
    Ok(())
}

/// Statements for a temporary account that can reach one database and nothing else on the server.
pub fn import_account_sql(db: &str, user: &str, password: &str) -> String {
    format!(
        "CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{password}';\n\
         ALTER USER '{user}'@'localhost' IDENTIFIED BY '{password}' ACCOUNT UNLOCK;\n\
         GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'localhost';\nFLUSH PRIVILEGES;"
    )
}

/// The account a database's imports run as. It stays afterwards, locked, because the views,
/// triggers and routines an import creates name it as their definer, and they stop working if it
/// goes. One per database, from a hash of its name, so two databases never share one.
fn import_account_name(db: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(db.as_bytes());
    let hex: String = hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("cp_owner_{hex}")
}

/// `DEFINER=` from a line of a dump: an account name in any of the forms MySQL writes, or
/// `CURRENT_USER`. An import account isn't allowed to use one, so without this a dump with a view
/// or trigger in it, which is what the panel's own export produces, couldn't be imported.
fn strip_definer_bytes(line: &[u8]) -> Vec<u8> {
    const KEY: &[u8] = b"DEFINER=";
    // A row of data may contain anything, and it isn't this.
    if line.starts_with(b"INSERT ") || !line.windows(KEY.len()).any(|w| w == KEY) {
        return line.to_vec();
    }
    // One name or host: quoted in backticks or single quotes, or plain.
    let name = |rest: &[u8]| -> Option<usize> {
        match rest.first()? {
            q @ (b'`' | b'\'') => Some(rest[1..].iter().position(|c| c == q)? + 2),
            _ => {
                let n = rest
                    .iter()
                    .position(|c| !(c.is_ascii_alphanumeric() || b"_.-%".contains(c)))
                    .unwrap_or(rest.len());
                (n > 0).then_some(n)
            }
        }
    };
    let clause = |rest: &[u8]| -> Option<usize> {
        if rest.starts_with(b"CURRENT_USER") {
            let n = b"CURRENT_USER".len();
            return Some(if rest[n..].starts_with(b"()") { n + 2 } else { n });
        }
        let user = name(rest)?;
        if rest.get(user) != Some(&b'@') {
            return None;
        }
        Some(user + 1 + name(&rest[user + 1..])?)
    };
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        if line[i..].starts_with(KEY) {
            if let Some(n) = clause(&line[i + KEY.len()..]) {
                i += KEY.len() + n;
                if line.get(i) == Some(&b' ') {
                    i += 1;
                }
                continue;
            }
        }
        out.push(line[i]);
        i += 1;
    }
    out
}

#[cfg(all(test, unix))]
pub fn strip_definers(line: &str) -> String {
    String::from_utf8_lossy(&strip_definer_bytes(line.as_bytes())).into_owned()
}

/// The MariaDB account for an import, with its login in a file only the site's user can read. It
/// can only be logged in to for the import: whatever happens, it's locked and given a password
/// nobody knows again afterwards.
struct ImportAccount {
    user: String,
    file: PathBuf,
}

impl ImportAccount {
    fn create(db: &str, owner: Option<(u32, u32)>) -> Result<Self, String> {
        use std::io::Write;
        // Quoted into the grant below. The panel's own names can't need this, but CE's aren't checked.
        if !db.chars().all(|c| c.is_ascii_alphanumeric() || "_-$".contains(c)) {
            return Err(format!("A database named {db} can't be imported into"));
        }
        let suffix = crate::auth::random_password(16).to_ascii_lowercase();
        let user = import_account_name(db);
        let password = generate_password();
        let dir = Path::new("/run/cloudpanel-import");
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        // Others may pass through to a file they own, but can't list it or replace anything.
        crate::fsutil::set_mode(dir, 0o711).map_err(|e| e.to_string())?;
        let file = dir.join(format!("{suffix}.cnf"));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o400);
        }
        let mut f = opts
            .open(&file)
            .map_err(|e| format!("create {}: {e}", file.display()))?;
        let account = ImportAccount { user, file };
        write!(f, "[client]\nuser={}\npassword=\"{password}\"\n", account.user).map_err(|e| e.to_string())?;
        crate::fsutil::fchown(&f, owner).map_err(|e| e.to_string())?;
        mysql(&import_account_sql(db, &account.user, &password))?;
        Ok(account)
    }
}

impl Drop for ImportAccount {
    fn drop(&mut self) {
        let _ = mysql(&format!(
            "ALTER USER '{}'@'localhost' IDENTIFIED BY '{}' ACCOUNT LOCK;",
            self.user,
            generate_password()
        ));
        let _ = fs::remove_file(&self.file);
    }
}

/// Does this client know `--sandbox`, which turns off its shell escape and the like?
fn mysql_has_sandbox() -> bool {
    run_with(mysql_bin(), &["--help", "--verbose"], &CmdOpts::default().timeout(30))
        .stdout
        .contains("--sandbox")
}

/// Run a dump that came from a site manager. It's a program: as well as the statements for its own
/// database it could hold ones for every other, for the server's accounts and for its files, and
/// `\!` asks the client itself to run a shell command. So the server sees an account with rights on
/// this one database and nothing else, and the client runs as the site's user.
fn import_mariadb(site: &Site, db: &str, file: &Path) -> Result<(), String> {
    use std::io::{BufRead, Write};
    // The file came from root-only staging and stays there. Only this copy of it changes.
    let clean = file.with_extension("clean");
    let copy = (|| -> std::io::Result<()> {
        let mut input = std::io::BufReader::new(fs::File::open(file)?);
        let mut output = std::io::BufWriter::new(fs::OpenOptions::new().write(true).create_new(true).open(&clean)?);
        let mut line = Vec::new();
        while input.read_until(b'\n', &mut line)? > 0 {
            output.write_all(&strip_definer_bytes(&line))?;
            line.clear();
        }
        output.flush()
    })();
    let result = copy.map_err(|e| e.to_string()).and_then(|()| {
        let account = ImportAccount::create(db, site_owner(site)?)?;
        let login = format!("--defaults-extra-file={}", account.file.display());
        let mut args = vec![login.as_str()];
        if mysql_has_sandbox() {
            args.push("--sandbox");
        }
        args.extend(["--", db]);
        run_with(
            mysql_bin(),
            &args,
            &CmdOpts::default()
                .user(&site.system_user)
                .stdin_file(&clean)
                .timeout(3600),
        )
        .into_result("mysql", "MariaDB/MySQL is not installed")
        .map(|_| ())
    });
    let _ = fs::remove_file(&clean);
    result
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
            let r = import_mariadb(site, db, &file);
            if let Some(p) = plain {
                let _ = fs::remove_file(p);
            }
            r?;
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
            install_sqlite(site, db, src)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_hosts_come_from_mysql_and_are_safe_to_quote() {
        assert_eq!(parse_hosts("%\n"), ["%"]);
        assert_eq!(parse_hosts("localhost\n127.0.0.1\n"), ["localhost", "127.0.0.1"]);
        // No account found: the statement still runs, for the host the panel uses itself.
        assert_eq!(parse_hosts(""), ["localhost"]);
        assert_eq!(parse_hosts("x'; DROP DATABASE y; --\n"), ["localhost"]);
    }

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
