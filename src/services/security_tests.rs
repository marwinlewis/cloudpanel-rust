//! What a site's user can do to the panel, which runs as root, through the files they own.
//!
//! The panel works inside directories its site users can write to, and they can replace anything
//! in there at any moment: with a link to `/etc/shadow`, or a link swapped in between the panel's
//! check of a path and its use of it. These tests play that user. Without root they can't aim at
//! real system files, so the "outside" here is a directory next to the site's home, and everything
//! the tests check is about whether the panel left the home.

use super::databases::{self, Engine};
use super::dotenv;
use super::files::SiteFs;
use crate::config::Config;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn current_user() -> String {
    let out = std::process::Command::new("id").arg("-un").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Box_ {
    _dir: tempfile::TempDir,
    home: PathBuf,
    outside: PathBuf,
    fs: SiteFs,
}

/// A home with a `secret` file just outside of it.
fn jail() -> Box_ {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let outside = dir.path().join("outside");
    fs::create_dir_all(home.join("htdocs")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret"), "the secret").unwrap();
    let fs_ = SiteFs::new(&home.to_string_lossy(), &current_user()).unwrap();
    Box_ {
        _dir: dir,
        home,
        outside,
        fs: fs_,
    }
}

fn mode_of(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn site_at(home: &Path, domain: &str) -> crate::db::models::Site {
    let mut site = super::nginx::test_site("static");
    site.domain = domain.to_string();
    site.home_dir = Some(home.to_string_lossy().into_owned());
    site.system_user = current_user();
    site
}

/// Run `f` on a thread, for operations that might hang on a hostile file.
fn with_deadline<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(5)).ok()
}

fn mkfifo(p: &Path) {
    assert!(std::process::Command::new("mkfifo").arg(p).status().unwrap().success());
}

// ---------- Links at the end of a path ----------

#[test]
fn a_link_out_of_the_home_is_refused_by_every_operation() {
    let j = jail();
    symlink(j.outside.join("secret"), j.home.join("link")).unwrap();
    assert!(j.fs.read_text("link").is_err());
    assert!(j.fs.download_path("link").is_err());
    let before = mode_of(&j.outside.join("secret"));
    let _ = j.fs.chmod("link", 0o666);
    assert_eq!(mode_of(&j.outside.join("secret")), before);
    let _ = j.fs.write_text("link", "pwned");
    assert_eq!(fs::read_to_string(j.outside.join("secret")).unwrap(), "the secret");
}

#[test]
fn a_dangling_link_out_of_the_home_cannot_create_a_file() {
    let j = jail();
    symlink(j.outside.join("new"), j.home.join("link")).unwrap();
    assert!(j.fs.upload_target("", "link", true).is_err());
    let _ = j.fs.write_text("link", "pwned");
    let _ = j.fs.create_file("link");
    let _ = j.fs.mkdir("link");
    let _ = j.fs.mkdir("link/deeper");
    assert!(!j.outside.join("new").exists());
}

#[test]
fn deleting_a_link_removes_the_link_not_what_it_points_at() {
    let j = jail();
    symlink(&j.outside, j.home.join("link")).unwrap();
    j.fs.delete("link").unwrap();
    assert!(j.outside.join("secret").exists());
    assert!(j.home.join("link").symlink_metadata().is_err());
}

// ---------- Links in the middle of a path ----------

#[test]
fn a_linked_folder_out_of_the_home_cannot_be_walked_through() {
    let j = jail();
    symlink(&j.outside, j.home.join("dir")).unwrap();
    assert!(j.fs.list("dir").is_err());
    assert!(j.fs.read_text("dir/secret").is_err());
    assert!(j.fs.download_path("dir/secret").is_err());
    assert!(j.fs.write_text("dir/new", "pwned").is_err());
    assert!(j.fs.create_file("dir/new").is_err());
    assert!(j.fs.mkdir("dir/new").is_err());
    assert!(j.fs.delete("dir/secret").is_err());
    assert!(j.fs.chmod("dir/secret", 0o666).is_err());
    assert!(j.fs.upload_target("dir", "new", false).is_err());
    fs::write(j.home.join("mine"), "x").unwrap();
    assert!(j.fs.rename("mine", "dir/stolen").is_err());
    assert!(j.fs.rename("dir/secret", "stolen").is_err());
    assert!(j.outside.join("secret").exists());
    assert!(!j.outside.join("new").exists());
    assert!(!j.outside.join("stolen").exists());
    assert!(!j.home.join("stolen").exists());
}

/// A link out of the home, reached through a chain of ones that look harmless.
#[test]
fn a_chain_of_links_cannot_lead_out() {
    let j = jail();
    fs::create_dir_all(j.home.join("a/b")).unwrap();
    symlink("../../..", j.home.join("a/b/up")).unwrap();
    symlink("a/b/up/outside", j.home.join("via")).unwrap();
    assert!(j.fs.read_text("via/secret").is_err());
    assert!(j.fs.list("via").is_err());
    symlink("loop2", j.home.join("loop1")).unwrap();
    symlink("loop1", j.home.join("loop2")).unwrap();
    assert!(j.fs.read_text("loop1").is_err());
}

/// People do keep links inside their sites, such as `current -> releases/42`, so those keep working.
#[test]
fn links_that_stay_inside_the_home_keep_working() {
    let j = jail();
    fs::create_dir_all(j.home.join("releases/42")).unwrap();
    fs::write(j.home.join("releases/42/index.html"), "hello").unwrap();
    symlink("releases/42", j.home.join("current")).unwrap();
    symlink(j.home.join("releases/42/index.html"), j.home.join("absolute")).unwrap();
    assert_eq!(j.fs.read_text("current/index.html").unwrap(), "hello");
    assert_eq!(j.fs.read_text("absolute").unwrap(), "hello");
    assert_eq!(j.fs.list("current").unwrap()[0].name, "index.html");
    assert!(j.fs.download_path("current/index.html").is_ok());
    j.fs.write_text("current/new.txt", "x").unwrap();
    assert!(j.home.join("releases/42/new.txt").exists());
    let names = j.fs.list("").unwrap();
    let link = names.iter().find(|e| e.name == "current").unwrap();
    assert_eq!(link.kind, "symlink");
    assert_eq!(link.target.as_deref(), Some("releases/42"));
}

#[test]
fn a_write_through_an_inside_link_replaces_the_file_it_points_at_or_is_refused() {
    let j = jail();
    fs::write(j.home.join("real.txt"), "old").unwrap();
    symlink("real.txt", j.home.join("alias.txt")).unwrap();
    if j.fs.write_text("alias.txt", "new").is_ok() {
        assert!(!j.outside.join("real.txt").exists());
    }
}

// ---------- Files that aren't files ----------

#[test]
fn a_fifo_does_not_hang_the_panel() {
    let j = jail();
    mkfifo(&j.home.join("pipe"));
    let (home, user) = (j.home.clone(), current_user());
    let result = with_deadline(move || {
        let s = SiteFs::new(&home.to_string_lossy(), &user).unwrap();
        (s.read_text("pipe").is_err(), s.download_path("pipe").is_err())
    });
    assert_eq!(result, Some((true, true)), "reading a FIFO hung or succeeded");
}

#[test]
fn folders_are_not_read_as_files() {
    let j = jail();
    assert!(j.fs.read_text("htdocs").is_err());
    assert!(j.fs.download_path("htdocs").is_err());
    assert!(j.fs.write_text("htdocs", "x").is_err());
}

#[test]
fn names_that_are_not_utf8_do_not_break_a_listing() {
    use std::os::unix::ffi::OsStrExt;
    let j = jail();
    let name = std::ffi::OsStr::from_bytes(b"bad-\xff\xfe-name");
    if fs::write(j.home.join(name), "x").is_ok() {
        assert!(j.fs.list("").unwrap().iter().any(|e| e.name.contains("bad-")));
    }
}

// ---------- Uploads (SEC-05) ----------

/// The temp file is in the site's home for as long as the upload takes. The site's user can replace
/// it with a link, and the panel then made the link's target world-readable.
#[test]
fn sec05_finishing_an_upload_cannot_chmod_through_a_link() {
    let j = jail();
    let secret = j.outside.join("secret");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    let temp = j.home.join(".upload-x");
    fs::write(&temp, "uploaded").unwrap();
    let written = crate::fsutil::identity(&fs::metadata(&temp).unwrap());
    fs::remove_file(&temp).unwrap();
    symlink(&secret, &temp).unwrap();
    let target = j.fs.upload_target("", "uploaded.txt", false).unwrap();
    assert!(j.fs.install_upload(&temp, written, &target).is_err());
    assert_eq!(
        mode_of(&secret),
        0o600,
        "the panel made a file outside the home readable"
    );
    assert!(
        j.home.join("uploaded.txt").symlink_metadata().is_err(),
        "the link was installed"
    );
}

/// Not a link this time, but a file of the user's own, perhaps a hard link to something else.
#[test]
fn sec05_finishing_an_upload_refuses_a_file_that_is_not_the_one_written() {
    let j = jail();
    let temp = j.home.join(".upload-x");
    fs::write(&temp, "uploaded").unwrap();
    let written = crate::fsutil::identity(&fs::metadata(&temp).unwrap());
    // As the panel does, so the number can't be given to another file.
    let _held = fs::File::open(&temp).unwrap();
    fs::remove_file(&temp).unwrap();
    let stand_in = j.outside.join("stand-in");
    fs::write(&stand_in, "something else").unwrap();
    fs::set_permissions(&stand_in, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&stand_in, &temp).unwrap();
    let target = j.fs.upload_target("", "uploaded.txt", false).unwrap();
    assert!(j.fs.install_upload(&temp, written, &target).is_err());
    assert_eq!(mode_of(&stand_in), 0o600);
}

#[test]
fn an_upload_that_was_left_alone_is_installed_for_the_site_user() {
    let j = jail();
    let temp = j.home.join(".upload-x");
    fs::write(&temp, "uploaded").unwrap();
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).unwrap();
    let written = crate::fsutil::identity(&fs::metadata(&temp).unwrap());
    let target = j.fs.upload_target("htdocs", "ok.txt", false).unwrap();
    j.fs.install_upload(&temp, written, &target).unwrap();
    assert_eq!(fs::read_to_string(j.home.join("htdocs/ok.txt")).unwrap(), "uploaded");
    assert_eq!(mode_of(&j.home.join("htdocs/ok.txt")), 0o644);
    assert!(temp.symlink_metadata().is_err());
}

// ---------- Paths swapped while they're being used (SEC-06) ----------

/// Keeps swapping `<home>/flip` between a real folder and a link out of the home, as a site's user
/// would, for as long as this is alive.
struct Flipper {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Flipper {
    fn start(j: &Box_) -> Self {
        fs::create_dir_all(j.home.join("flip")).unwrap();
        let (flip, parked, outside) = (j.home.join("flip"), j.home.join("parked"), j.outside.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                if fs::rename(&flip, &parked).is_ok() {
                    let _ = symlink(&outside, &flip);
                    std::thread::yield_now();
                    let _ = fs::remove_file(&flip);
                    let _ = fs::rename(&parked, &flip);
                }
                std::thread::yield_now();
            }
        });
        Flipper {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Flipper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

const RACE: Duration = Duration::from_secs(3);

#[test]
fn sec06_a_swapped_folder_cannot_redirect_a_read() {
    let j = jail();
    fs::create_dir_all(j.home.join("flip")).unwrap();
    fs::write(j.home.join("flip/secret"), "public").unwrap();
    let _flipper = Flipper::start(&j);
    let start = Instant::now();
    while start.elapsed() < RACE {
        if let Ok(text) = j.fs.read_text("flip/secret") {
            assert_eq!(text, "public", "read a file outside the home");
        }
    }
}

#[test]
fn sec06_a_swapped_folder_cannot_redirect_a_write() {
    let j = jail();
    let _flipper = Flipper::start(&j);
    let start = Instant::now();
    while start.elapsed() < RACE {
        let _ = j.fs.write_text("flip/pwned", "x");
        assert!(!j.outside.join("pwned").exists(), "wrote a file outside the home");
    }
}

#[test]
fn sec06_a_swapped_folder_cannot_redirect_a_chmod() {
    let j = jail();
    let secret = j.outside.join("secret");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    fs::create_dir_all(j.home.join("flip")).unwrap();
    fs::write(j.home.join("flip/secret"), "public").unwrap();
    let _flipper = Flipper::start(&j);
    let start = Instant::now();
    while start.elapsed() < RACE {
        let _ = j.fs.chmod("flip/secret", 0o666);
        assert_eq!(mode_of(&secret), 0o600, "changed a file outside the home");
    }
}

#[test]
fn sec06_a_swapped_folder_cannot_redirect_a_delete() {
    let j = jail();
    let _flipper = Flipper::start(&j);
    let start = Instant::now();
    while start.elapsed() < RACE {
        let _ = j.fs.delete("flip/secret");
        assert!(j.outside.join("secret").exists(), "deleted a file outside the home");
    }
}

#[test]
fn sec06_a_swapped_folder_cannot_redirect_a_new_folder_or_file() {
    let j = jail();
    let _flipper = Flipper::start(&j);
    let start = Instant::now();
    while start.elapsed() < RACE {
        let _ = j.fs.mkdir("flip/newdir");
        let _ = j.fs.create_file("flip/newfile");
        let _ = j.fs.delete("flip/newdir");
        let _ = j.fs.delete("flip/newfile");
        assert!(!j.outside.join("newdir").exists(), "made a folder outside the home");
        assert!(!j.outside.join("newfile").exists(), "made a file outside the home");
    }
}

// ---------- .env (SEC-07) ----------

fn env_box() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let other = dir.path().join("other-site");
    fs::create_dir_all(home.join("htdocs")).unwrap();
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join(".env"), "SECRET=another-sites-secret\n").unwrap();
    (dir, home, other)
}

/// The final part of the path was checked, and every part before it wasn't, so a linked working
/// folder gave up another site's `.env`.
#[test]
fn sec07_env_cannot_be_read_through_a_linked_folder() {
    let (_d, home, other) = env_box();
    symlink(&other, home.join("htdocs/a.example.com")).unwrap();
    let site = site_at(&home, "a.example.com");
    if let Ok(Some(text)) = dotenv::read_site(&site) {
        panic!("read a .env outside the home: {text}");
    }
}

#[test]
fn sec07_env_cannot_be_written_through_a_linked_folder() {
    let (_d, home, other) = env_box();
    symlink(&other, home.join("htdocs/a.example.com")).unwrap();
    let site = site_at(&home, "a.example.com");
    let _ = dotenv::write_site(&site, "SECRET=replaced\n");
    assert!(fs::read_to_string(other.join(".env"))
        .unwrap()
        .contains("another-sites-secret"));
}

#[test]
fn env_cannot_be_a_link() {
    let (_d, home, other) = env_box();
    fs::create_dir_all(home.join("htdocs/a.example.com")).unwrap();
    symlink(other.join(".env"), home.join("htdocs/a.example.com/.env")).unwrap();
    let site = site_at(&home, "a.example.com");
    assert!(dotenv::read_site(&site).is_err());
    assert!(dotenv::write_site(&site, "X=1\n").is_err());
    assert!(fs::read_to_string(other.join(".env"))
        .unwrap()
        .contains("another-sites-secret"));
}

#[test]
fn env_being_a_fifo_does_not_hang_the_panel() {
    let (_d, home, _other) = env_box();
    fs::create_dir_all(home.join("htdocs/a.example.com")).unwrap();
    mkfifo(&home.join("htdocs/a.example.com/.env"));
    let site = site_at(&home, "a.example.com");
    let result = with_deadline(move || dotenv::read_site(&site).is_err());
    assert_eq!(result, Some(true), "reading a FIFO hung or succeeded");
}

// ---------- SQLite files (SEC-01, SEC-04) ----------

/// A site with a `databases` folder, plus a SQLite file outside it standing in for the panel's own
/// database: what a site manager would be after.
struct Db {
    _dir: tempfile::TempDir,
    home: PathBuf,
    panel_db: PathBuf,
    site: crate::db::models::Site,
    config: Config,
}

fn db_box() -> Db {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(home.join("databases")).unwrap();
    let panel_db = dir.path().join("panel.db");
    rusqlite::Connection::open(&panel_db)
        .unwrap()
        .execute_batch("CREATE TABLE users(password_hash); INSERT INTO users VALUES ('the-admins-hash');")
        .unwrap();
    let site = site_at(&home, "db.example.com");
    Db {
        home,
        panel_db,
        site,
        config: Config::from_env(),
        _dir: dir,
    }
}

fn holds_the_hash(path: &Path) -> bool {
    fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).contains("the-admins-hash"))
        .unwrap_or(false)
}

#[test]
fn sec01_an_export_cannot_follow_a_link_to_the_panels_database() {
    let b = db_box();
    symlink(&b.panel_db, b.home.join("databases/app.sqlite")).unwrap();
    let dest = b.home.join("export.sqlite");
    let r = databases::export(&b.config, Engine::Sqlite, &b.site, "app", &dest);
    assert!(
        r.is_err() && !holds_the_hash(&dest),
        "exported the file behind a link: {r:?}"
    );
}

#[test]
fn sec01_an_export_cannot_follow_a_linked_folder() {
    let b = db_box();
    let elsewhere = b.panel_db.parent().unwrap().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::copy(&b.panel_db, elsewhere.join("app.sqlite")).unwrap();
    fs::remove_dir_all(b.home.join("databases")).unwrap();
    symlink(&elsewhere, b.home.join("databases")).unwrap();
    let dest = b.home.join("export.sqlite");
    let r = databases::export(&b.config, Engine::Sqlite, &b.site, "app", &dest);
    assert!(
        r.is_err() && !holds_the_hash(&dest),
        "exported through a linked folder: {r:?}"
    );
}

fn good_upload(b: &Db) -> PathBuf {
    let src = b.home.parent().unwrap().join("upload.sqlite");
    rusqlite::Connection::open(&src)
        .unwrap()
        .execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES ('uploaded');")
        .unwrap();
    src
}

/// The panel used a predictable temp name in a folder the site's user controls.
#[test]
fn sec04_an_import_cannot_write_through_a_planted_temp_file() {
    let b = db_box();
    databases::create_db(&b.config, Engine::Sqlite, &b.site, "app").unwrap();
    let victim = b.panel_db.parent().unwrap().join("victim");
    fs::write(&victim, "original").unwrap();
    symlink(&victim, b.home.join("databases/app.sqlite.importing")).unwrap();
    let src = good_upload(&b);
    let _ = databases::import(&b.config, Engine::Sqlite, &b.site, "app", &src);
    assert_eq!(fs::read_to_string(&victim).unwrap(), "original", "wrote through a link");
}

#[test]
fn sec04_an_import_cannot_write_through_a_linked_database_or_folder() {
    let b = db_box();
    let victim_dir = b.panel_db.parent().unwrap().join("victims");
    fs::create_dir_all(&victim_dir).unwrap();
    fs::write(victim_dir.join("app.sqlite"), "original").unwrap();
    fs::remove_dir_all(b.home.join("databases")).unwrap();
    symlink(&victim_dir, b.home.join("databases")).unwrap();
    let src = good_upload(&b);
    let r = databases::import(&b.config, Engine::Sqlite, &b.site, "app", &src);
    assert!(r.is_err(), "imported through a linked folder");
    assert_eq!(fs::read_to_string(victim_dir.join("app.sqlite")).unwrap(), "original");
}

#[test]
fn sec04_creating_a_database_cannot_follow_a_dangling_link() {
    let b = db_box();
    let victim = b.panel_db.parent().unwrap().join("created-by-root");
    symlink(&victim, b.home.join("databases/app.sqlite")).unwrap();
    let r = databases::create_db(&b.config, Engine::Sqlite, &b.site, "app");
    assert!(r.is_err(), "created a database through a link");
    assert!(!victim.exists(), "created a file outside the home");
}

/// SQLite would otherwise create its write-ahead log through this as root.
#[test]
fn sec04_creating_a_database_cannot_follow_a_planted_journal_link() {
    let b = db_box();
    let victim = b.panel_db.parent().unwrap().join("journal-victim");
    fs::write(&victim, "original").unwrap();
    symlink(&victim, b.home.join("databases/app.sqlite-wal")).unwrap();
    let _ = databases::create_db(&b.config, Engine::Sqlite, &b.site, "app");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "original");
}

#[test]
fn sec04_dropping_a_database_removes_links_not_their_targets() {
    let b = db_box();
    let victim_dir = b.panel_db.parent().unwrap().join("victims");
    fs::create_dir_all(&victim_dir).unwrap();
    fs::write(victim_dir.join("app.sqlite"), "original").unwrap();
    fs::remove_dir_all(b.home.join("databases")).unwrap();
    symlink(&victim_dir, b.home.join("databases")).unwrap();
    let _ = databases::drop_db(&b.config, Engine::Sqlite, &b.site, "app", &[]);
    assert!(
        victim_dir.join("app.sqlite").exists(),
        "deleted a file outside the home"
    );
}

/// A hostile database file shouldn't get to run anything while the panel is copying it.
#[test]
fn an_export_of_a_hostile_database_runs_nothing_of_its_own() {
    let b = db_box();
    let path = b.home.join("databases/app.sqlite");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE t(x);
             CREATE TABLE log(x);
             CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES ('ran'); END;",
        )
        .unwrap();
    let dest = b.home.join("export.sqlite");
    databases::export(&b.config, Engine::Sqlite, &b.site, "app", &dest).unwrap();
    let n: i64 = rusqlite::Connection::open(&dest)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM log", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

// ---------- MariaDB dumps (SEC-02) ----------

/// Dumps carry `DEFINER=` clauses that only a privileged account may use, and imports don't run as
/// one any more. Everything else about the dump stays as it was.
#[test]
fn sec02_definers_are_taken_out_of_a_dump() {
    let strip = databases::strip_definers;
    assert_eq!(
        strip("/*!50013 DEFINER=`app`@`localhost` SQL SECURITY DEFINER */"),
        "/*!50013 SQL SECURITY DEFINER */"
    );
    assert_eq!(
        strip("CREATE DEFINER=`root`@`%` TRIGGER t BEFORE INSERT ON x FOR EACH ROW SET @a=1;"),
        "CREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW SET @a=1;"
    );
    assert_eq!(
        strip("INSERT INTO t VALUES ('plain');"),
        "INSERT INTO t VALUES ('plain');"
    );
    assert_eq!(strip("DEFINER=not-a-clause"), "DEFINER=not-a-clause");
    assert_eq!(
        strip("CREATE DEFINER=CURRENT_USER PROCEDURE p() SET @a=1;"),
        "CREATE PROCEDURE p() SET @a=1;"
    );
}

#[test]
fn sec02_the_import_account_can_only_reach_its_own_database() {
    let sql = databases::import_account_sql("shop", "cp_owner_x", "Some-Password-123");
    assert!(
        sql.contains("GRANT ALL PRIVILEGES ON `shop`.* TO 'cp_owner_x'@'localhost'"),
        "{sql}"
    );
    assert!(!sql.contains("*.*"), "{sql}");
    assert!(!sql.to_uppercase().contains("WITH GRANT OPTION"), "{sql}");
    assert!(!sql.to_uppercase().contains("SUPER"), "{sql}");
    assert!(!sql.to_uppercase().contains(" FILE"), "{sql}");
}
