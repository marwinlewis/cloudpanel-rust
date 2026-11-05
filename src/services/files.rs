//! File manager confined to a site's home directory.
//!
//! Every client path is relative to the site home. It is normalized lexically (no `..`,
//! no absolute paths), then the canonical form of the deepest existing ancestor is checked
//! to still be inside the canonical home, so symlinks cannot be used to escape.

use super::cmd::{run_with, CmdOpts};
use super::sysusers;
use serde::Serialize;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const MAX_EDIT_BYTES: u64 = 2 * 1024 * 1024;

pub struct SiteFs {
    root: PathBuf,
    canon_root: PathBuf,
    user: String,
}

#[derive(Serialize)]
pub struct Entry {
    pub name: String,
    pub kind: &'static str, // file, dir, symlink
    pub size: u64,
    pub mode: String,
    pub modified: Option<i64>,
    pub target: Option<String>,
}

fn io_err(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory".into(),
        std::io::ErrorKind::PermissionDenied => "Permission denied".into(),
        std::io::ErrorKind::AlreadyExists => "A file with that name already exists".into(),
        _ => e.to_string(),
    }
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn mode_of(meta: &fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else if meta.is_dir() {
        0o755
    } else {
        0o644
    }
}

impl SiteFs {
    pub fn new(home: &str, user: &str) -> Result<Self, String> {
        let root = PathBuf::from(home);
        let canon_root = fs::canonicalize(&root).map_err(|e| format!("Site home is not accessible: {e}"))?;
        Ok(SiteFs {
            root,
            canon_root,
            user: user.to_string(),
        })
    }

    /// Normalize a client path ("htdocs/a.com/index.html", "/", "") to an absolute path.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf, String> {
        if rel.contains('\0') || rel.len() > 4096 {
            return Err("Invalid path".into());
        }
        let mut out = self.root.clone();
        for comp in Path::new(rel.trim_start_matches(['/', '\\'])).components() {
            match comp {
                Component::Normal(c) => out.push(c),
                Component::CurDir => {}
                _ => return Err("Path must stay inside the site directory".into()),
            }
        }
        // Check the deepest existing ancestor after resolving symlinks.
        let mut probe = out.clone();
        loop {
            if let Ok(canon) = fs::canonicalize(&probe) {
                if !canon.starts_with(&self.canon_root) {
                    return Err("Path must stay inside the site directory".into());
                }
                break;
            }
            if !probe.pop() {
                return Err("Invalid path".into());
            }
        }
        Ok(out)
    }

    /// Path shown to the client, relative to the home.
    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default()
    }

    fn is_root(&self, p: &Path) -> bool {
        p == self.root
    }

    pub fn list(&self, rel: &str) -> Result<Vec<Entry>, String> {
        let dir = self.resolve(rel)?;
        let mut out = Vec::new();
        for ent in fs::read_dir(&dir).map_err(io_err)? {
            let ent = ent.map_err(io_err)?;
            let meta = match ent.path().symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let kind = if meta.file_type().is_symlink() {
                "symlink"
            } else if meta.is_dir() {
                "dir"
            } else {
                "file"
            };
            out.push(Entry {
                name: ent.file_name().to_string_lossy().into_owned(),
                kind,
                size: if meta.is_dir() { 0 } else { meta.len() },
                mode: format!("{:o}", mode_of(&meta)),
                modified: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64),
                target: if kind == "symlink" {
                    fs::read_link(ent.path()).ok().map(|t| t.to_string_lossy().into_owned())
                } else {
                    None
                },
            });
        }
        out.sort_by_key(|e| (e.kind != "dir", e.name.to_lowercase()));
        Ok(out)
    }

    pub fn read_text(&self, rel: &str) -> Result<String, String> {
        let p = self.resolve(rel)?;
        let meta = fs::metadata(&p).map_err(io_err)?;
        if !meta.is_file() {
            return Err("Not a file".into());
        }
        if meta.len() > MAX_EDIT_BYTES {
            return Err("File is too large to edit here (max 2 MB); download it instead".into());
        }
        let bytes = fs::read(&p).map_err(io_err)?;
        if bytes.contains(&0) {
            return Err("This looks like a binary file; download it instead".into());
        }
        String::from_utf8(bytes).map_err(|_| "File is not UTF-8 text; download it instead".to_string())
    }

    pub fn write_text(&self, rel: &str, content: &str) -> Result<(), String> {
        if content.len() as u64 > MAX_EDIT_BYTES {
            return Err("Content is too large (max 2 MB)".into());
        }
        let p = self.resolve(rel)?;
        if self.is_root(&p) || p.is_dir() {
            return Err("Not a file".into());
        }
        let existed = p.exists();
        let mode = fs::metadata(&p).map(|m| mode_of(&m)).unwrap_or(0o644);
        crate::fsutil::write_atomic(&p, content.as_bytes(), mode).map_err(io_err)?;
        let _ = existed;
        sysusers::chown_one(&p, &self.user)
    }

    pub fn mkdir(&self, rel: &str) -> Result<(), String> {
        let p = self.resolve(rel)?;
        if p.exists() {
            return Err("A file with that name already exists".into());
        }
        fs::create_dir_all(&p).map_err(io_err)?;
        sysusers::chown_one(&p, &self.user)
    }

    pub fn create_file(&self, rel: &str) -> Result<(), String> {
        let p = self.resolve(rel)?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .map_err(io_err)?;
        sysusers::chown_one(&p, &self.user)
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let a = self.resolve(from)?;
        let b = self.resolve(to)?;
        if self.is_root(&a) || self.is_root(&b) {
            return Err("Cannot move the site directory itself".into());
        }
        if b.exists() {
            return Err("The destination already exists".into());
        }
        if b.starts_with(&a) {
            return Err("Cannot move a folder into itself".into());
        }
        fs::rename(&a, &b).map_err(io_err)
    }

    pub fn delete(&self, rel: &str) -> Result<(), String> {
        let p = self.resolve(rel)?;
        if self.is_root(&p) {
            return Err("Cannot delete the site directory".into());
        }
        let meta = p.symlink_metadata().map_err(io_err)?;
        if meta.is_dir() && !meta.file_type().is_symlink() {
            fs::remove_dir_all(&p).map_err(io_err)
        } else {
            fs::remove_file(&p).map_err(io_err)
        }
    }

    pub fn chmod(&self, rel: &str, mode: u32) -> Result<(), String> {
        let p = self.resolve(rel)?;
        if mode & 0o7000 != 0 {
            return Err("setuid, setgid and sticky bits are not allowed".into());
        }
        let meta = p.symlink_metadata().map_err(io_err)?;
        if meta.file_type().is_symlink() {
            return Err("Cannot change the mode of a symlink".into());
        }
        crate::fsutil::set_mode(&p, mode).map_err(io_err)
    }

    /// Path for a new uploaded file in `dir` (must not exist unless `overwrite`).
    pub fn upload_target(&self, dir: &str, name: &str, overwrite: bool) -> Result<PathBuf, String> {
        let name = crate::validate::file_name(name)?;
        let d = self.resolve(dir)?;
        if !d.is_dir() {
            return Err("Upload folder does not exist".into());
        }
        let p = d.join(name);
        if p.exists() && !overwrite {
            return Err("A file with that name already exists".into());
        }
        if p.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("Refusing to overwrite a symlink".into());
        }
        Ok(p)
    }

    pub fn finish_upload(&self, path: &Path) -> Result<(), String> {
        let _ = crate::fsutil::set_mode(path, 0o644);
        sysusers::chown_one(path, &self.user)
    }

    /// Path for downloading: must be a regular file inside the home.
    pub fn download_path(&self, rel: &str) -> Result<(PathBuf, u64), String> {
        let p = self.resolve(rel)?;
        let canon = fs::canonicalize(&p).map_err(io_err)?;
        if !canon.starts_with(&self.canon_root) {
            return Err("Path must stay inside the site directory".into());
        }
        let meta = fs::metadata(&canon).map_err(io_err)?;
        if !meta.is_file() {
            return Err("Not a file".into());
        }
        Ok((canon, meta.len()))
    }

    fn opts(&self, cwd: &Path) -> CmdOpts {
        let o = CmdOpts::default().cwd(cwd).timeout(30 * 60);
        if cfg!(unix) {
            o.user(&self.user)
        } else {
            o
        }
    }

    /// Extract a .zip / .tar / .tar.gz / .tgz archive next to itself, as the site user.
    pub fn extract(&self, rel: &str) -> Result<(), String> {
        let p = self.resolve(rel)?;
        let dir = p.parent().ok_or("Invalid path")?.to_path_buf();
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let file = p.to_string_lossy().into_owned();
        let r = if name.ends_with(".zip") {
            run_with("unzip", &["-o", "-q", "--", &file], &self.opts(&dir))
        } else if [".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz"]
            .iter()
            .any(|e| name.ends_with(e))
        {
            run_with(
                "tar",
                &["-xf", &file, "--no-same-owner", "--no-same-permissions"],
                &self.opts(&dir),
            )
        } else {
            return Err("Supported archives: .zip, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz".into());
        };
        r.into_result("extract", "unzip/tar is not installed").map(|_| ())
    }

    /// Compress entries of a directory into `<archive>.tar.gz`, as the site user.
    pub fn compress(&self, dir: &str, names: &[String], archive: &str) -> Result<String, String> {
        let d = self.resolve(dir)?;
        let mut archive = crate::validate::file_name(archive)?;
        if !archive.ends_with(".tar.gz") {
            archive.push_str(".tar.gz");
        }
        if d.join(&archive).exists() {
            return Err("An archive with that name already exists".into());
        }
        let mut args = vec!["-czf".to_string(), archive.clone(), "--".to_string()];
        for n in names {
            let n = crate::validate::file_name(n)?;
            self.resolve(&format!("{}/{n}", self.rel(&d)))?;
            args.push(n);
        }
        if names.is_empty() {
            return Err("Select files to compress".into());
        }
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        run_with("tar", &argv, &self.opts(&d)).into_result("tar", "tar is not installed")?;
        Ok(archive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user running the tests. Writes are chowned to the site user, and only root
    /// may chown to someone else (CI runs unprivileged), but anyone may chown to themselves.
    fn current_user() -> String {
        std::process::Command::new("id")
            .arg("-un")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|u| !u.is_empty())
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "nobody".into())
    }

    fn sfs() -> (tempfile::TempDir, SiteFs) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("home/htdocs")).unwrap();
        let s = SiteFs::new(&dir.path().join("home").to_string_lossy(), &current_user()).unwrap();
        (dir, s)
    }

    #[test]
    fn confines_paths() {
        let (dir, s) = sfs();
        assert!(s.resolve("htdocs/index.html").is_ok());
        assert!(s.resolve("").is_ok());
        assert!(s.resolve("../etc/passwd").is_err());
        assert!(s.resolve("htdocs/../../x").is_err());
        fs::write(dir.path().join("outside.txt"), "x").unwrap();
        assert!(s.resolve("/htdocs").unwrap().starts_with(dir.path()));
        assert!(s.delete("").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        let (dir, s) = sfs();
        fs::create_dir_all(dir.path().join("secret")).unwrap();
        fs::write(dir.path().join("secret/key"), "x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("secret"), dir.path().join("home/link")).unwrap();
        assert!(s.resolve("link/key").is_err());
        assert!(s.read_text("link/key").is_err());
        assert!(s.list("link").is_err());
    }

    #[test]
    fn edit_rename_delete() {
        let (_dir, s) = sfs();
        s.write_text("htdocs/a.txt", "hello").unwrap();
        assert_eq!(s.read_text("htdocs/a.txt").unwrap(), "hello");
        s.mkdir("htdocs/sub").unwrap();
        s.rename("htdocs/a.txt", "htdocs/sub/b.txt").unwrap();
        assert!(s.rename("htdocs/sub", "htdocs/sub/inner").is_err());
        let names: Vec<String> = s.list("htdocs/sub").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["b.txt"]);
        s.delete("htdocs/sub").unwrap();
        assert!(s.list("htdocs").unwrap().is_empty());
        assert!(s.upload_target("htdocs", "../x", false).is_err());
    }
}
