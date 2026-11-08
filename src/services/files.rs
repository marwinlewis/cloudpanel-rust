//! File manager confined to a site's home directory.
//!
//! Every client path is relative to the site home. It is normalized lexically (no `..`, no
//! absolute paths), and every operation then works through [`Confined`], so neither a link nor a
//! folder swapped for a link at the wrong moment can take the panel, as root, out of the home.

use super::cmd::{run_with, CmdOpts};
use super::sysusers;
use crate::fsutil::{Confined, Pinned};
use serde::Serialize;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const MAX_EDIT_BYTES: u64 = 2 * 1024 * 1024;

pub struct SiteFs {
    root: PathBuf,
    confined: Confined,
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
        std::io::ErrorKind::PermissionDenied if e.to_string() == crate::fsutil::ESCAPED => {
            crate::fsutil::ESCAPED.into()
        }
        std::io::ErrorKind::PermissionDenied => "Permission denied".into(),
        std::io::ErrorKind::AlreadyExists => "A file with that name already exists".into(),
        std::io::ErrorKind::InvalidInput => "Not a file".into(),
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
        let confined = Confined::open(&root).map_err(|e| format!("Site home is not accessible: {e}"))?;
        Ok(SiteFs {
            root,
            confined,
            user: user.to_string(),
        })
    }

    /// A client path ("htdocs/a.com/index.html", "/", "") in terms of the home, with nothing in it
    /// that climbs up.
    fn clean(rel: &str) -> Result<PathBuf, String> {
        if rel.contains('\0') || rel.len() > 4096 {
            return Err("Invalid path".into());
        }
        let mut out = PathBuf::new();
        for comp in Path::new(rel.trim_start_matches(['/', '\\'])).components() {
            match comp {
                Component::Normal(c) => out.push(c),
                Component::CurDir => {}
                _ => return Err(crate::fsutil::ESCAPED.into()),
            }
        }
        Ok(out)
    }

    /// Normalize a client path to an absolute one, checking that it leads somewhere inside the home.
    /// For paths handed to a command running as the site's user, who can't do more with them than
    /// that user could anyway. As root, use [`Self::pin`], as this can change straight afterwards.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf, String> {
        let clean = Self::clean(rel)?;
        // The deepest part that exists has to be inside. What's below it doesn't exist yet.
        let mut probe = clean.clone();
        loop {
            match self.confined.pin(&probe, true) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && probe.pop() => {}
                Err(e) => return Err(io_err(e)),
            }
        }
        Ok(self.root.join(clean))
    }

    fn pin(&self, rel: &str, follow_last: bool) -> Result<Pinned, String> {
        self.confined.pin(&Self::clean(rel)?, follow_last).map_err(io_err)
    }

    fn owner(&self) -> Result<Option<(u32, u32)>, String> {
        sysusers::ids(&self.user)
    }

    /// Path shown to the client, relative to the home.
    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default()
    }

    pub fn list(&self, rel: &str) -> Result<Vec<Entry>, String> {
        let dir = self.confined.pin_dir(&Self::clean(rel)?).map_err(io_err)?;
        let mut out = Vec::new();
        for ent in fs::read_dir(dir.path()).map_err(io_err)? {
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
        use std::io::Read;
        let file = self.confined.open_file(&Self::clean(rel)?, true).map_err(io_err)?;
        if file.metadata().map_err(io_err)?.len() > MAX_EDIT_BYTES {
            return Err("File is too large to edit here (max 2 MB); download it instead".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_EDIT_BYTES + 1).read_to_end(&mut bytes).map_err(io_err)?;
        if bytes.len() as u64 > MAX_EDIT_BYTES {
            return Err("File is too large to edit here (max 2 MB); download it instead".into());
        }
        if bytes.contains(&0) {
            return Err("This looks like a binary file; download it instead".into());
        }
        String::from_utf8(bytes).map_err(|_| "File is not UTF-8 text; download it instead".to_string())
    }

    pub fn write_text(&self, rel: &str, content: &str) -> Result<(), String> {
        if content.len() as u64 > MAX_EDIT_BYTES {
            return Err("Content is too large (max 2 MB)".into());
        }
        let clean = Self::clean(rel)?;
        let at = match self.confined.pin(&clean, true) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Saving a new file makes the folders it needs.
                if let Some(parent) = clean.parent() {
                    self.confined.mkdir_all(parent, self.owner()?).map_err(io_err)?;
                }
                self.confined.pin(&clean, true).map_err(io_err)?
            }
            other => other.map_err(io_err)?,
        };
        if at.leaf().is_none() {
            return Err("Not a file".into());
        }
        let mode = match at.lstat().map_err(io_err)? {
            Some(m) if m.is_dir() => return Err("Not a file".into()),
            Some(m) if !m.is_file() => return Err("Not a file".into()),
            Some(m) => mode_of(&m),
            None => 0o644,
        };
        crate::fsutil::write_atomic(at.path(), content.as_bytes(), mode).map_err(io_err)?;
        crate::fsutil::lchown(at.path(), self.owner()?).map_err(io_err)
    }

    pub fn mkdir(&self, rel: &str) -> Result<(), String> {
        let clean = Self::clean(rel)?;
        if clean.as_os_str().is_empty() {
            return Err("A file with that name already exists".into());
        }
        match self.confined.pin(&clean, false) {
            Ok(at) if at.lstat().map_err(io_err)?.is_some() => {
                return Err("A file with that name already exists".into());
            }
            Ok(_) => {}
            // Folders on the way that aren't there yet get made too.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(e)),
        }
        self.confined.mkdir_all(&clean, self.owner()?).map_err(io_err)
    }

    pub fn create_file(&self, rel: &str) -> Result<(), String> {
        let at = self.pin(rel, false)?;
        if at.leaf().is_none() {
            return Err("A file with that name already exists".into());
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(at.path())
            .map_err(io_err)?;
        crate::fsutil::fchown(&file, self.owner()?).map_err(io_err)
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        let (a_clean, b_clean) = (Self::clean(from)?, Self::clean(to)?);
        let a = self.confined.pin(&a_clean, false).map_err(io_err)?;
        let b = self.confined.pin(&b_clean, false).map_err(io_err)?;
        if a.leaf().is_none() || b.leaf().is_none() {
            return Err("Cannot move the site directory itself".into());
        }
        if b.lstat().map_err(io_err)?.is_some() {
            return Err("The destination already exists".into());
        }
        if b_clean.starts_with(&a_clean) {
            return Err("Cannot move a folder into itself".into());
        }
        fs::rename(a.path(), b.path()).map_err(io_err)
    }

    pub fn delete(&self, rel: &str) -> Result<(), String> {
        let at = self.pin(rel, false)?;
        if at.leaf().is_none() {
            return Err("Cannot delete the site directory".into());
        }
        let meta = at.lstat().map_err(io_err)?.ok_or("No such file or directory")?;
        if meta.is_dir() {
            fs::remove_dir_all(at.path()).map_err(io_err)
        } else {
            fs::remove_file(at.path()).map_err(io_err)
        }
    }

    pub fn chmod(&self, rel: &str, mode: u32) -> Result<(), String> {
        if mode & 0o7000 != 0 {
            return Err("setuid, setgid and sticky bits are not allowed".into());
        }
        let at = self.pin(rel, false)?;
        let meta = at.lstat().map_err(io_err)?.ok_or("No such file or directory")?;
        if meta.file_type().is_symlink() {
            return Err("Cannot change the mode of a symlink".into());
        }
        if meta.is_dir() {
            let dir = self.confined.pin_dir(&Self::clean(rel)?).map_err(io_err)?;
            return crate::fsutil::set_mode(dir.path(), mode).map_err(io_err);
        }
        let file = crate::fsutil::open_regular(at.path()).map_err(io_err)?;
        crate::fsutil::fchmod(&file, mode).map_err(io_err)
    }

    /// Where a new uploaded file in `dir` goes (must not exist unless `overwrite`). The folder is
    /// held, so this stays that folder however long the caller takes.
    pub fn upload_target(&self, dir: &str, name: &str, overwrite: bool) -> Result<Pinned, String> {
        let name = crate::validate::file_name(name)?;
        let folder = Self::clean(dir)?;
        let at = self.confined.pin_dir(&folder).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "Upload folder does not exist".to_string(),
            _ => io_err(e),
        })?;
        let target = self.confined.pin(&folder.join(&name), false).map_err(io_err)?;
        drop(at);
        match target.lstat().map_err(io_err)? {
            Some(m) if m.file_type().is_symlink() => Err("Refusing to overwrite a symlink".into()),
            Some(m) if m.is_dir() => Err("A folder with that name already exists".into()),
            Some(_) if !overwrite => Err("A file with that name already exists".into()),
            _ => Ok(target),
        }
    }

    /// Put an uploaded temp file in its place, belonging to the site's user. The temp file sits in
    /// the home while it arrives, so it may well not be what the panel wrote any more: it must
    /// still be the same file, `written`, and only the open file is ever changed.
    pub fn install_upload(&self, temp: &Path, written: (u64, u64), target: &Pinned) -> Result<(), String> {
        let name = temp.file_name().ok_or("Invalid upload")?;
        let at = self.confined.pin(Path::new(name), false).map_err(io_err)?;
        let file = crate::fsutil::open_regular(at.path()).map_err(io_err)?;
        if crate::fsutil::identity(&file.metadata().map_err(io_err)?) != written {
            return Err("The upload was changed while it was being received".into());
        }
        crate::fsutil::fchmod(&file, 0o644).map_err(io_err)?;
        crate::fsutil::fchown(&file, self.owner()?).map_err(io_err)?;
        fs::rename(at.path(), target.path()).map_err(io_err)
    }

    /// Open a regular file inside the home for downloading: the open file, its name and its size.
    pub fn download_path(&self, rel: &str) -> Result<(fs::File, String, u64), String> {
        let clean = Self::clean(rel)?;
        let file = self.confined.open_file(&clean, true).map_err(io_err)?;
        let len = file.metadata().map_err(io_err)?.len();
        let name = clean
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "download".into());
        Ok((file, name, len))
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
