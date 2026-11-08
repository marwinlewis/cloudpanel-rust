use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};

/// Atomically write `contents` to `path` (write temp file + rename) with the given unix mode.
#[allow(unused_variables)]
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = dir.join(format!(".{}.tmp{}", file_name, std::process::id()));

    // The directory may be writable by a site user while the panel runs as root, and the
    // temp name is predictable: never open a planted file or follow a planted symlink.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut f = opts.open(&tmp)?;
        // Set the mode on the open file, so the umask can't widen or narrow it and a swapped
        // path can't redirect the chmod.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Create a directory (and parents) and restrict it to the given unix mode.
pub fn create_private_dir(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    set_mode(path, mode)
}

#[allow(unused_variables)]
pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// A directory tree that links can't lead out of, for the panel's work in directories its site
/// users can write to.
///
/// Checking a path and then using it leaves a gap, in which the path's owner can swap any folder
/// along it for a link, so the panel, as root, would act on whatever that points at. So nothing
/// here looks a path up twice. It walks down one part at a time, holding each folder open, never
/// following a link without resolving it itself, and hands back a path through `/proc/self/fd`
/// that means that folder whatever happens to its name afterwards. Links that stay inside the tree
/// keep working, as sites do use them (`current -> releases/42`).
pub struct Confined {
    #[cfg(unix)]
    root: std::os::fd::OwnedFd,
    canon: PathBuf,
}

/// A location inside a [`Confined`] tree, valid while this lives.
pub struct Pinned {
    #[cfg(unix)]
    _held: std::os::fd::OwnedFd,
    path: PathBuf,
    leaf: Option<OsString>,
}

impl Pinned {
    /// A path to this location, for the file functions. Its folders can't change under it, though
    /// the last part can, so what opens it must not follow links: see [`Confined::open_file`].
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The last part of the path, or None for a folder pinned as a whole.
    pub fn leaf(&self) -> Option<&OsStr> {
        self.leaf.as_deref()
    }

    /// The link, file or folder here, without following a link. None if nothing's there.
    pub fn lstat(&self) -> std::io::Result<Option<fs::Metadata>> {
        match fs::symlink_metadata(&self.path) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// A sibling of this location, in the same held folder.
    pub fn sibling(&self, name: &str) -> PathBuf {
        match self.path.parent() {
            Some(dir) if self.leaf.is_some() => dir.join(name),
            _ => self.path.join(name),
        }
    }
}

fn escaped() -> std::io::Error {
    std::io::Error::new(ErrorKind::PermissionDenied, ESCAPED)
}

/// The message for a path that leads out of its tree.
pub const ESCAPED: &str = "Path must stay inside the site directory";

impl Confined {
    pub fn open(root: &Path) -> std::io::Result<Self> {
        let canon = fs::canonicalize(root)?;
        #[cfg(unix)]
        {
            use rustix::fs::{openat, Mode, OFlags, CWD};
            let root = openat(
                CWD,
                &canon,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(Confined { root, canon })
        }
        #[cfg(not(unix))]
        Ok(Confined { canon })
    }

    /// The real location of the tree, with no links in it.
    pub fn canonical(&self) -> &Path {
        &self.canon
    }

    /// Walk to `rel`. Links in its folders are followed for as long as they stay inside, or it's
    /// an error. The same goes for the last part with `follow_last`, and otherwise that is left as
    /// it is, whatever it is. The last part needn't exist. Its folders must.
    #[cfg(unix)]
    pub fn pin(&self, rel: &Path, follow_last: bool) -> std::io::Result<Pinned> {
        use rustix::fs::{fstat, openat, readlinkat, FileType, Mode, OFlags};
        use std::collections::VecDeque;
        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::ffi::OsStrExt;

        const MAX_LINKS: u32 = 40;
        // Each holds a descriptor. Anything deeper than this isn't a real site's path.
        const MAX_DEPTH: usize = 256;

        let parts = |p: &Path| -> std::io::Result<VecDeque<OsString>> {
            let mut out = VecDeque::new();
            for c in p.components() {
                match c {
                    Component::Normal(n) => out.push_back(n.to_os_string()),
                    Component::CurDir => {}
                    Component::ParentDir => out.push_back("..".into()),
                    Component::RootDir | Component::Prefix(_) => return Err(escaped()),
                }
            }
            Ok(out)
        };

        let mut queue = parts(rel)?;
        let mut stack = vec![self.root.as_fd().try_clone_to_owned()?];
        let mut links = 0;
        let mut leaf = None;
        while let Some(part) = queue.pop_front() {
            if part.as_bytes() == b".." {
                if stack.len() == 1 {
                    return Err(escaped());
                }
                stack.pop();
                continue;
            }
            let top = stack.last().unwrap().as_fd();
            let last = queue.is_empty();
            if last && !follow_last {
                leaf = Some(part);
                break;
            }
            let opened = openat(
                top,
                part.as_os_str(),
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            );
            let fd = match opened {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if last => {
                    leaf = Some(part);
                    break;
                }
                Err(e) => return Err(e.into()),
            };
            let kind = FileType::from_raw_mode(fstat(&fd)?.st_mode);
            if kind == FileType::Symlink {
                links += 1;
                if links > MAX_LINKS {
                    return Err(rustix::io::Errno::LOOP.into());
                }
                let target = readlinkat(top, part.as_os_str(), Vec::new())?;
                let target = Path::new(OsStr::from_bytes(target.as_bytes()));
                let target = if target.is_absolute() {
                    // An absolute link is fine if it points inside. It starts again from the top.
                    let inside = target.strip_prefix(&self.canon).map_err(|_| escaped())?;
                    stack.truncate(1);
                    inside
                } else {
                    target
                };
                for p in parts(target)?.into_iter().rev() {
                    queue.push_front(p);
                }
                if queue.len() + stack.len() > MAX_DEPTH {
                    return Err(rustix::io::Errno::NAMETOOLONG.into());
                }
                continue;
            }
            if last {
                leaf = Some(part);
                break;
            }
            if kind != FileType::Directory {
                return Err(rustix::io::Errno::NOTDIR.into());
            }
            stack.push(fd);
            if stack.len() > MAX_DEPTH {
                return Err(rustix::io::Errno::NAMETOOLONG.into());
            }
        }
        let held = stack.pop().unwrap();
        let mut path = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
        if let Some(l) = &leaf {
            path.push(l);
        }
        Ok(Pinned {
            _held: held,
            path,
            leaf,
        })
    }

    /// Local development on Windows: site users and links don't come into it.
    #[cfg(not(unix))]
    pub fn pin(&self, rel: &Path, _follow_last: bool) -> std::io::Result<Pinned> {
        let mut path = self.canon.clone();
        let mut leaf = None;
        for c in rel.components() {
            match c {
                Component::Normal(n) => {
                    path.push(n);
                    leaf = Some(n.to_os_string());
                }
                Component::CurDir => {}
                _ => return Err(escaped()),
            }
        }
        Ok(Pinned { path, leaf })
    }

    /// A folder, held open as a whole, so everything under the returned path is really inside it.
    #[cfg(unix)]
    pub fn pin_dir(&self, rel: &Path) -> std::io::Result<Pinned> {
        use rustix::fs::{openat, Mode, OFlags};
        use std::os::fd::AsRawFd;
        let at = self.pin(rel, true)?;
        let Some(leaf) = &at.leaf else {
            return Ok(at);
        };
        let held = openat(
            &at._held,
            leaf.as_os_str(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let path = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
        Ok(Pinned {
            _held: held,
            path,
            leaf: None,
        })
    }

    #[cfg(not(unix))]
    pub fn pin_dir(&self, rel: &Path) -> std::io::Result<Pinned> {
        let mut at = self.pin(rel, true)?;
        at.leaf = None;
        Ok(at)
    }

    /// Open a regular file for reading. The last part is followed if `follow_last`, inside the tree
    /// only, and anything other than a regular file is an error, without hanging on a FIFO.
    pub fn open_file(&self, rel: &Path, follow_last: bool) -> std::io::Result<fs::File> {
        let at = self.pin(rel, follow_last)?;
        open_regular(at.path())
    }

    /// Make the folder `rel` and any missing above it, each belonging to `owner`.
    pub fn mkdir_all(&self, rel: &Path, owner: Option<(u32, u32)>) -> std::io::Result<()> {
        let mut sofar = PathBuf::new();
        for c in rel.components() {
            sofar.push(c);
            if !matches!(c, Component::Normal(_)) {
                continue;
            }
            let at = self.pin(&sofar, true)?;
            match at.lstat()? {
                Some(m) if m.is_dir() => {}
                Some(_) => return Err(rustix_notdir()),
                None => {
                    fs::create_dir(at.path())?;
                    lchown(at.path(), owner)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn rustix_notdir() -> std::io::Error {
    rustix::io::Errno::NOTDIR.into()
}
#[cfg(not(unix))]
fn rustix_notdir() -> std::io::Error {
    std::io::Error::other("Not a directory")
}

/// Open a path for reading if it's a regular file, without following a link at its end and without
/// waiting on a FIFO.
pub fn open_regular(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(ErrorKind::InvalidInput, "Not a file"));
    }
    Ok(file)
}

/// Give a path to `owner`, the link itself if it is one. None leaves it alone.
#[allow(unused_variables)]
pub fn lchown(path: &Path, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Give an open file to `owner`, which no swapped path can redirect. None leaves it alone.
#[allow(unused_variables)]
pub fn fchown(file: &fs::File, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Set the mode of an open file, which no swapped path can redirect.
#[allow(unused_variables)]
pub fn fchmod(file: &fs::File, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Whether the panel could act on another user's files.
pub fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The owner of a file, where there is such a thing.
#[allow(unused_variables)]
pub fn owner_uid(meta: &fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(meta.uid())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// What identifies a file whatever its name becomes: (device, inode). Nothing on Windows, which is
/// only local development, with no site users to guard against.
#[allow(unused_variables)]
pub fn identity(meta: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        (0, 0)
    }
}

/// Read a text file that a site's user controls, as root: inside `root` only, a regular file only,
/// and at most `max` bytes. For anything that isn't that, an error.
pub fn read_confined(root: &Path, file: &Path, max: u64) -> std::io::Result<String> {
    use std::io::Read;
    let confined = Confined::open(root)?;
    let canon_file = file
        .strip_prefix(root)
        .or_else(|_| file.strip_prefix(confined.canonical()));
    let rel = canon_file.map_err(|_| escaped())?;
    let f = confined.open_file(rel, true)?;
    let mut text = String::new();
    f.take(max).read_to_string(&mut text)?;
    Ok(text)
}

/// Last `lines` lines of a text file, reading at most the final 2 MB.
pub fn tail_file(path: &Path, lines: usize) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX: u64 = 2 * 1024 * 1024;
    let mut f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(MAX);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let all: Vec<&str> = text.lines().collect();
    let skip = all.len().saturating_sub(lines);
    Ok(all[skip..].join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tails_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.log");
        fs::write(&p, "a\nb\nc\nd\n").unwrap();
        assert_eq!(tail_file(&p, 2).unwrap(), "c\nd");
        assert_eq!(tail_file(&p, 10).unwrap(), "a\nb\nc\nd");
    }
}
