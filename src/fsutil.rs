use std::fs;
use std::io::Write;
use std::path::Path;

/// Atomically write `contents` to `path` (write temp file + rename) with the given unix mode.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = dir.join(format!(".{}.tmp{}", file_name, std::process::id()));

    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    set_mode(&tmp, mode)?;
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
