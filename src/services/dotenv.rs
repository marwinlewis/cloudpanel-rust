//! A site's `.env` file: the single source of truth for its app's environment variables.
//!
//! The file belongs to the site user, so root never hands it to anything that would follow
//! a link: systemd gets a copy rendered by the panel (see `apps::render_env`), never an
//! `EnvironmentFile=` pointing at this path, which PID 1 would read as root.

use super::apps;
use super::files::SiteFs;
use crate::db::models::Site;
use crate::validate;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MAX_ENV_BYTES: u64 = 256 * 1024;
const MAX_VALUE_BYTES: usize = 32 * 1024;

#[derive(Debug, Default)]
pub struct Parsed {
    pub vars: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

/// Parse dotenv text. Lines that can't be understood become warnings rather than errors,
/// because the file may also be edited by hand.
pub fn parse(text: &str) -> Parsed {
    let text = text.replace("\r\n", "\n");
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Parsed::default();
    let mut i = 0;
    while i < lines.len() {
        let no = i + 1;
        let line = lines[i].trim_start();
        i += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map(str::trim_start).unwrap_or(line);
        let Some((key, rest)) = line.split_once('=') else {
            out.warnings.push(format!("Line {no}: expected KEY=value"));
            continue;
        };
        let key = key.trim();
        if validate::env_key(key).is_err() {
            out.warnings.push(format!("Line {no}: invalid variable name"));
            continue;
        }
        let rest = rest.trim_start();
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                // Quoted values may span lines; give up and keep the literal text if unclosed.
                let mut buf = rest[1..].to_string();
                let mut next = i;
                let closed = loop {
                    if let Some(v) = closing_quote(&buf, q) {
                        break Some(v);
                    }
                    if next >= lines.len() {
                        break None;
                    }
                    buf.push('\n');
                    buf.push_str(lines[next]);
                    next += 1;
                };
                match closed {
                    Some(v) => {
                        i = next;
                        v
                    }
                    None => {
                        out.warnings.push(format!("Line {no}: unterminated quote"));
                        rest.trim_end().to_string()
                    }
                }
            }
            _ => strip_inline_comment(rest).trim_end().to_string(),
        };
        if value.len() > MAX_VALUE_BYTES {
            out.warnings.push(format!("Line {no}: value is too long"));
            continue;
        }
        out.vars.insert(key.to_string(), value);
    }
    out
}

/// The unescaped value if `s` (the text after an opening quote) contains its closing quote.
fn closing_quote(s: &str, quote: char) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == quote {
            return Some(out);
        }
        if c == '\\' && quote == '"' {
            match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                e @ ('"' | '\\' | '$' | '`') => out.push(e),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(c);
        }
    }
    None
}

fn strip_inline_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &s[..i];
        }
    }
    s
}

/// Format a value so that [`parse`] reads back exactly the same string.
pub fn quote_value(v: &str) -> String {
    let plain = !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '+' | ',' | '='));
    if plain {
        return v.to_string();
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Path of the site's `.env` (None for sites created before v0.3, which have no user).
pub fn path_for(site: &Site) -> Option<PathBuf> {
    site.home_dir.as_ref()?;
    Some(Path::new(&apps::workdir(site)).join(".env"))
}

/// Read the site's `.env`, or None if it doesn't exist.
///
/// The panel runs as root and the site user controls this path, so the file must be a regular file
/// inside the site's home, and neither a link there nor one swapped in for a folder on the way to
/// it (say, to another site's working folder) can leak another file.
pub fn read_site(site: &Site) -> Result<Option<String>, String> {
    let Some(path) = path_for(site) else {
        return Ok(None);
    };
    let home = site.home_dir.as_deref().unwrap_or_default();
    let confined = crate::fsutil::Confined::open(Path::new(home)).map_err(|e| format!("Cannot read .env: {e}"))?;
    let rel = path
        .strip_prefix(home)
        .map_err(|_| "The working directory must be inside the site's home".to_string())?;
    let not_a_file = || ".env must be a regular file, not a link or folder".to_string();
    let at = match confined.pin(rel, false) {
        Ok(at) => at,
        // A folder on the way that doesn't exist yet is the same as no file.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot read .env: {e}")),
    };
    match at.lstat().map_err(|e| format!("Cannot read .env: {e}"))? {
        None => return Ok(None),
        Some(m) if !m.file_type().is_file() => return Err(not_a_file()),
        Some(m) if m.len() > MAX_ENV_BYTES => {
            return Err(format!(".env is too large (max {} KB)", MAX_ENV_BYTES / 1024))
        }
        Some(_) => {}
    }
    let mut file = crate::fsutil::open_regular(at.path()).map_err(|_| not_a_file())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_ENV_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read .env: {e}"))?;
    if bytes.len() as u64 > MAX_ENV_BYTES {
        return Err(format!(".env is too large (max {} KB)", MAX_ENV_BYTES / 1024));
    }
    if bytes.contains(&0) {
        return Err(".env is not a text file".into());
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ".env is not UTF-8 text".to_string())
}

/// Write the site's `.env`. A new file is created owner and group only, before any content
/// goes in; an existing file keeps its mode.
pub fn write_site(site: &Site, content: &str) -> Result<(), String> {
    if content.len() as u64 > MAX_ENV_BYTES {
        return Err(format!(".env is too large (max {} KB)", MAX_ENV_BYTES / 1024));
    }
    let path = path_for(site).ok_or("This site has no home directory")?;
    let home = site.home_dir.as_deref().ok_or("This site has no home directory")?;
    let dir = path.parent().ok_or("Invalid working directory")?;
    if !dir.is_dir() && dir.symlink_metadata().is_err() {
        return Err(format!(
            "The working directory {} does not exist yet; create it or upload your app first",
            dir.display()
        ));
    }
    let sfs = SiteFs::new(home, &site.system_user)?;
    let rel = sfs.rel(&path);
    if rel.is_empty() {
        return Err("The working directory must be inside the site's home".into());
    }
    // Before anything looks at the file, in case a folder on the way is a link out of the home.
    sfs.resolve(&rel)?;
    match fs::symlink_metadata(&path) {
        Ok(m) if !m.file_type().is_file() => return Err(".env must be a regular file, not a link or folder".into()),
        Ok(_) => {}
        Err(_) => {
            sfs.create_file(&rel)?;
            sfs.chmod(&rel, 0o640)?;
        }
    }
    let mut text = content.replace("\r\n", "\n");
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    sfs.write_text(&rel, &text)
}

/// What the Application tab shows in its environment box.
#[derive(Debug, Serialize)]
pub struct EnvView {
    pub path: Option<String>,
    pub exists: bool,
    pub content: String,
    /// Keys only in the panel's database, included in `content` so saving moves them to the file.
    pub imported_keys: Vec<String>,
    pub warnings: Vec<String>,
    /// The file's PORT, when it disagrees with the site's app port (which wins).
    pub port_conflict: Option<String>,
}

pub fn view(site: &Site) -> Result<EnvView, String> {
    let file = read_site(site)?;
    let exists = file.is_some();
    let mut content = file.unwrap_or_default();
    let parsed = parse(&content);
    let imported: Vec<(String, String)> = site
        .env_map()
        .into_iter()
        .filter(|(k, _)| !parsed.vars.contains_key(k))
        .collect();
    if !imported.is_empty() {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        for (k, v) in &imported {
            content.push_str(&format!("{k}={}\n", quote_value(v)));
        }
    }
    let port_conflict = match (parsed.vars.get("PORT"), site.target_port) {
        (Some(p), Some(t)) if p.trim() != t.to_string() => Some(p.clone()),
        _ => None,
    };
    Ok(EnvView {
        path: path_for(site).map(|p| p.to_string_lossy().into_owned()),
        exists,
        content,
        imported_keys: imported.into_iter().map(|(k, _)| k).collect(),
        warnings: parsed.warnings,
        port_conflict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_forms() {
        let p = parse(
            "# comment\r\n\nA=1\nexport B=two\nC=\"x y\" # note\nD='single $raw'\nE=plain # gone\nF=a#b\nG=\nH=\"l1\\nl2\"\n",
        );
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        assert_eq!(p.vars["A"], "1");
        assert_eq!(p.vars["B"], "two");
        assert_eq!(p.vars["C"], "x y");
        assert_eq!(p.vars["D"], "single $raw");
        assert_eq!(p.vars["E"], "plain");
        assert_eq!(p.vars["F"], "a#b");
        assert_eq!(p.vars["G"], "");
        assert_eq!(p.vars["H"], "l1\nl2");
    }

    #[test]
    fn multiline_quotes_and_last_wins() {
        let p = parse("KEY=\"-----BEGIN\nabc\n-----END\"\nA=1\nA=2\n");
        assert_eq!(p.vars["KEY"], "-----BEGIN\nabc\n-----END");
        assert_eq!(p.vars["A"], "2");
    }

    #[test]
    fn bad_lines_are_warnings_with_line_numbers() {
        let p = parse("good=1\nnot a pair\n1BAD=x\nOPEN=\"never closed\nLATER=2\n");
        assert_eq!(p.vars["good"], "1");
        assert_eq!(p.vars["LATER"], "2");
        assert_eq!(p.vars["OPEN"], "\"never closed");
        assert_eq!(p.warnings.len(), 3);
        assert!(p.warnings[0].starts_with("Line 2"));
        assert!(p.warnings[1].starts_with("Line 3"));
        assert!(p.warnings[2].starts_with("Line 4"));
    }

    #[test]
    fn quoting_round_trips() {
        for v in ["plain", "with space", "a\"b$c`d\\e", "line1\nline2", "", "#hash"] {
            let text = format!("K={}\n", quote_value(v));
            assert_eq!(parse(&text).vars["K"], v, "{text}");
        }
    }
}
