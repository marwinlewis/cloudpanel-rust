//! Strict validation for every value that ends up in a config file, a file path
//! or a command-line argument. Values are checked against allow-lists so nothing
//! can inject nginx directives, traverse paths or smuggle CLI flags.

use std::path::{Component, Path, PathBuf};

pub type VResult<T> = Result<T, String>;

/// Normalize and validate a DNS hostname (RFC 1123, ASCII only).
pub fn domain(input: &str) -> VResult<String> {
    let d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 {
        return Err("Domain must be between 1 and 253 characters".into());
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return Err("Domain must contain at least one dot (e.g. example.com)".into());
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err("Each domain label must be 1-63 characters".into());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("Domain may only contain letters, digits, hyphens and dots".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain labels cannot start or end with a hyphen".into());
        }
    }
    if labels.last().is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit())) {
        return Err("Top-level domain cannot be numeric".into());
    }
    Ok(d)
}

pub fn email(input: &str) -> VResult<String> {
    let e = input.trim();
    let invalid = || Err("Invalid email address".to_string());
    if e.len() > 254 || e.starts_with('-') {
        return invalid();
    }
    let Some((local, host)) = e.split_once('@') else {
        return invalid();
    };
    if local.is_empty() || local.len() > 64 || !local.chars().all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
    {
        return invalid();
    }
    domain(host).map_err(|_| "Invalid email domain".to_string())?;
    Ok(e.to_string())
}

/// Linux account name (as accepted by useradd's default NAME_REGEX).
pub fn system_user(input: &str) -> VResult<String> {
    let u = input.trim();
    let mut chars = u.chars();
    let ok_first = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    let ok_rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ok_first || !ok_rest || u.len() > 32 {
        return Err("Invalid system user name".into());
    }
    Ok(u.to_string())
}

/// Panel login name.
pub fn username(input: &str) -> VResult<String> {
    let u = input.trim();
    if u.len() < 3
        || u.len() > 32
        || !u
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err("Username must be 3-32 characters: letters, digits, '.', '_' or '-'".into());
    }
    Ok(u.to_string())
}

pub fn password(input: &str) -> VResult<()> {
    let n = input.chars().count();
    if n < 10 {
        return Err("Password must be at least 10 characters".into());
    }
    if n > 128 {
        return Err("Password must be at most 128 characters".into());
    }
    Ok(())
}

/// Docker container id or name.
pub fn container_id(input: &str) -> VResult<String> {
    let mut chars = input.chars();
    let ok_first = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let ok_rest = chars.all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if !ok_first || !ok_rest || input.len() > 128 {
        return Err("Invalid container id".into());
    }
    Ok(input.to_string())
}

pub fn port(p: Option<u16>) -> VResult<u16> {
    match p {
        Some(p) if p > 0 => Ok(p),
        _ => Err("A valid port (1-65535) is required".into()),
    }
}

/// Lexically normalize an absolute path (resolving `.` and rejecting `..`) and make sure
/// it lives inside `base`. Only conservative characters are allowed so the value is safe
/// to embed in an nginx config.
pub fn path_within(input: &str, base: &Path) -> VResult<PathBuf> {
    let s = input.trim();
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c) || (cfg!(windows) && "\\:".contains(c)))
    {
        return Err("Path contains unsupported characters".into());
    }
    let p = Path::new(s);
    if !p.is_absolute() {
        return Err("Path must be absolute".into());
    }
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => return Err("Path must not contain '..'".into()),
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    let base = absolute(base);
    if !out.starts_with(&base) || out == base {
        return Err(format!("Path must be inside {}", base.display()));
    }
    Ok(out)
}

/// Absolute version of `p` without requiring it to exist.
pub fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    let joined = std::env::current_dir().unwrap_or_default().join(p);
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

const CRON_MACROS: &[&str] = &[
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@midnight",
    "@hourly",
];

/// Validate a cron schedule: either a macro or five fields of `*`, numbers, ranges,
/// steps, lists and month/day names.
pub fn cron_schedule(input: &str) -> VResult<String> {
    let s = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if CRON_MACROS.contains(&s.as_str()) {
        return Ok(s);
    }
    let fields: Vec<&str> = s.split(' ').collect();
    if fields.len() != 5 {
        return Err("Schedule must have 5 fields (minute hour day month weekday) or be a macro like @daily".into());
    }
    let limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];
    for (field, (min, max)) in fields.iter().zip(limits) {
        for item in field.split(',') {
            let (range, step) = match item.split_once('/') {
                Some((r, st)) => (r, Some(st)),
                None => (item, None),
            };
            if let Some(st) = step {
                match st.parse::<u32>() {
                    Ok(n) if n >= 1 && n <= max => {}
                    _ => return Err(format!("Invalid step in '{}'", item)),
                }
            }
            if range == "*" {
                continue;
            }
            let bounds: Vec<&str> = range.split('-').collect();
            if bounds.is_empty() || bounds.len() > 2 {
                return Err(format!("Invalid cron field '{}'", item));
            }
            for b in bounds {
                let ok = match b.parse::<u32>() {
                    Ok(n) => n >= min && n <= max,
                    Err(_) => b.len() == 3 && b.chars().all(|c| c.is_ascii_alphabetic()),
                };
                if !ok {
                    return Err(format!("Invalid cron value '{}'", b));
                }
            }
        }
    }
    Ok(s)
}

pub fn cron_command(input: &str) -> VResult<String> {
    let c = input.trim();
    if c.is_empty() || c.len() > 1000 {
        return Err("Command must be between 1 and 1000 characters".into());
    }
    if c.chars().any(|ch| ch == '\n' || ch == '\r' || ch == '\0') {
        return Err("Command must be a single line".into());
    }
    Ok(c.to_string())
}

pub fn short_text(input: Option<&str>, max: usize) -> VResult<Option<String>> {
    match input.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) if s.chars().count() > max => Err(format!("Text must be at most {} characters", max)),
        Some(s) if s.chars().any(|c| c.is_control()) => Err("Text contains control characters".into()),
        Some(s) => Ok(Some(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(domain(" Example.COM. ").unwrap(), "example.com");
        assert!(domain("api.sub.example.co.uk").is_ok());
        for bad in [
            "",
            "localhost",
            "a.com;\n}",
            "a.com {",
            "../etc/passwd",
            "-x.com",
            "x-.com",
            "a..com",
            "exa mple.com",
            "ex\u{e4}mple.com",
            "1.2.3.4",
            "a.com/../../x",
        ] {
            assert!(domain(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn emails() {
        assert!(email("ops@example.com").is_ok());
        assert!(email("-m@example.com").is_err());
        assert!(email("a b@example.com").is_err());
        assert!(email("nobody").is_err());
    }

    #[test]
    fn containers() {
        assert!(container_id("3f2a9c1b").is_ok());
        assert!(container_id("my_app-1.web").is_ok());
        assert!(container_id("--help").is_err());
        assert!(container_id("a;rm").is_err());
        assert!(container_id("").is_err());
    }

    #[test]
    fn cron() {
        assert!(cron_schedule("*/5 * * * *").is_ok());
        assert!(cron_schedule("0 3 * * MON-FRI").is_ok());
        assert!(cron_schedule("@daily").is_ok());
        assert!(cron_schedule("1,15,30 0-6 1 1-12/2 0").is_ok());
        assert!(cron_schedule("60 * * * *").is_err());
        assert!(cron_schedule("* * * *").is_err());
        assert!(cron_schedule("* * * * * root").is_err());
        assert!(cron_schedule("* * * * $(id)").is_err());
        assert!(cron_command("echo hi\nroot evil").is_err());
        assert!(cron_command("/usr/bin/php artisan schedule:run").is_ok());
    }

    #[test]
    fn users() {
        assert!(system_user("www-data").is_ok());
        assert!(system_user("Root").is_err());
        assert!(system_user("-x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn paths() {
        let base = Path::new("/var/www");
        assert_eq!(
            path_within("/var/www/a.com/public", base).unwrap(),
            PathBuf::from("/var/www/a.com/public")
        );
        assert!(path_within("/var/www/../etc", base).is_err());
        assert!(path_within("/etc", base).is_err());
        assert!(path_within("/var/www", base).is_err());
        assert!(path_within("/var/www/a;b", base).is_err());
        assert!(path_within("relative/x", base).is_err());
    }
}
