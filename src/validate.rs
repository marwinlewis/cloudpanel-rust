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

/// Environment variable name for app units.
pub fn env_key(input: &str) -> VResult<String> {
    let k = input.trim();
    let mut chars = k.chars();
    let ok_first = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if !ok_first || k.len() > 64 || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("Invalid environment variable name '{k}'"));
    }
    Ok(k.to_string())
}

pub fn env_value(input: &str) -> VResult<String> {
    if input.len() > 4096 || input.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
        return Err("Environment values must be single-line and at most 4096 bytes".into());
    }
    Ok(input.to_string())
}

/// Command line for an app unit (run by `/bin/sh -c` as the site user).
pub fn app_command(input: &str) -> VResult<String> {
    let c = input.trim();
    if c.is_empty() || c.len() > 1000 {
        return Err("Start command must be between 1 and 1000 characters".into());
    }
    if c.chars().any(|ch| ch == '\n' || ch == '\r' || ch == '\0') {
        return Err("Start command must be a single line".into());
    }
    Ok(c.to_string())
}

const SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Validate an OpenSSH public key line. Returns the normalized key and its SHA256 fingerprint.
/// Options prefixes (`command="..."` etc.) are rejected.
pub fn ssh_public_key(input: &str) -> VResult<(String, String)> {
    use base64::Engine;
    use sha2::Digest;
    let line = input.trim();
    if line.len() > 16 * 1024 || line.contains(['\n', '\r', '\0']) {
        return Err("Paste a single public key line".into());
    }
    let mut parts = line.split_whitespace();
    let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else {
        return Err("Public key must look like 'ssh-ed25519 AAAA... comment'".into());
    };
    if !SSH_KEY_TYPES.contains(&kind) {
        return Err("Unsupported key type (use ed25519, RSA or ECDSA)".into());
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "Public key data is not valid base64".to_string())?;
    // The blob starts with a length-prefixed copy of the key type.
    let inner_ok = blob.len() > 4 && {
        let n = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        blob.len() >= 4 + n && &blob[4..4 + n] == kind.as_bytes()
    };
    if !inner_ok {
        return Err("Public key data does not match its type".into());
    }
    let comment: String = parts.collect::<Vec<_>>().join(" ");
    if comment.chars().count() > 120 || comment.chars().any(|c| c.is_control()) {
        return Err("Key comment is too long or has control characters".into());
    }
    let fp = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(&blob))
    );
    let normalized = if comment.is_empty() {
        format!("{kind} {b64}")
    } else {
        format!("{kind} {b64} {comment}")
    };
    Ok((normalized, fp))
}

/// IPv4/IPv6 address with optional prefix length.
pub fn cidr(input: &str) -> VResult<String> {
    let s = input.trim();
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let ip: std::net::IpAddr = addr.parse().map_err(|_| format!("'{s}' is not a valid IP address"))?;
    if let Some(p) = prefix {
        let max = if ip.is_ipv4() { 32 } else { 128 };
        match p.parse::<u8>() {
            Ok(n) if n <= max => {}
            _ => return Err(format!("'{s}' has an invalid prefix length")),
        }
    }
    Ok(match prefix {
        Some(p) => format!("{ip}/{p}"),
        None => ip.to_string(),
    })
}

/// A single path component (file or directory name).
pub fn file_name(input: &str) -> VResult<String> {
    let n = input.trim();
    if n.is_empty() || n.len() > 255 || n == "." || n == ".." {
        return Err("Invalid file name".into());
    }
    if n.contains(['/', '\\', '\0']) || n.chars().any(|c| c.is_control()) {
        return Err("File names cannot contain slashes or control characters".into());
    }
    Ok(n.to_string())
}

/// Extra nginx directives placed inside a site's `server {}` block. `nginx -t` with
/// rollback is the real safety net; this rejects the obviously dangerous cases.
pub fn nginx_directives(input: &str) -> VResult<String> {
    let s = input.replace("\r\n", "\n");
    if s.len() > 16 * 1024 {
        return Err("Custom directives must be at most 16 KB".into());
    }
    if s.contains('\0') {
        return Err("Custom directives contain a NUL byte".into());
    }
    let mut depth: i32 = 0;
    for c in s.chars() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return Err("Unbalanced '}' would close the server block".into());
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("Unbalanced braces in custom directives".into());
    }
    for line in s.lines() {
        let t = line.trim_start();
        let word = t.split(|c: char| c.is_whitespace() || c == ';').next().unwrap_or("");
        match word {
            "load_module" | "server" | "http" | "events" | "stream" => {
                return Err(format!("'{word}' is not allowed in custom directives"))
            }
            "include" => {
                let target = t["include".len()..].trim().trim_end_matches(';').trim();
                if !target.starts_with("/etc/nginx/") || target.contains("..") {
                    return Err("include is only allowed for files under /etc/nginx/".into());
                }
            }
            _ => {}
        }
    }
    Ok(s.trim_end().to_string())
}

/// Derive a Linux user name for a site from its domain, e.g. `app.example.com` -> `app-example`.
pub fn site_user_from_domain(domain: &str) -> String {
    let labels: Vec<&str> = domain.split('.').collect();
    let base = if labels.len() > 2 {
        labels[..labels.len() - 1].join("-")
    } else {
        labels[0].to_string()
    };
    let mut u: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if !u.starts_with(|c: char| c.is_ascii_lowercase()) {
        u = format!("s{u}");
    }
    u.truncate(28);
    u.trim_end_matches('-').to_string()
}

/// Octal file mode such as `755` or `0644`.
pub fn file_mode(input: &str) -> VResult<u32> {
    let s = input.trim();
    if s.is_empty() || s.len() > 4 || !s.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err("Mode must be octal, e.g. 644 or 755".into());
    }
    u32::from_str_radix(s, 8).map_err(|_| "Invalid mode".to_string())
}

/// Database / database-user identifier: `^[a-z][a-z0-9_]{0,31}$`.
pub fn db_identifier(input: &str) -> VResult<String> {
    let s = input.trim();
    let mut chars = s.chars();
    let ok_first = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    if !ok_first || s.len() > 32 || !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err("Use 1-32 lowercase letters, digits or '_', starting with a letter".into());
    }
    Ok(s.to_string())
}

/// systemd unit name from the managed allow-list or a CloudPanel app unit.
pub fn service_name(input: &str) -> VResult<String> {
    let s = input.trim().trim_end_matches(".service");
    const ALLOWED: &[&str] = &[
        "nginx",
        "ssh",
        "sshd",
        "cron",
        "fail2ban",
        "docker",
        "mariadb",
        "mysql",
        "mongod",
        "ufw",
        "certbot.timer",
    ];
    let is_app = s.strip_prefix("cloudpanel-app-").is_some_and(|rest| {
        !rest.is_empty()
            && rest.len() <= 64
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    });
    if ALLOWED.contains(&s) || is_app {
        Ok(s.to_string())
    } else {
        Err(format!("'{s}' is not a managed service"))
    }
}

/// Docker image reference such as `nginx:1.27`, `ghcr.io/org/app@sha256:...`.
pub fn image_ref(input: &str) -> VResult<String> {
    let s = input.trim();
    let ok_first = s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    if !ok_first || s.len() > 255 || !s.chars().all(|c| c.is_ascii_alphanumeric() || "._-/:@".contains(c)) {
        return Err("Invalid image reference".into());
    }
    Ok(s.to_string())
}

/// Port or `start:end` range. Returns (start, Some(end)) for ranges.
pub fn port_range(input: &str) -> VResult<(u16, Option<u16>)> {
    let s = input.trim();
    let parse = |p: &str| -> VResult<u16> {
        match p.trim().parse::<u16>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(format!("'{p}' is not a valid port")),
        }
    };
    match s.split_once([':', '-']) {
        Some((a, b)) => {
            let (a, b) = (parse(a)?, parse(b)?);
            if a >= b {
                return Err("Port range start must be lower than its end".into());
            }
            Ok((a, Some(b)))
        }
        None => Ok((parse(s)?, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_keys() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@laptop";
        let (norm, fp) = ssh_public_key(key).unwrap();
        assert!(norm.ends_with("me@laptop"));
        assert!(fp.starts_with("SHA256:"));
        assert!(ssh_public_key("command=\"rm -rf /\" ssh-ed25519 AAAA").is_err());
        assert!(
            ssh_public_key("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl").is_err()
        );
        assert!(ssh_public_key("ssh-ed25519 !!!").is_err());
    }

    #[test]
    fn cidrs_and_names() {
        assert_eq!(cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(cidr("2001:db8::1").unwrap(), "2001:db8::1");
        assert!(cidr("10.0.0.0/33").is_err());
        assert!(cidr("10.0.0.1; deny").is_err());
        assert!(file_name("..").is_err());
        assert!(file_name("a/b").is_err());
        assert!(file_name("index.html").is_ok());
        assert_eq!(site_user_from_domain("app.example.com"), "app-example");
        assert_eq!(site_user_from_domain("example.com"), "example");
        assert_eq!(site_user_from_domain("1x.io"), "s1x");
        assert_eq!(file_mode("755").unwrap(), 0o755);
        assert!(file_mode("999").is_err());
    }

    #[test]
    fn directives_and_env() {
        assert!(nginx_directives("location /api { proxy_pass http://127.0.0.1:9000; }").is_ok());
        assert!(nginx_directives("} server { listen 81;").is_err());
        assert!(nginx_directives("include /etc/passwd;").is_err());
        assert!(nginx_directives("include /etc/nginx/snippets/x.conf;").is_ok());
        assert!(nginx_directives("load_module x.so;").is_err());
        assert!(env_key("NODE_ENV").is_ok());
        assert!(env_key("1BAD").is_err());
        assert!(env_value("a\nb").is_err());
    }

    #[test]
    fn identifiers() {
        assert!(db_identifier("shop_db").is_ok());
        assert!(db_identifier("Shop").is_err());
        assert!(db_identifier("x`; DROP").is_err());
        assert!(service_name("nginx").is_ok());
        assert!(service_name("cloudpanel-app-shop-example").is_ok());
        assert!(service_name("sshd; reboot").is_err());
        assert!(service_name("systemd-journald").is_err());
        assert!(image_ref("ghcr.io/org/app:1.2@sha256:abc").is_ok());
        assert!(image_ref("--privileged").is_err());
        assert_eq!(port_range("6000:6010").unwrap(), (6000, Some(6010)));
        assert_eq!(port_range("80").unwrap(), (80, None));
        assert!(port_range("10:5").is_err());
    }

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
