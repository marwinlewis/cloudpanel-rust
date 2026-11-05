use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Result of running a system tool. `Missing` means the binary isn't installed (e.g. local dev).
pub enum CmdOutcome {
    Ok(String),
    Failed(String),
    Missing,
}

/// Run `program` with arguments passed directly to `execve` (never through a shell).
pub fn run(program: &str, args: &[&str]) -> CmdOutcome {
    run_with(program, args, &CmdOpts::default()).outcome(program)
}

/// Options for [`run_with`].
#[derive(Default, Clone)]
pub struct CmdOpts {
    pub stdin: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    pub env: Vec<(String, String)>,
    /// Run as this (already validated) local user via `runuser`.
    pub as_user: Option<String>,
    pub cwd: Option<PathBuf>,
    /// Feed this file to stdin (takes precedence over `stdin`).
    pub stdin_file: Option<PathBuf>,
}

impl CmdOpts {
    pub fn stdin_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.stdin_file = Some(path.into());
        self
    }
    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout = Some(Duration::from_secs(secs));
        self
    }
    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }
    pub fn user(mut self, user: &str) -> Self {
        self.as_user = Some(user.into());
        self
    }
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }
}

pub struct CmdResult {
    /// None when the binary is missing.
    pub code: Option<i32>,
    pub missing: bool,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CmdResult {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }

    pub fn outcome(self, program: &str) -> CmdOutcome {
        if self.missing {
            return CmdOutcome::Missing;
        }
        if self.success() {
            return CmdOutcome::Ok(self.stdout);
        }
        let mut msg = self.stderr.trim().to_string();
        if msg.is_empty() {
            msg = self.stdout.trim().to_string();
        }
        if self.timed_out {
            msg = format!("{program} timed out. {msg}");
        } else if msg.is_empty() {
            msg = format!("{program} exited with code {}", self.code.unwrap_or(-1));
        }
        CmdOutcome::Failed(msg)
    }

    /// Ok(stdout) or Err(message); a missing binary is an error with `missing_msg`.
    pub fn into_result(self, program: &str, missing_msg: &str) -> Result<String, String> {
        match self.outcome(program) {
            CmdOutcome::Ok(s) => Ok(s),
            CmdOutcome::Failed(e) => Err(e),
            CmdOutcome::Missing => Err(missing_msg.to_string()),
        }
    }

    /// Combined stdout + stderr.
    pub fn combined(&self) -> String {
        let mut s = self.stdout.clone();
        if !self.stderr.is_empty() {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&self.stderr);
        }
        s
    }
}

/// Locate `systemd-run`. The panel's own PATH can be minimal (or overridden by its env
/// file), so the standard locations are checked directly as well.
pub fn systemd_run() -> Option<PathBuf> {
    if !cfg!(unix) {
        return None;
    }
    if let Some(path) = std::env::var_os("PATH") {
        if let Some(p) = std::env::split_paths(&path)
            .map(|d| d.join("systemd-run"))
            .find(|p| p.is_file())
        {
            return Some(p);
        }
    }
    ["/usr/bin/systemd-run", "/bin/systemd-run", "/usr/local/bin/systemd-run"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

fn build(program: &str, args: &[&str], opts: &CmdOpts) -> Command {
    build_with(program, args, opts, systemd_run())
}

fn build_with(program: &str, args: &[&str], opts: &CmdOpts, systemd_run: Option<PathBuf>) -> Command {
    // Switching user with `runuser` fails inside the panel's systemd sandbox
    // (NoNewPrivileges/RestrictSUIDSGID: "runuser: cannot set user id: Operation not
    // permitted"), so when systemd is available let PID 1 start the command as the
    // target user in a transient unit.
    if let Some(user) = &opts.as_user {
        if let Some(sr) = systemd_run {
            let mut c = Command::new(sr);
            c.args(["--wait", "--pipe", "--collect", "--quiet", "--service-type=exec"]);
            c.arg(format!("--uid={user}"));
            if let Some(t) = opts.timeout {
                // Killing the systemd-run client on timeout doesn't stop the unit.
                c.arg(format!("--property=RuntimeMaxSec={}", t.as_secs().max(1)));
            }
            c.arg("--setenv=LC_ALL=C");
            if let Ok(path) = std::env::var("PATH") {
                c.arg(format!("--setenv=PATH={path}"));
            }
            for (k, v) in &opts.env {
                c.arg(format!("--setenv={k}={v}"));
            }
            if let Some(dir) = &opts.cwd {
                c.arg(format!("--working-directory={}", dir.display()));
            }
            c.arg("--").arg(program).args(args);
            c.env("LC_ALL", "C");
            return c;
        }
    }
    let mut cmd = match &opts.as_user {
        Some(user) => {
            let mut c = Command::new("runuser");
            c.args(["-u", user, "--", program]);
            c
        }
        None => Command::new(program),
    };
    cmd.args(args).env("LC_ALL", "C");
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    if let Some(dir) = &opts.cwd {
        cmd.current_dir(dir);
    }
    cmd
}

/// Run a program with stdin, timeout, extra env and optional user switch.
pub fn run_with(program: &str, args: &[&str], opts: &CmdOpts) -> CmdResult {
    let mut out = String::new();
    let mut err = String::new();
    let res = run_streaming(program, args, opts, &mut |line, is_err| {
        let buf = if is_err { &mut err } else { &mut out };
        buf.push_str(line);
        buf.push('\n');
    });
    CmdResult {
        stdout: out,
        stderr: err,
        ..res
    }
}

/// Like [`run_with`] but calls `on_line(line, is_stderr)` for each line as it arrives.
/// The returned result has empty stdout/stderr.
pub fn run_streaming(program: &str, args: &[&str], opts: &CmdOpts, on_line: &mut dyn FnMut(&str, bool)) -> CmdResult {
    let empty = |code, missing, timed_out| CmdResult {
        code,
        missing,
        timed_out,
        stdout: String::new(),
        stderr: String::new(),
    };
    let mut cmd = build(program, args, opts);
    let stdin = match (&opts.stdin_file, &opts.stdin) {
        (Some(path), _) => match std::fs::File::open(path) {
            Ok(f) => Stdio::from(f),
            Err(e) => {
                on_line(&format!("cannot open {}: {e}", path.display()), true);
                return empty(Some(-1), false, false);
            }
        },
        (None, Some(_)) => Stdio::piped(),
        (None, None) => Stdio::null(),
    };
    cmd.stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return empty(None, true, false),
        Err(e) => {
            on_line(&format!("failed to run {program}: {e}"), true);
            return empty(Some(-1), false, false);
        }
    };

    if let (Some(data), Some(mut stdin)) = (opts.stdin.clone(), child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }

    let (tx, rx) = mpsc::channel::<(String, bool)>();
    let mut readers = Vec::new();
    for (stream, is_err) in [
        (child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>), false),
        (child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>), true),
    ] {
        if let Some(s) = stream {
            let tx = tx.clone();
            readers.push(std::thread::spawn(move || {
                let mut reader = BufReader::new(s);
                let mut buf = Vec::new();
                loop {
                    buf.clear();
                    match reader.read_until(b'\n', &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let line = String::from_utf8_lossy(&buf);
                            let _ = tx.send((line.trim_end_matches(['\n', '\r']).to_string(), is_err));
                        }
                    }
                }
            }));
        }
    }
    drop(tx);

    let deadline = opts.timeout.map(|t| Instant::now() + t);
    let mut timed_out = false;
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((line, is_err)) => on_line(&line, is_err),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if let Some(d) = deadline {
            if Instant::now() > d {
                timed_out = true;
                let _ = child.kill();
                break;
            }
        }
    }
    for r in readers {
        let _ = r.join();
    }
    while let Ok((line, is_err)) = rx.try_recv() {
        on_line(&line, is_err);
    }
    let code = child.wait().ok().and_then(|s| s.code()).or(Some(-1));
    empty(code, false, timed_out)
}

/// Run a command outside the panel's systemd sandbox (for tools that rewrite files under
/// `/etc` or `/usr`, like `useradd` or `apt-get`). Falls back to a direct call when
/// `systemd-run` is unavailable (development).
pub fn run_host(program: &str, args: &[&str], opts: &CmdOpts) -> CmdResult {
    if let Some(sr) = systemd_run() {
        let sr = sr.to_string_lossy().into_owned();
        let mut full: Vec<&str> = vec!["--wait", "--pipe", "--collect", "--quiet", "--service-type=exec"];
        let envs: Vec<String> = opts.env.iter().map(|(k, v)| format!("--setenv={k}={v}")).collect();
        full.extend(envs.iter().map(String::as_str));
        let user_arg;
        if let Some(u) = &opts.as_user {
            user_arg = format!("--uid={u}");
            full.push(&user_arg);
        }
        let cwd_arg;
        if let Some(c) = &opts.cwd {
            cwd_arg = format!("--working-directory={}", c.display());
            full.push(&cwd_arg);
        }
        full.push("--");
        full.push(program);
        full.extend_from_slice(args);
        let inner = CmdOpts {
            stdin: opts.stdin.clone(),
            stdin_file: opts.stdin_file.clone(),
            timeout: opts.timeout,
            ..Default::default()
        };
        return run_with(&sr, &full, &inner);
    }
    run_with(program, args, opts)
}

/// Is `program` on PATH?
pub fn which(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let p = dir.join(program);
        p.is_file() || (cfg!(windows) && dir.join(format!("{program}.exe")).is_file())
    })
}

/// Last `max` bytes of `s` on a char boundary.
pub fn tail(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary() {
        let r = run_with("definitely-not-a-real-binary-xyz", &[], &CmdOpts::default());
        assert!(r.missing);
        assert!(matches!(r.outcome("x"), CmdOutcome::Missing));
    }

    fn argv(c: &Command) -> (String, Vec<String>) {
        (
            c.get_program().to_string_lossy().into_owned(),
            c.get_args().map(|a| a.to_string_lossy().into_owned()).collect(),
        )
    }

    /// Regression: commands run as a site user (e.g. `npm install`) must go through
    /// systemd-run, because `runuser` cannot switch users inside the panel's sandbox.
    #[test]
    fn user_commands_use_systemd_run_when_available() {
        let opts = CmdOpts::default()
            .user("shop")
            .cwd("/home/shop/app")
            .env("HOME", "/home/shop")
            .timeout(1200);
        let (prog, args) = argv(&build_with(
            "npm",
            &["install", "--no-audit"],
            &opts,
            Some(PathBuf::from("/usr/bin/systemd-run")),
        ));
        assert_eq!(prog, "/usr/bin/systemd-run");
        assert!(!args.iter().any(|a| a == "runuser"));
        assert!(args.contains(&"--uid=shop".to_string()));
        assert!(args.contains(&"--wait".to_string()));
        assert!(args.contains(&"--pipe".to_string()));
        assert!(args.contains(&"--setenv=HOME=/home/shop".to_string()));
        assert!(args.contains(&"--property=RuntimeMaxSec=1200".to_string()));
        assert!(args.contains(&"--working-directory=/home/shop/app".to_string()));
        let sep = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(&args[sep + 1..], ["npm", "install", "--no-audit"]);
    }

    #[test]
    fn runuser_is_only_a_fallback_without_systemd() {
        let opts = CmdOpts::default().user("shop");
        let (prog, args) = argv(&build_with("npm", &["ci"], &opts, None));
        assert_eq!(prog, "runuser");
        assert_eq!(args, ["-u", "shop", "--", "npm", "ci"]);
        // No user switch requested: run the program directly.
        let (prog, args) = argv(&build_with(
            "npm",
            &["ci"],
            &CmdOpts::default(),
            Some(PathBuf::from("/usr/bin/systemd-run")),
        ));
        assert_eq!(prog, "npm");
        assert_eq!(args, ["ci"]);
    }

    #[test]
    fn tail_respects_boundaries() {
        assert_eq!(tail("hello", 10), "hello");
        assert_eq!(tail("hello", 3), "llo");
        assert_eq!(tail("héllo", 4), "llo");
    }
}
