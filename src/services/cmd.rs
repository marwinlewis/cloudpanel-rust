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

fn build(program: &str, args: &[&str], opts: &CmdOpts) -> Command {
    // Switching user with `runuser` fails inside the panel's systemd sandbox
    // ("runuser: cannot set user id: Operation not permitted"), so when systemd is
    // available let PID 1 start the command as the target user in a transient unit.
    if let Some(user) = &opts.as_user {
        if cfg!(unix) && which("systemd-run") {
            let mut c = Command::new("systemd-run");
            c.args(["--wait", "--pipe", "--collect", "--quiet", "--service-type=exec"]);
            c.arg(format!("--uid={user}"));
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
    if cfg!(unix) && which("systemd-run") {
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
        return run_with("systemd-run", &full, &inner);
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

    #[test]
    fn tail_respects_boundaries() {
        assert_eq!(tail("hello", 10), "hello");
        assert_eq!(tail("hello", 3), "llo");
        assert_eq!(tail("héllo", 4), "llo");
    }
}
