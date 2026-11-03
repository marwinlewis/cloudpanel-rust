use std::process::Command;

/// Result of running a system tool. `Missing` means the binary isn't installed (e.g. local dev).
pub enum CmdOutcome {
    Ok(String),
    Failed(String),
    Missing,
}

/// Run `program` with arguments passed directly to `execve` (never through a shell).
pub fn run(program: &str, args: &[&str]) -> CmdOutcome {
    match Command::new(program).args(args).env("LC_ALL", "C").output() {
        Ok(out) if out.status.success() => CmdOutcome::Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        Ok(out) => {
            let mut msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if msg.is_empty() {
                msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
            if msg.is_empty() {
                msg = format!("{program} exited with {}", out.status);
            }
            CmdOutcome::Failed(msg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CmdOutcome::Missing,
        Err(e) => CmdOutcome::Failed(format!("failed to run {program}: {e}")),
    }
}
