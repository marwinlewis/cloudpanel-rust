use super::cmd::{run_with, CmdOpts};
use crate::config::Config;
use crate::db::{self, models::CronJob};
use crate::fsutil::write_atomic;
use rusqlite::Connection;
use std::path::Path;
use std::time::Instant;
use tracing::info;

pub struct CronService;

const OUTPUT_CAP: usize = 64 * 1024;

/// Path of the panel binary used in generated cron lines.
fn self_bin() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| p.starts_with('/') && !p.contains(char::is_whitespace))
        .unwrap_or_else(|| "/usr/local/bin/cloudpanel".into())
}

impl CronService {
    /// Render `/etc/cron.d/cloudpanel`. Each job runs through `cloudpanel cron-run <id>` as
    /// root, which loads the command from the database, switches to the job's user and
    /// records the exit code and output.
    pub fn render(config: &Config, jobs: &[CronJob]) -> String {
        let db = crate::validate::absolute(&config.db_path);
        let data = crate::validate::absolute(&config.data_dir);
        Self::render_with(jobs, &self_bin(), &db.to_string_lossy(), &data.to_string_lossy())
    }

    pub fn render_with(jobs: &[CronJob], bin: &str, db_path: &str, data_dir: &str) -> String {
        let mut out = String::from(
            "# Managed by CloudPanel - do not edit, changes will be overwritten\n\
             SHELL=/bin/sh\n\
             PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
        );
        // cron does not load the service environment; tell cron-run where the database is.
        if !db_path.contains(char::is_whitespace) && !data_dir.contains(char::is_whitespace) {
            out.push_str(&format!(
                "CLOUDPANEL_DATA_DIR={data_dir}\nCLOUDPANEL_DB_PATH={db_path}\n"
            ));
        }
        out.push('\n');
        for job in jobs.iter().filter(|j| j.is_active) {
            out.push_str(&format!(
                "# job {}: {}\n",
                job.id,
                job.name.as_deref().unwrap_or("").replace('\n', " ")
            ));
            out.push_str(&format!(
                "{} root {bin} cron-run {} >/dev/null 2>&1\n",
                job.schedule, job.id
            ));
        }
        out
    }

    pub fn apply(config: &Config, jobs: &[CronJob]) -> Result<(), String> {
        let cron_file: &Path = &config.cron_file;
        write_atomic(cron_file, Self::render(config, jobs).as_bytes(), 0o644)
            .map_err(|e| format!("Failed to write {}: {e}", cron_file.display()))?;
        info!("Wrote {} cron job(s) to {}", jobs.len(), cron_file.display());
        Ok(())
    }

    /// Check that a local account exists (so cron doesn't silently ignore the line).
    pub fn user_exists(user: &str) -> bool {
        if cfg!(windows) {
            return true;
        }
        super::sysusers::user_exists(user)
    }
}

/// Execute a job now and record the run. Returns the exit code.
pub fn execute(conn: &Connection, job: &CronJob, timeout_secs: Option<u64>) -> (i32, String) {
    let started = chrono::Utc::now();
    let t = Instant::now();
    let mut opts = CmdOpts::default().env("CLOUDPANEL_CRON_JOB", &job.id.to_string());
    if let Some(s) = timeout_secs {
        opts = opts.timeout(s);
    }
    if job.user != "root" && cfg!(unix) {
        opts = opts.user(&job.user);
        if let Some(home) = home_of(&job.user) {
            opts = opts.cwd(&home).env("HOME", &home);
        }
    }
    let shell = if cfg!(windows) { "sh" } else { "/bin/sh" };
    let r = run_with(shell, &["-c", &job.command], &opts);
    let mut output = r.combined();
    if r.missing {
        output = "/bin/sh is not available".into();
    }
    if r.timed_out {
        output.push_str("\n[killed: timed out]");
    }
    let output = super::cmd::tail(&output, OUTPUT_CAP).to_string();
    let code = if r.missing { 127 } else { r.code.unwrap_or(-1) };
    let _ = db::record_cron_run(
        conn,
        job.id,
        started,
        t.elapsed().as_millis() as i64,
        Some(code),
        &output,
    );
    (code, output)
}

fn home_of(user: &str) -> Option<String> {
    std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 5 && f[0] == user).then(|| f[5].to_string())
    })
}

/// Entry point for `cloudpanel cron-run <id>` (invoked by cron).
pub fn run_job(_config: &Config, conn: &Connection, id: i64) -> Result<i32, Box<dyn std::error::Error>> {
    let job = db::find_cron_job(conn, id)?.ok_or_else(|| format!("cron job {id} not found"))?;
    if !job.is_active {
        return Ok(0);
    }
    let (code, _) = execute(conn, &job, None);
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn renders_wrapper_lines() {
        let jobs = vec![
            CronJob {
                id: 1,
                site_id: None,
                name: Some("nightly".into()),
                schedule: "0 3 * * *".into(),
                command: "date +%F >> /tmp/x".into(),
                user: "root".into(),
                is_active: true,
                created_at: Utc::now(),
            },
            CronJob {
                id: 2,
                site_id: None,
                name: None,
                schedule: "@hourly".into(),
                command: "true".into(),
                user: "www-data".into(),
                is_active: false,
                created_at: Utc::now(),
            },
        ];
        let out = CronService::render_with(
            &jobs,
            "/usr/local/bin/cloudpanel",
            "/var/lib/cloudpanel/cloudpanel.db",
            "/var/lib/cloudpanel",
        );
        assert!(out.contains(
            "CLOUDPANEL_DB_PATH=/var/lib/cloudpanel/cloudpanel.db
"
        ));
        assert!(out.contains("0 3 * * * root /usr/local/bin/cloudpanel cron-run 1 >/dev/null 2>&1\n"));
        assert!(!out.contains("cron-run 2"));
        // Commands never appear in the crontab, so '%' needs no escaping.
        assert!(!out.contains("date +"));
    }
}
